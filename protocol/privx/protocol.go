// Package privx implements the PrivX-raw v3.1 private proxy protocol.
package privx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	mathrand "math/rand/v2"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// ─── wire constants ───────────────────────────────────────────────────────────

const (
	outerWireLen  = 96 // c1_outer_salt(16) + AEAD(64-byte body)(80)
	outerSaltLen  = 16
	outerBodyLen  = 64 // plaintext body inside outer AEAD
	outerTagLen   = 16
	outerCTLen    = outerBodyLen + outerTagLen // 80

	msgTypeC1Outer = byte(0x31)
	msgTypeS1Outer = byte(0x32)
	msgTypeC1Inner = byte(0x01)
	msgTypeS1Inner = byte(0x02)
	msgTypeUDPC2S  = byte(0x10)
	msgTypeUDPS2C  = byte(0x11)
	msgTypeData    = byte(0x00)
	msgTypeKU      = byte(0x01)

	flagFastOpenRequest  = byte(0x01)
	flagFastOpenAccepted = byte(0x01)

	protoLabelTCP = "PrivX-raw/TCP/v3.1"
	protoLabelUDP = "PrivX-raw/UDP/v3.1"

	addrIPv4   = byte(0x01)
	addrIPv6   = byte(0x04)
	addrDomain = byte(0x03)
)

var (
	defaultC1Buckets     = []int{256, 512, 1024, 1536, 2048}
	defaultS1Buckets     = []int{128, 256, 384, 512, 768}
	defaultRecordBuckets = []int{512, 1024, 2048, 4096, 8192, 16384}
	defaultUDPBuckets    = []int{64, 128, 256, 512, 1024, 1280}
)

var (
	errAuthFailed = errors.New("privx: authentication failed")
	errReplay     = errors.New("privx: replay detected")
)

// ─── Config ──────────────────────────────────────────────────────────────────

// Config holds the parsed, validated protocol configuration.
type Config struct {
	ServerStaticPub  *ecdh.PublicKey
	ServerStaticPriv *ecdh.PrivateKey // server-side only
	PSK              []byte
	Cipher           string
	HandshakeMode    string
	FastOpenPolicy   string
	ClockSkewWindow  time.Duration
	TCPReplayWindow  time.Duration
	C1Buckets        []int
	S1Buckets        []int
	RecordBuckets    []int
	UDPBuckets       []int
	PadUpProb        float64

	outerMaster []byte
	tcpMaster   []byte
	udpMaster   []byte
}

func NewConfig(
	pubKey *ecdh.PublicKey,
	privKey *ecdh.PrivateKey,
	psk []byte,
	cipherName string,
	handshakeMode string,
	fastOpenPolicy string,
	clockSkewSec, tcpReplaySec int,
	c1B, s1B, recB, udpB []int,
	padUpProb float64,
) (*Config, error) {
	if len(psk) != 32 {
		return nil, errors.New("privx: PSK must be exactly 32 bytes")
	}
	if cipherName == "" {
		cipherName = "aes-256-gcm"
	}
	if cipherName != "aes-256-gcm" && cipherName != "chacha20-poly1305" {
		return nil, errors.New("privx: invalid cipher")
	}
	if handshakeMode == "" {
		handshakeMode = "strict_2rtt"
	}
	if handshakeMode != "strict_2rtt" && handshakeMode != "fast_open_1rtt" {
		return nil, errors.New("privx: invalid handshake_mode")
	}
	if fastOpenPolicy == "" {
		fastOpenPolicy = "reject"
	}
	if fastOpenPolicy != "reject" && fastOpenPolicy != "accept" {
		return nil, errors.New("privx: invalid fast_open_policy")
	}
	if clockSkewSec <= 0 {
		clockSkewSec = 30
	}
	if tcpReplaySec <= 0 {
		tcpReplaySec = 120
	}
	if padUpProb <= 0 {
		padUpProb = 0.15
	}
	if len(c1B) == 0 {
		c1B = defaultC1Buckets
	}
	if len(s1B) == 0 {
		s1B = defaultS1Buckets
	}
	if len(recB) == 0 {
		recB = defaultRecordBuckets
	}
	if len(udpB) == 0 {
		udpB = defaultUDPBuckets
	}

	cfg := &Config{
		ServerStaticPub:  pubKey,
		ServerStaticPriv: privKey,
		PSK:              psk,
		Cipher:           cipherName,
		HandshakeMode:    handshakeMode,
		FastOpenPolicy:   fastOpenPolicy,
		ClockSkewWindow:  time.Duration(clockSkewSec) * time.Second,
		TCPReplayWindow:  time.Duration(tcpReplaySec) * time.Second,
		C1Buckets:        c1B,
		S1Buckets:        s1B,
		RecordBuckets:    recB,
		UDPBuckets:       udpB,
		PadUpProb:        padUpProb,
	}
	cfg.deriveRoots()
	return cfg, nil
}

func (c *Config) deriveRoots() {
	pskRoot := hkdfExtract(make([]byte, 32), c.PSK)
	c.outerMaster = hkdfExpand(pskRoot, []byte("PrivX-raw/v3.1/outer"), 32)
	c.tcpMaster = hkdfExpand(pskRoot, []byte("PrivX-raw/v3.1/tcp"), 32)
	c.udpMaster = hkdfExpand(pskRoot, []byte("PrivX-raw/v3.1/udp"), 32)
}

func (c *Config) newAEAD(key []byte) cipher.AEAD {
	if c.Cipher == "chacha20-poly1305" {
		a, err := chacha20poly1305.New(key)
		if err != nil {
			panic(err)
		}
		return a
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return a
}

// ─── KDF primitives ───────────────────────────────────────────────────────────

func hkdfExtract(salt, ikm []byte) []byte {
	return hkdf.Extract(sha256.New, ikm, salt)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	r := hkdf.Expand(sha256.New, prk, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err)
	}
	return out
}

func h256(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func buildNonce(iv4 []byte, counter uint64) []byte {
	n := make([]byte, 12)
	copy(n[:4], iv4)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

func aeadSeal(a cipher.AEAD, iv4 []byte, counter uint64, plain, aad []byte) []byte {
	return a.Seal(nil, buildNonce(iv4, counter), plain, aad)
}

func aeadOpen(a cipher.AEAD, iv4 []byte, counter uint64, ct, aad []byte) ([]byte, error) {
	return a.Open(nil, buildNonce(iv4, counter), ct, aad)
}

// ─── Bucket helpers ───────────────────────────────────────────────────────────

// chooseBucket picks the smallest bucket >= minLen, with probabilistic up-round.
func chooseBucket(buckets []int, minLen int, padUpProb float64) (int, error) {
	target := -1
	for _, b := range buckets {
		if b >= minLen {
			target = b
			break
		}
	}
	if target < 0 {
		return 0, errors.New("privx: payload exceeds max bucket")
	}
	if padUpProb > 0 && target != buckets[len(buckets)-1] {
		if mathrand.Float64() < padUpProb {
			for _, b := range buckets {
				if b > target {
					target = b
					break
				}
			}
		}
	}
	return target, nil
}

func inBuckets(buckets []int, val int) bool {
	for _, b := range buckets {
		if b == val {
			return true
		}
	}
	return false
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// ─── Replay cache ─────────────────────────────────────────────────────────────

type replayCache struct {
	mu      sync.Mutex
	tokens  map[[32]byte]int64
	maxDiff int64
	maxSize int
	bornAt  int64
}

func newReplayCache(window time.Duration, maxSize int) *replayCache {
	if maxSize <= 0 {
		maxSize = 65536
	}
	return &replayCache{
		tokens:  make(map[[32]byte]int64),
		maxDiff: int64(window.Seconds()),
		maxSize: maxSize,
		bornAt:  time.Now().Unix(),
	}
}

// Available returns true when the cache is past its grace period and has capacity.
func (c *replayCache) Available(now int64) bool {
	return now-c.bornAt >= 2*c.maxDiff && len(c.tokens) < c.maxSize
}

// Insert atomically inserts key. Returns errReplay if already present.
func (c *replayCache) Insert(key [32]byte, now int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.tokens) > c.maxSize/2 {
		for k, exp := range c.tokens {
			if now > exp {
				delete(c.tokens, k)
			}
		}
	}
	if exp, exists := c.tokens[key]; exists && now <= exp {
		return errReplay
	}
	c.tokens[key] = now + 2*c.maxDiff
	return nil
}

func makeReplayKey(clientEphPub, connID []byte, clientTime uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte("PrivX-raw/TCP/v3.1/replay"))
	h.Write(clientEphPub)
	h.Write(connID)
	var tb [8]byte
	binary.BigEndian.PutUint64(tb[:], clientTime)
	h.Write(tb[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ─── TCP outer-key derivation ─────────────────────────────────────────────────

func deriveC1OuterKeys(outerMaster, salt []byte) (key, iv4 []byte) {
	prk := hkdfExtract(outerMaster, salt)
	key = hkdfExpand(prk, []byte("c1o_key"), 32)
	iv4 = hkdfExpand(prk, []byte("c1o_iv4"), 4)
	return
}

func deriveS1OuterKeys(outerMaster, salt, c1oh []byte) (key, iv4 []byte) {
	ikm := append(append([]byte{}, salt...), c1oh...)
	prk := hkdfExtract(outerMaster, ikm)
	key = hkdfExpand(prk, []byte("s1o_key"), 32)
	iv4 = hkdfExpand(prk, []byte("s1o_iv4"), 4)
	return
}

// ─── TCP inner-key derivation ─────────────────────────────────────────────────

type c1Keys struct {
	key  []byte
	iv4  []byte
	sec0 []byte
	th0  []byte
}

func deriveC1Keys(tcpMaster, serverStaticPub, c1OuterWire, es []byte) c1Keys {
	c1oh := h256(c1OuterWire)
	th0 := h256([]byte(protoLabelTCP), serverStaticPub, c1oh)
	sec0 := hkdfExtract(tcpMaster, es)
	return c1Keys{
		key:  hkdfExpand(sec0, append([]byte("c1i_key"), th0...), 32),
		iv4:  hkdfExpand(sec0, append([]byte("c1i_iv4"), th0...), 4),
		sec0: sec0,
		th0:  th0,
	}
}

type s1Keys struct {
	key  []byte
	iv4  []byte
	sec1 []byte
	th1  []byte
}

func deriveS1Keys(sec0, th0, c1InnerWire, s1OuterWire, ee []byte) s1Keys {
	th1 := h256(th0, c1InnerWire, s1OuterWire)
	sec1 := hkdfExtract(sec0, ee)
	return s1Keys{
		key:  hkdfExpand(sec1, append([]byte("s1i_key"), th1...), 32),
		iv4:  hkdfExpand(sec1, append([]byte("s1i_iv4"), th1...), 4),
		sec1: sec1,
		th1:  th1,
	}
}

type sessionKeys struct {
	c2sKey    []byte
	c2sIV4    []byte
	s2cKey    []byte
	s2cIV4    []byte
	c2sSecret []byte
	s2cSecret []byte
}

func deriveTransportKeys(sec1, th1, s1InnerWire []byte) sessionKeys {
	th2 := h256(th1, s1InnerWire)
	c2sInfo := append([]byte("c2s_secret"), th2...)
	s2cInfo := append([]byte("s2c_secret"), th2...)
	c2sSec := hkdfExpand(sec1, c2sInfo, 32)
	s2cSec := hkdfExpand(sec1, s2cInfo, 32)
	return sessionKeys{
		c2sKey:    hkdfExpand(c2sSec, []byte("key"), 32),
		c2sIV4:    hkdfExpand(c2sSec, []byte("iv4"), 4),
		s2cKey:    hkdfExpand(s2cSec, []byte("key"), 32),
		s2cIV4:    hkdfExpand(s2cSec, []byte("iv4"), 4),
		c2sSecret: c2sSec,
		s2cSecret: s2cSec,
	}
}

// ─── UDP session-key derivation ───────────────────────────────────────────────

type udpKeys struct {
	c2sKey []byte
	c2sIV4 []byte
	s2cKey []byte
	s2cIV4 []byte
}

func deriveUDPKeys(udpMaster, sessionID []byte) udpKeys {
	uh := h256([]byte(protoLabelUDP), sessionID)
	prk := hkdfExtract(udpMaster, uh)
	c2sSec := hkdfExpand(prk, []byte("c2s_secret"), 32)
	s2cSec := hkdfExpand(prk, []byte("s2c_secret"), 32)
	return udpKeys{
		c2sKey: hkdfExpand(c2sSec, []byte("key"), 32),
		c2sIV4: hkdfExpand(c2sSec, []byte("iv4"), 4),
		s2cKey: hkdfExpand(s2cSec, []byte("key"), 32),
		s2cIV4: hkdfExpand(s2cSec, []byte("iv4"), 4),
	}
}

// ─── Outer header encode / decode ─────────────────────────────────────────────

type c1Outer struct {
	flags        byte
	connID       [12]byte
	clientEphPub [32]byte
	innerCTLen   uint16
}

func encodeC1Outer(cfg *Config, p c1Outer) (wire []byte, c1oh []byte, err error) {
	salt := randBytes(outerSaltLen)
	key, iv4 := deriveC1OuterKeys(cfg.outerMaster, salt)
	aead := cfg.newAEAD(key)
	aad := append([]byte("PrivX-raw/TCP/v3.1/C1O"), cfg.ServerStaticPub.Bytes()...)

	body := make([]byte, outerBodyLen)
	body[0] = msgTypeC1Outer
	body[1] = p.flags
	// body[2:4] reserved = 0
	copy(body[4:16], p.connID[:])
	copy(body[16:48], p.clientEphPub[:])
	binary.BigEndian.PutUint16(body[48:50], p.innerCTLen)
	// body[50:54] reserved = 0
	copy(body[54:], randBytes(outerBodyLen-54)) // outer_pad

	ct := aeadSeal(aead, iv4, 0, body, aad)
	wire = append(salt, ct...)
	c1oh = h256(wire)
	return
}

func decodeC1Outer(cfg *Config, wire []byte) (p c1Outer, c1oh []byte, err error) {
	if len(wire) != outerWireLen {
		err = errAuthFailed
		return
	}
	salt := wire[:outerSaltLen]
	ct := wire[outerSaltLen:]
	key, iv4 := deriveC1OuterKeys(cfg.outerMaster, salt)
	aead := cfg.newAEAD(key)
	aad := append([]byte("PrivX-raw/TCP/v3.1/C1O"), cfg.ServerStaticPub.Bytes()...)

	body, e := aeadOpen(aead, iv4, 0, ct, aad)
	if e != nil {
		err = errAuthFailed
		return
	}
	if body[0] != msgTypeC1Outer || body[2] != 0 || body[3] != 0 ||
		body[50] != 0 || body[51] != 0 || body[52] != 0 || body[53] != 0 {
		err = errAuthFailed
		return
	}
	p.flags = body[1]
	copy(p.connID[:], body[4:16])
	copy(p.clientEphPub[:], body[16:48])
	p.innerCTLen = binary.BigEndian.Uint16(body[48:50])
	c1oh = h256(wire)
	return
}

type s1Outer struct {
	flags        byte
	connID       [12]byte
	serverEphPub [32]byte
	innerCTLen   uint16
}

func encodeS1Outer(cfg *Config, p s1Outer, c1oh []byte) (wire []byte, err error) {
	salt := randBytes(outerSaltLen)
	key, iv4 := deriveS1OuterKeys(cfg.outerMaster, salt, c1oh)
	aead := cfg.newAEAD(key)
	aad := append([]byte("PrivX-raw/TCP/v3.1/S1O"), c1oh...)

	body := make([]byte, outerBodyLen)
	body[0] = msgTypeS1Outer
	body[1] = p.flags
	copy(body[4:16], p.connID[:])
	copy(body[16:48], p.serverEphPub[:])
	binary.BigEndian.PutUint16(body[48:50], p.innerCTLen)
	copy(body[54:], randBytes(outerBodyLen-54))

	ct := aeadSeal(aead, iv4, 0, body, aad)
	wire = append(salt, ct...)
	return
}

func decodeS1Outer(cfg *Config, wire []byte, c1oh []byte) (p s1Outer, err error) {
	if len(wire) != outerWireLen {
		err = errAuthFailed
		return
	}
	salt := wire[:outerSaltLen]
	ct := wire[outerSaltLen:]
	key, iv4 := deriveS1OuterKeys(cfg.outerMaster, salt, c1oh)
	aead := cfg.newAEAD(key)
	aad := append([]byte("PrivX-raw/TCP/v3.1/S1O"), c1oh...)

	body, e := aeadOpen(aead, iv4, 0, ct, aad)
	if e != nil {
		err = errAuthFailed
		return
	}
	if body[0] != msgTypeS1Outer || body[2] != 0 || body[3] != 0 ||
		body[50] != 0 || body[51] != 0 || body[52] != 0 || body[53] != 0 {
		err = errAuthFailed
		return
	}
	p.flags = body[1]
	copy(p.connID[:], body[4:16])
	copy(p.serverEphPub[:], body[16:48])
	p.innerCTLen = binary.BigEndian.Uint16(body[48:50])
	return
}

// ─── C1 / S1 inner encode / decode ───────────────────────────────────────────

type c1Inner struct {
	flags       byte
	clientTime  uint64
	connID      [12]byte
	dst         addrSpec
	earlyData   []byte
}

func encodeC1Inner(cfg *Config, p c1Inner, k c1Keys) (wire []byte, err error) {
	aead := cfg.newAEAD(k.key)
	addrBytes := encodeAddr(p.dst)
	// compute minimum plain size + tag, then pick bucket
	fixedSize := 1 + 1 + 8 + 12 + len(addrBytes) + 2 + len(p.earlyData) + 2
	minCT := fixedSize + 2 + aead.Overhead() // +2 for pad_len field
	target, e := chooseBucket(cfg.C1Buckets, minCT, cfg.PadUpProb)
	if e != nil {
		err = e
		return
	}
	padLen := target - aead.Overhead() - fixedSize - 2
	if padLen < 0 {
		padLen = 0
	}

	plain := make([]byte, 0, fixedSize+2+padLen)
	plain = append(plain, msgTypeC1Inner, p.flags)
	var tb [8]byte
	binary.BigEndian.PutUint64(tb[:], p.clientTime)
	plain = append(plain, tb[:]...)
	plain = append(plain, p.connID[:]...)
	plain = append(plain, addrBytes...)
	plain = append(plain, uint16be(uint16(len(p.earlyData)))...)
	plain = append(plain, p.earlyData...)
	plain = append(plain, uint16be(uint16(padLen))...)
	plain = append(plain, randBytes(padLen)...)

	wire = aeadSeal(aead, k.iv4, 0, plain, k.th0)
	return
}

func decodeC1Inner(cfg *Config, wire []byte, k c1Keys) (p c1Inner, err error) {
	aead := cfg.newAEAD(k.key)
	plain, e := aeadOpen(aead, k.iv4, 0, wire, k.th0)
	if e != nil {
		err = errAuthFailed
		return
	}
	if len(plain) < 24 {
		err = errAuthFailed
		return
	}
	if plain[0] != msgTypeC1Inner {
		err = errAuthFailed
		return
	}
	p.flags = plain[1]
	p.clientTime = binary.BigEndian.Uint64(plain[2:10])
	copy(p.connID[:], plain[10:22])

	addr, addrSize, ae := decodeAddr(plain[22:])
	if ae != nil {
		err = errAuthFailed
		return
	}
	p.dst = addr
	off := 22 + addrSize
	if off+4 > len(plain) {
		err = errAuthFailed
		return
	}
	earlyDataLen := int(binary.BigEndian.Uint16(plain[off : off+2]))
	off += 2
	if off+earlyDataLen > len(plain) {
		err = errAuthFailed
		return
	}
	p.earlyData = plain[off : off+earlyDataLen]
	return
}

type s1Inner struct {
	flags  byte
	connID [12]byte
}

func encodeS1Inner(cfg *Config, p s1Inner, k s1Keys) (wire []byte, err error) {
	aead := cfg.newAEAD(k.key)
	fixedSize := 1 + 1 + 12
	minCT := fixedSize + 2 + aead.Overhead()
	target, e := chooseBucket(cfg.S1Buckets, minCT, cfg.PadUpProb)
	if e != nil {
		err = e
		return
	}
	padLen := target - aead.Overhead() - fixedSize - 2
	if padLen < 0 {
		padLen = 0
	}
	plain := make([]byte, 0, fixedSize+2+padLen)
	plain = append(plain, msgTypeS1Inner, p.flags)
	plain = append(plain, p.connID[:]...)
	plain = append(plain, uint16be(uint16(padLen))...)
	plain = append(plain, randBytes(padLen)...)

	wire = aeadSeal(aead, k.iv4, 0, plain, k.th1)
	return
}

func decodeS1Inner(cfg *Config, wire []byte, k s1Keys) (p s1Inner, err error) {
	aead := cfg.newAEAD(k.key)
	plain, e := aeadOpen(aead, k.iv4, 0, wire, k.th1)
	if e != nil {
		err = errAuthFailed
		return
	}
	if len(plain) < 14 || plain[0] != msgTypeS1Inner {
		err = errAuthFailed
		return
	}
	p.flags = plain[1]
	copy(p.connID[:], plain[2:14])
	return
}

// ─── Address spec ─────────────────────────────────────────────────────────────

type addrSpec struct {
	atype  byte
	ip     net.IP
	domain string
	port   uint16
}

func encodeAddr(a addrSpec) []byte {
	switch a.atype {
	case addrIPv4:
		b := make([]byte, 7)
		b[0] = addrIPv4
		copy(b[1:5], a.ip.To4())
		binary.BigEndian.PutUint16(b[5:7], a.port)
		return b
	case addrIPv6:
		b := make([]byte, 19)
		b[0] = addrIPv6
		copy(b[1:17], a.ip.To16())
		binary.BigEndian.PutUint16(b[17:19], a.port)
		return b
	default: // domain
		dl := len(a.domain)
		b := make([]byte, 4+dl)
		b[0] = addrDomain
		b[1] = byte(dl)
		copy(b[2:], a.domain)
		binary.BigEndian.PutUint16(b[2+dl:4+dl], a.port)
		return b
	}
}

func decodeAddr(b []byte) (addrSpec, int, error) {
	if len(b) < 1 {
		return addrSpec{}, 0, errors.New("privx: empty addr")
	}
	switch b[0] {
	case addrIPv4:
		if len(b) < 7 {
			return addrSpec{}, 0, errors.New("privx: short IPv4")
		}
		return addrSpec{atype: addrIPv4, ip: net.IP(append([]byte{}, b[1:5]...)), port: binary.BigEndian.Uint16(b[5:7])}, 7, nil
	case addrIPv6:
		if len(b) < 19 {
			return addrSpec{}, 0, errors.New("privx: short IPv6")
		}
		return addrSpec{atype: addrIPv6, ip: net.IP(append([]byte{}, b[1:17]...)), port: binary.BigEndian.Uint16(b[17:19])}, 19, nil
	case addrDomain:
		if len(b) < 2 {
			return addrSpec{}, 0, errors.New("privx: short domain")
		}
		dl := int(b[1])
		if len(b) < 4+dl {
			return addrSpec{}, 0, errors.New("privx: short domain data")
		}
		return addrSpec{atype: addrDomain, domain: string(b[2 : 2+dl]), port: binary.BigEndian.Uint16(b[2+dl : 4+dl])}, 4 + dl, nil
	default:
		return addrSpec{}, 0, errors.New("privx: unknown atype")
	}
}

// ─── TCPConn (transport AEAD framing) ────────────────────────────────────────

// TCPConn wraps a net.Conn with directional per-frame AEAD encryption.
type TCPConn struct {
	net.Conn
	cfg *Config

	writeMu     sync.Mutex
	writeKey    []byte
	writeIV4    []byte
	writeSecret []byte
	writeCount  uint64

	readMu     sync.Mutex
	readKey    []byte
	readIV4    []byte
	readSecret []byte
	readCount  uint64
	readBuf    []byte
}

func newTCPConn(conn net.Conn, cfg *Config, sk sessionKeys, isClient bool) *TCPConn {
	c := &TCPConn{Conn: conn, cfg: cfg}
	if isClient {
		c.writeKey, c.writeIV4, c.writeSecret = sk.c2sKey, sk.c2sIV4, sk.c2sSecret
		c.readKey, c.readIV4, c.readSecret = sk.s2cKey, sk.s2cIV4, sk.s2cSecret
	} else {
		c.writeKey, c.writeIV4, c.writeSecret = sk.s2cKey, sk.s2cIV4, sk.s2cSecret
		c.readKey, c.readIV4, c.readSecret = sk.c2sKey, sk.c2sIV4, sk.c2sSecret
	}
	return c
}

func (c *TCPConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	aead := c.cfg.newAEAD(c.writeKey)
	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > 16384 {
			chunk = chunk[:16384]
		}
		wire, err := c.encryptFrame(aead, msgTypeData, chunk)
		if err != nil {
			return total, err
		}
		if _, err = c.Conn.Write(wire); err != nil {
			return total, err
		}
		total += len(chunk)
		b = b[len(chunk):]
	}
	return total, nil
}

func (c *TCPConn) encryptFrame(aead cipher.AEAD, frameType byte, data []byte) ([]byte, error) {
	// FRAME_PLAIN: frame_type(1)+data_len(2)+data+pad_len(2)+padding
	// We pick a bucket for the FRAME_CT (FRAME_PLAIN + tag)
	baseMin := 1 + 2 + len(data) + 2 + aead.Overhead()
	target, err := chooseBucket(c.cfg.RecordBuckets, baseMin, c.cfg.PadUpProb)
	padLen := 0
	if err == nil {
		padLen = target - aead.Overhead() - 1 - 2 - len(data) - 2
		if padLen < 0 {
			padLen = 0
		}
	}

	plain := make([]byte, 1+2+len(data)+2+padLen)
	plain[0] = frameType
	binary.BigEndian.PutUint16(plain[1:3], uint16(len(data)))
	copy(plain[3:], data)
	binary.BigEndian.PutUint16(plain[3+len(data):], uint16(padLen))
	if padLen > 0 {
		if _, err2 := rand.Read(plain[3+len(data)+2:]); err2 != nil {
			return nil, err2
		}
	}

	frameCT := aeadSeal(aead, c.writeIV4, c.writeCount+1, plain, nil)
	lenBuf := uint16be(uint16(len(frameCT)))
	lenCT := aeadSeal(aead, c.writeIV4, c.writeCount, lenBuf, nil)
	c.writeCount += 2

	return append(lenCT, frameCT...), nil
}

func (c *TCPConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.readLocked(b)
}

func (c *TCPConn) readLocked(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	aead := c.cfg.newAEAD(c.readKey)
	tagSize := aead.Overhead()

	lenCT := make([]byte, 2+tagSize)
	if _, err := io.ReadFull(c.Conn, lenCT); err != nil {
		return 0, err
	}
	lenPlain, err := aeadOpen(aead, c.readIV4, c.readCount, lenCT, nil)
	if err != nil {
		return 0, errAuthFailed
	}
	c.readCount++

	frameLen := int(binary.BigEndian.Uint16(lenPlain))
	if frameLen > 16384+tagSize+1+2+2+16384 {
		return 0, errAuthFailed
	}

	frameCT := make([]byte, frameLen)
	if _, err = io.ReadFull(c.Conn, frameCT); err != nil {
		return 0, err
	}
	framePlain, err := aeadOpen(aead, c.readIV4, c.readCount, frameCT, nil)
	if err != nil {
		return 0, errAuthFailed
	}
	c.readCount++

	if len(framePlain) < 5 {
		return 0, errAuthFailed
	}
	ft := framePlain[0]
	dataLen := int(binary.BigEndian.Uint16(framePlain[1:3]))
	if 3+dataLen > len(framePlain) {
		return 0, errAuthFailed
	}
	data := framePlain[3 : 3+dataLen]

	if ft == msgTypeKU {
		c.rotateReadKey()
		return c.readLocked(b)
	}

	n := copy(b, data)
	if n < len(data) {
		c.readBuf = append(c.readBuf[:0], data[n:]...)
	}
	return n, nil
}

func (c *TCPConn) rotateReadKey() {
	newSec := hkdfExpand(c.readSecret, []byte("ku"), 32)
	c.readKey = hkdfExpand(newSec, []byte("key"), 32)
	c.readIV4 = hkdfExpand(newSec, []byte("iv4"), 4)
	c.readSecret = newSec
	c.readCount = 0
}

// ─── UDP packet encode / decode ───────────────────────────────────────────────

type udpC2SPacket struct {
	sessionID [12]byte
	packetID  uint64
	clientTime uint64
	dst       addrSpec
	payload   []byte
}

func encodeUDPC2S(cfg *Config, k udpKeys, p udpC2SPacket) ([]byte, error) {
	aead := cfg.newAEAD(k.c2sKey)
	addrB := encodeAddr(p.dst)
	// fixedPlain includes the 1-byte pad_len field at end; minimum is padLen=0
	fixedPlain := 1 + 1 + 8 + len(addrB) + len(p.payload) + 1
	minCT := fixedPlain + aead.Overhead()
	target, err := chooseBucket(cfg.UDPBuckets, minCT, cfg.PadUpProb)
	padLen := 0
	if err == nil {
		padLen = target - aead.Overhead() - fixedPlain
		if padLen < 0 {
			padLen = 0
		}
	}

	// Layout: [msg_type][flags][time][addr][payload][padding][pad_len]
	// pad_len is last byte so decoder can read it as plain[len-1]
	plain := make([]byte, 0, fixedPlain+padLen)
	plain = append(plain, msgTypeUDPC2S, 0) // flags=0
	var tb [8]byte
	binary.BigEndian.PutUint64(tb[:], p.clientTime)
	plain = append(plain, tb[:]...)
	plain = append(plain, addrB...)
	plain = append(plain, p.payload...)
	plain = append(plain, randBytes(padLen)...)
	plain = append(plain, byte(padLen))

	var pidB [8]byte
	binary.BigEndian.PutUint64(pidB[:], p.packetID)
	aad := append(append([]byte{}, p.sessionID[:]...), pidB[:]...)

	ct := aeadSeal(aead, k.c2sIV4, p.packetID, plain, aad)
	wire := make([]byte, 12+8+len(ct))
	copy(wire[:12], p.sessionID[:])
	binary.BigEndian.PutUint64(wire[12:20], p.packetID)
	copy(wire[20:], ct)
	return wire, nil
}

type udpS2CPacket struct {
	sessionID  [12]byte
	packetID   uint64
	serverTime uint64
	src        addrSpec
	payload    []byte
}

func encodeUDPS2C(cfg *Config, k udpKeys, p udpS2CPacket) ([]byte, error) {
	aead := cfg.newAEAD(k.s2cKey)
	addrB := encodeAddr(p.src)
	fixedPlain := 1 + 1 + 8 + len(addrB) + len(p.payload) + 1
	minCT := fixedPlain + aead.Overhead()
	target, err := chooseBucket(cfg.UDPBuckets, minCT, cfg.PadUpProb)
	padLen := 0
	if err == nil {
		padLen = target - aead.Overhead() - fixedPlain
		if padLen < 0 {
			padLen = 0
		}
	}

	// Layout: [msg_type][flags][time][addr][payload][padding][pad_len]
	plain := make([]byte, 0, fixedPlain+padLen)
	plain = append(plain, msgTypeUDPS2C, 0)
	var tb [8]byte
	binary.BigEndian.PutUint64(tb[:], p.serverTime)
	plain = append(plain, tb[:]...)
	plain = append(plain, addrB...)
	plain = append(plain, p.payload...)
	plain = append(plain, randBytes(padLen)...)
	plain = append(plain, byte(padLen))

	var pidB [8]byte
	binary.BigEndian.PutUint64(pidB[:], p.packetID)
	aad := append(append([]byte{}, p.sessionID[:]...), pidB[:]...)

	ct := aeadSeal(aead, k.s2cIV4, p.packetID, plain, aad)
	wire := make([]byte, 12+8+len(ct))
	copy(wire[:12], p.sessionID[:])
	binary.BigEndian.PutUint64(wire[12:20], p.packetID)
	copy(wire[20:], ct)
	return wire, nil
}

func decodeUDPC2S(cfg *Config, k udpKeys, wire []byte) (udpC2SPacket, error) {
	if len(wire) < 20+cfg.newAEAD(k.c2sKey).Overhead() {
		return udpC2SPacket{}, errAuthFailed
	}
	var p udpC2SPacket
	copy(p.sessionID[:], wire[:12])
	p.packetID = binary.BigEndian.Uint64(wire[12:20])

	aead := cfg.newAEAD(k.c2sKey)
	var pidB [8]byte
	binary.BigEndian.PutUint64(pidB[:], p.packetID)
	aad := append(append([]byte{}, p.sessionID[:]...), pidB[:]...)

	plain, err := aeadOpen(aead, k.c2sIV4, p.packetID, wire[20:], aad)
	if err != nil {
		return udpC2SPacket{}, errAuthFailed
	}
	if len(plain) < 10 || plain[0] != msgTypeUDPC2S || plain[1] != 0 {
		return udpC2SPacket{}, errAuthFailed
	}
	p.clientTime = binary.BigEndian.Uint64(plain[2:10])
	addr, addrSize, ae := decodeAddr(plain[10:])
	if ae != nil {
		return udpC2SPacket{}, errAuthFailed
	}
	p.dst = addr
	off := 10 + addrSize
	padLen := int(plain[len(plain)-1])
	payloadEnd := len(plain) - 1 - padLen
	if payloadEnd < off {
		return udpC2SPacket{}, errAuthFailed
	}
	p.payload = plain[off:payloadEnd]
	return p, nil
}

func decodeUDPS2C(cfg *Config, k udpKeys, wire []byte) (udpS2CPacket, error) {
	if len(wire) < 20+cfg.newAEAD(k.s2cKey).Overhead() {
		return udpS2CPacket{}, errAuthFailed
	}
	var p udpS2CPacket
	copy(p.sessionID[:], wire[:12])
	p.packetID = binary.BigEndian.Uint64(wire[12:20])

	aead := cfg.newAEAD(k.s2cKey)
	var pidB [8]byte
	binary.BigEndian.PutUint64(pidB[:], p.packetID)
	aad := append(append([]byte{}, p.sessionID[:]...), pidB[:]...)

	plain, err := aeadOpen(aead, k.s2cIV4, p.packetID, wire[20:], aad)
	if err != nil {
		return udpS2CPacket{}, errAuthFailed
	}
	if len(plain) < 10 || plain[0] != msgTypeUDPS2C || plain[1] != 0 {
		return udpS2CPacket{}, errAuthFailed
	}
	p.serverTime = binary.BigEndian.Uint64(plain[2:10])
	addr, addrSize, ae := decodeAddr(plain[10:])
	if ae != nil {
		return udpS2CPacket{}, errAuthFailed
	}
	p.src = addr
	off := 10 + addrSize
	padLen := int(plain[len(plain)-1])
	payloadEnd := len(plain) - 1 - padLen
	if payloadEnd < off {
		return udpS2CPacket{}, errAuthFailed
	}
	p.payload = plain[off:payloadEnd]
	return p, nil
}

// ─── misc helpers ─────────────────────────────────────────────────────────────

func uint16be(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
