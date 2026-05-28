package privx

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// ─── Client handshake ─────────────────────────────────────────────────────────

// ClientHandshake performs the full PrivX client-side handshake (strict_2rtt or fast_open_1rtt).
// On success it returns a *TCPConn ready for transport data.
// earlyData is only sent when cfg.HandshakeMode == "fast_open_1rtt".
func ClientHandshake(conn net.Conn, cfg *Config, dst M.Socksaddr, earlyData []byte) (*TCPConn, []byte, error) {
	// 1. Generate ephemeral keypair
	curve := ecdh.X25519()
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("privx: gen eph key: %w", err)
	}
	defer eraseKey(ephPriv)

	ephPub := ephPriv.PublicKey()

	// 2. Compute es = X25519(client_eph_priv, server_static_pub)
	es, err := ephPriv.ECDH(cfg.ServerStaticPub)
	if err != nil || allZero(es) {
		return nil, nil, errAuthFailed
	}

	// 3. Derive C1 outer keys (need inner CT length first; we build inner first)
	now := uint64(time.Now().Unix())
	connID := randBytes(12)

	var flags byte
	var ed []byte
	if cfg.HandshakeMode == "fast_open_1rtt" {
		flags = flagFastOpenRequest
		ed = earlyData
	}

	// We need to know innerCTLen before encoding outer.
	// Build a scratch to measure size: use a placeholder outer wire to derive keys.
	// Strategy: encode with a zero outer wire hash placeholder, correct later.
	// Actually we must send outer first — but innerCTLen is in outer.
	// Solution: build inner first using a temporary th0 derived from a placeholder c1oh,
	// then re-derive with the real c1oh. This is a chicken-and-egg problem.
	//
	// Correct approach: pick the bucket size before building outer.
	// We know the inner plaintext size exactly: compute it, pick bucket, then build outer.

	addrB := encodeAddr(socksAddrToSpec(dst))
	innerFixedSize := 1 + 1 + 8 + 12 + len(addrB) + 2 + len(ed)
	innerMinCT := innerFixedSize + 2 + 16 // +2=pad_len field, +16=AEAD tag
	innerCTLen, err := chooseBucket(cfg.C1Buckets, innerMinCT, cfg.PadUpProb)
	if err != nil {
		return nil, nil, fmt.Errorf("privx: C1 too large: %w", err)
	}

	// 4. Encode C1 outer (innerCTLen now known)
	var ephPubBytes [32]byte
	copy(ephPubBytes[:], ephPub.Bytes())
	var connIDArr [12]byte
	copy(connIDArr[:], connID)

	c1OuterPlain := c1Outer{
		flags:        flags,
		connID:       connIDArr,
		clientEphPub: ephPubBytes,
		innerCTLen:   uint16(innerCTLen),
	}
	c1OuterWire, c1oh, err := encodeC1Outer(cfg, c1OuterPlain)
	if err != nil {
		return nil, nil, fmt.Errorf("privx: encode C1 outer: %w", err)
	}

	// 5. Derive C1 inner keys
	c1k := deriveC1Keys(cfg.tcpMaster, cfg.ServerStaticPub.Bytes(), c1OuterWire, es)

	// 6. Encode C1 inner
	c1InnerPlain := c1Inner{
		flags:      flags,
		clientTime: now,
		connID:     connIDArr,
		dst:        socksAddrToSpec(dst),
		earlyData:  ed,
	}
	c1InnerWire, err := encodeC1InnerFixed(cfg, c1InnerPlain, c1k, innerCTLen)
	if err != nil {
		return nil, nil, fmt.Errorf("privx: encode C1 inner: %w", err)
	}

	// 7. Send C1
	c1Wire := append(c1OuterWire, c1InnerWire...)
	if _, err = conn.Write(c1Wire); err != nil {
		return nil, nil, err
	}

	// 8. Read S1 outer (96 bytes)
	s1OuterWire := make([]byte, outerWireLen)
	if _, err = io.ReadFull(conn, s1OuterWire); err != nil {
		return nil, nil, err
	}
	s1OuterDecoded, err := decodeS1Outer(cfg, s1OuterWire, c1oh)
	if err != nil {
		return nil, nil, errAuthFailed
	}
	if s1OuterDecoded.connID != connIDArr {
		return nil, nil, errAuthFailed
	}
	if !inBuckets(cfg.S1Buckets, int(s1OuterDecoded.innerCTLen)) {
		return nil, nil, errAuthFailed
	}

	// 9. Read S1 inner
	s1InnerWire := make([]byte, s1OuterDecoded.innerCTLen)
	if _, err = io.ReadFull(conn, s1InnerWire); err != nil {
		return nil, nil, err
	}

	// 10. Derive ee = X25519(client_eph_priv, server_eph_pub)
	serverEphPub, err := curve.NewPublicKey(s1OuterDecoded.serverEphPub[:])
	if err != nil {
		return nil, nil, errAuthFailed
	}
	ee, err := ephPriv.ECDH(serverEphPub)
	if err != nil || allZero(ee) {
		return nil, nil, errAuthFailed
	}

	// 11. Derive S1 inner keys and decode
	s1k := deriveS1Keys(c1k.sec0, c1k.th0, c1InnerWire, s1OuterWire, ee)
	s1InnerDecoded, err := decodeS1Inner(cfg, s1InnerWire, s1k)
	if err != nil {
		return nil, nil, errAuthFailed
	}
	if s1InnerDecoded.connID != connIDArr {
		return nil, nil, errAuthFailed
	}

	// 12. Derive transport keys
	sk := deriveTransportKeys(s1k.sec1, s1k.th1, s1InnerWire)

	// Determine if early data was accepted
	fastOpenAccepted := s1InnerDecoded.flags&flagFastOpenAccepted != 0

	var retransmit []byte
	if cfg.HandshakeMode == "fast_open_1rtt" && !fastOpenAccepted && len(ed) > 0 {
		retransmit = ed
	}

	tc := newTCPConn(conn, cfg, sk, true)
	return tc, retransmit, nil
}

// ─── Server handshake ─────────────────────────────────────────────────────────

// ServerResult is the outcome of a successful server handshake.
type ServerResult struct {
	Conn           *TCPConn
	Dst            M.Socksaddr
	EarlyData      []byte // non-nil only when fast_open accepted
	FastOpenAccepted bool
}

// ServerHandshake performs the PrivX server-side handshake.
// Returns ServerResult on success. On any authentication failure, close the conn and return errAuthFailed.
func ServerHandshake(conn net.Conn, cfg *Config, cache *replayCache) (ServerResult, error) {
	fail := func() (ServerResult, error) {
		conn.Close()
		return ServerResult{}, errAuthFailed
	}

	// 1. Read C1 outer
	c1OuterWire := make([]byte, outerWireLen)
	if _, err := io.ReadFull(conn, c1OuterWire); err != nil {
		return fail()
	}
	c1OuterDecoded, c1oh, err := decodeC1Outer(cfg, c1OuterWire)
	if err != nil {
		return fail()
	}
	if !inBuckets(cfg.C1Buckets, int(c1OuterDecoded.innerCTLen)) {
		return fail()
	}

	// 2. Read C1 inner
	c1InnerWire := make([]byte, c1OuterDecoded.innerCTLen)
	if _, err = io.ReadFull(conn, c1InnerWire); err != nil {
		return fail()
	}

	// 3. Compute es = X25519(server_static_priv, client_eph_pub)
	curve := ecdh.X25519()
	clientEphPub, err := curve.NewPublicKey(c1OuterDecoded.clientEphPub[:])
	if err != nil {
		return fail()
	}
	es, err := cfg.ServerStaticPriv.ECDH(clientEphPub)
	if err != nil || allZero(es) {
		return fail()
	}

	// 4. Derive C1 inner keys and decrypt
	c1k := deriveC1Keys(cfg.tcpMaster, cfg.ServerStaticPub.Bytes(), c1OuterWire, es)
	c1InnerDecoded, err := decodeC1Inner(cfg, c1InnerWire, c1k)
	if err != nil {
		return fail()
	}

	// 5. Validate
	if c1InnerDecoded.connID != c1OuterDecoded.connID {
		return fail()
	}
	now := time.Now().Unix()
	diff := int64(c1InnerDecoded.clientTime) - now
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(cfg.ClockSkewWindow.Seconds()) {
		return fail()
	}
	if cfg.HandshakeMode == "strict_2rtt" && len(c1InnerDecoded.earlyData) > 0 {
		return fail()
	}

	// 6. Replay cache check
	rkey := makeReplayKey(c1OuterDecoded.clientEphPub[:], c1OuterDecoded.connID[:], c1InnerDecoded.clientTime)
	cacheAvailable := cache != nil && cache.Available(now)
	if cache != nil {
		if err = cache.Insert(rkey, now); err != nil {
			return fail()
		}
	}

	// 7. Generate server ephemeral keypair
	serverEphPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return ServerResult{}, fmt.Errorf("privx: gen server eph: %w", err)
	}
	defer eraseKey(serverEphPriv)
	serverEphPub := serverEphPriv.PublicKey()

	// 8. Determine fast_open acceptance
	var s1Flags byte
	var earlyDataOut []byte
	fastOpenAccepted := false
	if cfg.HandshakeMode == "fast_open_1rtt" && c1OuterDecoded.flags&flagFastOpenRequest != 0 {
		if !cacheAvailable {
			// grace period or cache full: reject early data
		} else if cfg.FastOpenPolicy == "accept" {
			s1Flags = flagFastOpenAccepted
			earlyDataOut = c1InnerDecoded.earlyData
			fastOpenAccepted = true
		}
	}

	// 9. Compute ee = X25519(server_eph_priv, client_eph_pub)
	ee, err := serverEphPriv.ECDH(clientEphPub)
	if err != nil || allZero(ee) {
		return fail()
	}

	// 10. Encode and send S1
	var serverEphPubBytes [32]byte
	copy(serverEphPubBytes[:], serverEphPub.Bytes())

	s1k := deriveS1Keys(c1k.sec0, c1k.th0, c1InnerWire, nil /* placeholder */, ee)

	// We need to send S1 outer first, but s1OuterWire depends on innerCTLen.
	// Build inner first to measure size, then outer.
	s1InnerPlain := s1Inner{
		flags:  s1Flags,
		connID: c1OuterDecoded.connID,
	}
	innerCTLen, err := measureS1InnerLen(cfg, s1InnerPlain)
	if err != nil {
		return ServerResult{}, err
	}

	s1OuterPlain := s1Outer{
		flags:        s1Flags,
		connID:       c1OuterDecoded.connID,
		serverEphPub: serverEphPubBytes,
		innerCTLen:   uint16(innerCTLen),
	}
	s1OuterWire, err := encodeS1Outer(cfg, s1OuterPlain, c1oh)
	if err != nil {
		return ServerResult{}, err
	}

	// Re-derive S1 inner keys with real s1OuterWire
	s1k = deriveS1Keys(c1k.sec0, c1k.th0, c1InnerWire, s1OuterWire, ee)

	s1InnerWire, err := encodeS1InnerFixed(cfg, s1InnerPlain, s1k, innerCTLen)
	if err != nil {
		return ServerResult{}, err
	}

	s1Wire := append(s1OuterWire, s1InnerWire...)
	if _, err = conn.Write(s1Wire); err != nil {
		return ServerResult{}, err
	}

	// 11. Derive transport keys
	sk := deriveTransportKeys(s1k.sec1, s1k.th1, s1InnerWire)
	tc := newTCPConn(conn, cfg, sk, false)

	dst := specToSocksAddr(c1InnerDecoded.dst)
	return ServerResult{
		Conn:             tc,
		Dst:              dst,
		EarlyData:        earlyDataOut,
		FastOpenAccepted: fastOpenAccepted,
	}, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func socksAddrToSpec(addr M.Socksaddr) addrSpec {
	if addr.IsIP() {
		ip := addr.Addr.Unmap()
		if ip.Is4() {
			b := ip.As4()
			return addrSpec{atype: addrIPv4, ip: net.IP(b[:]), port: addr.Port}
		}
		b := ip.As16()
		return addrSpec{atype: addrIPv6, ip: net.IP(b[:]), port: addr.Port}
	}
	return addrSpec{atype: addrDomain, domain: addr.Fqdn, port: addr.Port}
}

func specToSocksAddr(a addrSpec) M.Socksaddr {
	switch a.atype {
	case addrIPv4, addrIPv6:
		return M.SocksaddrFromNet(&net.TCPAddr{IP: a.ip, Port: int(a.port)})
	default:
		return M.ParseSocksaddrHostPort(a.domain, a.port)
	}
}

func eraseKey(k *ecdh.PrivateKey) {
	// best-effort: Go GC does not guarantee physical erasure
	_ = k
}

// encodeC1InnerFixed builds C1 inner ciphertext padded to exactly targetCTLen bytes.
func encodeC1InnerFixed(cfg *Config, p c1Inner, k c1Keys, targetCTLen int) ([]byte, error) {
	aead := cfg.newAEAD(k.key)
	addrB := encodeAddr(p.dst)
	fixedSize := 1 + 1 + 8 + 12 + len(addrB) + 2 + len(p.earlyData)
	padLen := targetCTLen - aead.Overhead() - fixedSize - 2
	if padLen < 0 {
		padLen = 0
	}

	plain := make([]byte, 0, fixedSize+2+padLen)
	plain = append(plain, msgTypeC1Inner, p.flags)
	plain = append(plain, uint64be(p.clientTime)...)
	plain = append(plain, p.connID[:]...)
	plain = append(plain, addrB...)
	plain = append(plain, uint16be(uint16(len(p.earlyData)))...)
	plain = append(plain, p.earlyData...)
	plain = append(plain, uint16be(uint16(padLen))...)
	plain = append(plain, randBytes(padLen)...)

	return aeadSeal(aead, k.iv4, 0, plain, k.th0), nil
}

// encodeS1InnerFixed builds S1 inner ciphertext padded to exactly targetCTLen bytes.
func encodeS1InnerFixed(cfg *Config, p s1Inner, k s1Keys, targetCTLen int) ([]byte, error) {
	aead := cfg.newAEAD(k.key)
	fixedSize := 1 + 1 + 12
	padLen := targetCTLen - aead.Overhead() - fixedSize - 2
	if padLen < 0 {
		padLen = 0
	}
	plain := make([]byte, 0, fixedSize+2+padLen)
	plain = append(plain, msgTypeS1Inner, p.flags)
	plain = append(plain, p.connID[:]...)
	plain = append(plain, uint16be(uint16(padLen))...)
	plain = append(plain, randBytes(padLen)...)
	return aeadSeal(aead, k.iv4, 0, plain, k.th1), nil
}

// measureS1InnerLen picks the bucket size for S1 inner given a placeholder th1.
func measureS1InnerLen(cfg *Config, p s1Inner) (int, error) {
	fixedSize := 1 + 1 + 12
	minCT := fixedSize + 2 + 16 // 16 = tag
	return chooseBucket(cfg.S1Buckets, minCT, cfg.PadUpProb)
}

func uint64be(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}
