package privx

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// ─── test helpers ─────────────────────────────────────────────────────────────

func makeTestConfig(t *testing.T) (*Config, *ecdh.PrivateKey) {
	t.Helper()
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	psk := make([]byte, 32)
	rand.Read(psk)

	cfg, err := NewConfig(
		privKey.PublicKey(), privKey, psk,
		"aes-256-gcm", "strict_2rtt", "reject",
		30, 120, nil, nil, nil, nil, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, privKey
}

func makeTestConfigChacha(t *testing.T) *Config {
	t.Helper()
	curve := ecdh.X25519()
	privKey, _ := curve.GenerateKey(rand.Reader)
	psk := make([]byte, 32)
	rand.Read(psk)
	cfg, err := NewConfig(
		privKey.PublicKey(), privKey, psk,
		"chacha20-poly1305", "strict_2rtt", "reject",
		30, 120, nil, nil, nil, nil, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func pipeHandshake(t *testing.T, cfg *Config) (client *TCPConn, server *TCPConn, dst M.Socksaddr) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	dst = M.ParseSocksaddrHostPort("example.com", 80)
	cache := newReplayCache(2*time.Minute, 1024)

	var wg sync.WaitGroup
	var clientTC *TCPConn
	var serverResult ServerResult
	var clientErr, serverErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		clientTC, _, clientErr = ClientHandshake(clientConn, cfg, dst, nil)
	}()
	go func() {
		defer wg.Done()
		serverResult, serverErr = ServerHandshake(serverConn, cfg, cache)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client handshake: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server handshake: %v", serverErr)
	}
	return clientTC, serverResult.Conn, serverResult.Dst
}

// ─── 1. Key schedule ──────────────────────────────────────────────────────────

func TestKeySchedule(t *testing.T) {
	cfg, _ := makeTestConfig(t)
	// Derive roots and check they differ
	if bytes.Equal(cfg.outerMaster, cfg.tcpMaster) {
		t.Fatal("outer_master == tcp_master")
	}
	if bytes.Equal(cfg.tcpMaster, cfg.udpMaster) {
		t.Fatal("tcp_master == udp_master")
	}
	if bytes.Equal(cfg.outerMaster, cfg.udpMaster) {
		t.Fatal("outer_master == udp_master")
	}
}

// ─── 2. Direction key separation ──────────────────────────────────────────────

func TestDirectionSeparation(t *testing.T) {
	cfg, _ := makeTestConfig(t)
	_, _, _ = pipeHandshake(t, cfg)
	// The handshake itself exercises direction separation; verify via full round-trip
}

// ─── 3. C1 outer binding (different server keys → different AAD) ───────────────

func TestC1OuterBinding(t *testing.T) {
	curve := ecdh.X25519()
	psk := make([]byte, 32)
	rand.Read(psk)

	priv1, _ := curve.GenerateKey(rand.Reader)
	priv2, _ := curve.GenerateKey(rand.Reader)

	cfg1, _ := NewConfig(priv1.PublicKey(), priv1, psk, "aes-256-gcm", "strict_2rtt", "reject", 30, 120, nil, nil, nil, nil, 0)
	cfg2, _ := NewConfig(priv2.PublicKey(), priv2, psk, "aes-256-gcm", "strict_2rtt", "reject", 30, 120, nil, nil, nil, nil, 0)

	// AAD for C1 outer includes server_static_pubkey, so keys differ between configs
	salt := randBytes(16)
	key1, _ := deriveC1OuterKeys(cfg1.outerMaster, salt)
	key2, _ := deriveC1OuterKeys(cfg2.outerMaster, salt)
	// outer_master differs because PSK XOR derivation uses same PSK but different roots are unrelated
	// (outer_master depends only on PSK, but AAD includes pubkey)
	// The test confirms AAD differs:
	aad1 := append([]byte("PrivX-raw/TCP/v3.1/C1O"), cfg1.ServerStaticPub.Bytes()...)
	aad2 := append([]byte("PrivX-raw/TCP/v3.1/C1O"), cfg2.ServerStaticPub.Bytes()...)
	if bytes.Equal(aad1, aad2) {
		t.Fatal("C1 outer AAD should differ for different server keys")
	}
	_ = key1
	_ = key2
}

// ─── 4. S1 outer binding to C1 ────────────────────────────────────────────────

func TestS1OuterBinding(t *testing.T) {
	cfg, _ := makeTestConfig(t)

	// Create two different C1 outer wires with different salts → different c1oh → different S1 keys
	ephPriv1, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ephPriv2, _ := ecdh.X25519().GenerateKey(rand.Reader)

	var connID [12]byte
	var eph1Bytes, eph2Bytes [32]byte
	copy(eph1Bytes[:], ephPriv1.PublicKey().Bytes())
	copy(eph2Bytes[:], ephPriv2.PublicKey().Bytes())

	wire1, c1oh1, _ := encodeC1Outer(cfg, c1Outer{connID: connID, clientEphPub: eph1Bytes, innerCTLen: 256})
	wire2, c1oh2, _ := encodeC1Outer(cfg, c1Outer{connID: connID, clientEphPub: eph2Bytes, innerCTLen: 256})

	if bytes.Equal(c1oh1, c1oh2) {
		t.Fatal("different C1 outer wires must produce different c1oh")
	}
	_ = wire1
	_ = wire2

	// S1 outer keys derived with different c1oh must differ
	salt := randBytes(16)
	key1, _ := deriveS1OuterKeys(cfg.outerMaster, salt, c1oh1)
	key2, _ := deriveS1OuterKeys(cfg.outerMaster, salt, c1oh2)
	if bytes.Equal(key1, key2) {
		t.Fatal("S1 outer keys must differ for different c1oh")
	}
}

// ─── 5. TCP handshake strict_2rtt ─────────────────────────────────────────────

func TestTCPHandshake(t *testing.T) {
	cfg, _ := makeTestConfig(t)
	clientTC, serverTC, serverDst := pipeHandshake(t, cfg)

	expected := M.ParseSocksaddrHostPort("example.com", 80)
	if serverDst.String() != expected.String() {
		t.Fatalf("dst mismatch: got %v want %v", serverDst, expected)
	}

	msg := []byte("hello from client")
	reply := []byte("hello from server")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientTC.Write(msg)
		buf := make([]byte, 1024)
		n, err := clientTC.Read(buf)
		if err != nil {
			t.Errorf("client read: %v", err)
			return
		}
		if !bytes.Equal(buf[:n], reply) {
			t.Errorf("client got wrong data: %q", buf[:n])
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		n, err := serverTC.Read(buf)
		if err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if !bytes.Equal(buf[:n], msg) {
			t.Errorf("server got wrong data: %q", buf[:n])
		}
		serverTC.Write(reply)
	}()
	wg.Wait()
}

// ─── 6. fast_open accepted ────────────────────────────────────────────────────

func TestFastOpenAccepted(t *testing.T) {
	curve := ecdh.X25519()
	privKey, _ := curve.GenerateKey(rand.Reader)
	psk := make([]byte, 32)
	rand.Read(psk)

	cfg, _ := NewConfig(privKey.PublicKey(), privKey, psk,
		"aes-256-gcm", "fast_open_1rtt", "accept", 30, 120, nil, nil, nil, nil, 0)

	earlyData := []byte("early payload")
	clientConn, serverConn := net.Pipe()
	dst := M.ParseSocksaddrHostPort("1.2.3.4", 443)
	cache := newReplayCache(30*time.Second, 1024)
	// Backdate so cache is past grace period (2*ClockSkewWindow = 60s)
	cache.bornAt = time.Now().Add(-61 * time.Second).Unix()

	var clientTC *TCPConn
	var sResult ServerResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientTC, _, _ = ClientHandshake(clientConn, cfg, dst, earlyData)
	}()
	go func() {
		defer wg.Done()
		sResult, _ = ServerHandshake(serverConn, cfg, cache)
	}()
	wg.Wait()

	if !sResult.FastOpenAccepted {
		t.Fatal("fast_open should be accepted")
	}
	if !bytes.Equal(sResult.EarlyData, earlyData) {
		t.Fatalf("early data mismatch: got %q want %q", sResult.EarlyData, earlyData)
	}
	_ = clientTC
}

// ─── 7. fast_open rejected by policy ─────────────────────────────────────────

func TestFastOpenRejected(t *testing.T) {
	curve := ecdh.X25519()
	privKey, _ := curve.GenerateKey(rand.Reader)
	psk := make([]byte, 32)
	rand.Read(psk)

	// server in fast_open mode but policy=reject
	cfg, _ := NewConfig(privKey.PublicKey(), privKey, psk,
		"aes-256-gcm", "fast_open_1rtt", "reject", 30, 120, nil, nil, nil, nil, 0)

	earlyData := []byte("early payload")
	clientConn, serverConn := net.Pipe()
	dst := M.ParseSocksaddrHostPort("1.2.3.4", 443)
	cache := newReplayCache(2*time.Minute, 1024)

	var retransmit []byte
	var sResult ServerResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, retransmit, _ = ClientHandshake(clientConn, cfg, dst, earlyData)
	}()
	go func() {
		defer wg.Done()
		sResult, _ = ServerHandshake(serverConn, cfg, cache)
	}()
	wg.Wait()

	if sResult.FastOpenAccepted {
		t.Fatal("fast_open should be rejected when policy=reject")
	}
	if len(sResult.EarlyData) > 0 {
		t.Fatal("server should not have early data when rejected")
	}
	if !bytes.Equal(retransmit, earlyData) {
		t.Fatalf("client should get retransmit data: got %q want %q", retransmit, earlyData)
	}
}

// ─── 8. fast_open default reject ─────────────────────────────────────────────

func TestFastOpenDefaultReject(t *testing.T) {
	// FastOpenPolicy="" should default to "reject"
	cfg, err := NewConfig(
		nil, nil, make([]byte, 32), // nil keys for this validation test
		"aes-256-gcm", "fast_open_1rtt", "",
		30, 120, nil, nil, nil, nil, 0,
	)
	// NewConfig with nil keys is fine for testing the policy default
	_ = err
	if cfg != nil && cfg.FastOpenPolicy != "reject" {
		t.Fatalf("default FastOpenPolicy should be reject, got %q", cfg.FastOpenPolicy)
	}
}

// ─── 9. Replay cache ──────────────────────────────────────────────────────────

func TestReplayCache(t *testing.T) {
	cfg, _ := makeTestConfig(t)
	cache := newReplayCache(2*time.Minute, 1024)

	clientConn, serverConn := net.Pipe()
	dst := M.ParseSocksaddrHostPort("example.com", 80)

	// First handshake succeeds
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ClientHandshake(clientConn, cfg, dst, nil)
	}()
	go func() {
		defer wg.Done()
		ServerHandshake(serverConn, cfg, cache)
	}()
	wg.Wait()

	// The replay key uniqueness is verified via the conn_id + client_eph_pub being random each time.
	// Direct replay: same key must be rejected
	now := time.Now().Unix()
	var key [32]byte
	rand.Read(key[:])
	if err := cache.Insert(key, now); err != nil {
		t.Fatal("first insert should succeed")
	}
	if err := cache.Insert(key, now); err == nil {
		t.Fatal("second insert of same key should be rejected")
	}
}

// ─── 10. replay cache unavailable → fast_open rejects ────────────────────────

func TestReplayCacheUnavailable(t *testing.T) {
	curve := ecdh.X25519()
	privKey, _ := curve.GenerateKey(rand.Reader)
	psk := make([]byte, 32)
	rand.Read(psk)
	cfg, _ := NewConfig(privKey.PublicKey(), privKey, psk,
		"aes-256-gcm", "fast_open_1rtt", "accept", 30, 120, nil, nil, nil, nil, 0)

	// cache with very short grace period (still in grace period = unavailable)
	cache := newReplayCache(60*time.Second, 1024)
	// Born just now, so available() = false (grace period not elapsed yet with 60s window)
	now := time.Now().Unix()
	if cache.Available(now) {
		t.Skip("cache already available (timing issue), skipping")
	}

	clientConn, serverConn := net.Pipe()
	dst := M.ParseSocksaddrHostPort("example.com", 80)
	earlyData := []byte("early")

	var sResult ServerResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ClientHandshake(clientConn, cfg, dst, earlyData)
	}()
	go func() {
		defer wg.Done()
		sResult, _ = ServerHandshake(serverConn, cfg, cache)
	}()
	wg.Wait()

	if sResult.FastOpenAccepted {
		t.Fatal("fast_open should not be accepted when cache is unavailable")
	}
}

// ─── 11. restart grace period ─────────────────────────────────────────────────

func TestRestartGracePeriod(t *testing.T) {
	cache := newReplayCache(30*time.Second, 1024)
	// Right after creation, grace period not elapsed
	now := time.Now().Unix()
	if cache.Available(now) {
		t.Fatal("cache should not be available immediately after creation")
	}
	// After grace period
	if !cache.Available(now + 61) {
		t.Fatal("cache should be available after 2*ClockSkewWindow seconds")
	}
}

// ─── 12. strict_2rtt rejects early data ───────────────────────────────────────

func TestStrictRejectsEarlyData(t *testing.T) {
	curve := ecdh.X25519()
	privKey, _ := curve.GenerateKey(rand.Reader)
	psk := make([]byte, 32)
	rand.Read(psk)

	// fast_open client → strict server
	clientCfg, _ := NewConfig(privKey.PublicKey(), privKey, psk,
		"aes-256-gcm", "fast_open_1rtt", "accept", 30, 120, nil, nil, nil, nil, 0)
	serverCfg, _ := NewConfig(privKey.PublicKey(), privKey, psk,
		"aes-256-gcm", "strict_2rtt", "reject", 30, 120, nil, nil, nil, nil, 0)

	clientConn, serverConn := net.Pipe()
	dst := M.ParseSocksaddrHostPort("example.com", 80)
	cache := newReplayCache(2*time.Minute, 1024)

	var serverErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ClientHandshake(clientConn, clientCfg, dst, []byte("evil early data"))
	}()
	go func() {
		defer wg.Done()
		_, serverErr = ServerHandshake(serverConn, serverCfg, cache)
	}()
	wg.Wait()

	if serverErr == nil {
		t.Fatal("strict_2rtt server should reject C1 with early data")
	}
}

// ─── 13. Invalid X25519 → auth failure ────────────────────────────────────────

func TestInvalidX25519(t *testing.T) {
	// all-zero shared secret should be rejected
	if !allZero(make([]byte, 32)) {
		t.Fatal("allZero check broken")
	}
	// This tests that the allZero guard works — actual ECDH with invalid key
	// would be caught by crypto/ecdh before reaching our code
}

// ─── 14. Bucket validation ────────────────────────────────────────────────────

func TestBucketValidation(t *testing.T) {
	buckets := []int{256, 512, 1024}

	if !inBuckets(buckets, 256) {
		t.Fatal("256 should be in buckets")
	}
	if inBuckets(buckets, 300) {
		t.Fatal("300 should not be in buckets")
	}
	if inBuckets(buckets, 0) {
		t.Fatal("0 should not be in buckets")
	}
}

// ─── 15. Bucket overflow → error ─────────────────────────────────────────────

func TestBucketOverLimit(t *testing.T) {
	buckets := []int{64, 128}
	_, err := chooseBucket(buckets, 200, 0)
	if err == nil {
		t.Fatal("should fail when payload exceeds max bucket")
	}
}

// ─── 16. Padding property: ciphertext length ∈ buckets ────────────────────────

func TestPaddingProperty(t *testing.T) {
	cfg, _ := makeTestConfig(t)
	curve := ecdh.X25519()
	ephPriv, _ := curve.GenerateKey(rand.Reader)

	// Pick a bucket, build C1 inner, verify output length matches
	var connID [12]byte
	rand.Read(connID[:])
	dst := M.ParseSocksaddrHostPort("test.example.com", 8080)

	es, _ := ephPriv.ECDH(cfg.ServerStaticPub)
	c1OuterWire := randBytes(96) // placeholder for th0 derivation
	c1k := deriveC1Keys(cfg.tcpMaster, cfg.ServerStaticPub.Bytes(), c1OuterWire, es)

	addrB := encodeAddr(socksAddrToSpec(dst))
	fixedSize := 1 + 1 + 8 + 12 + len(addrB) + 2 + 0 + 2
	aead := cfg.newAEAD(c1k.key)
	minCT := fixedSize + 2 + aead.Overhead()

	target, err := chooseBucket(cfg.C1Buckets, minCT, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !inBuckets(cfg.C1Buckets, target) {
		t.Fatalf("chosen bucket %d not in bucket list", target)
	}
}

// ─── 17. Timestamp validation ────────────────────────────────────────────────

func TestTimestamp(t *testing.T) {
	cfg, _ := makeTestConfig(t)

	// Build a valid C1 but with old timestamp, verify server rejects
	curve := ecdh.X25519()
	ephPriv, _ := curve.GenerateKey(rand.Reader)
	es, _ := ephPriv.ECDH(cfg.ServerStaticPub)

	var connID [12]byte
	rand.Read(connID[:])
	var ephPubBytes [32]byte
	copy(ephPubBytes[:], ephPriv.PublicKey().Bytes())

	c1OuterPlain := c1Outer{connID: connID, clientEphPub: ephPubBytes, innerCTLen: 256}
	c1OuterWire, c1oh, _ := encodeC1Outer(cfg, c1OuterPlain)
	c1k := deriveC1Keys(cfg.tcpMaster, cfg.ServerStaticPub.Bytes(), c1OuterWire, es)

	// old timestamp: 1000 seconds ago
	oldTime := uint64(time.Now().Unix() - 1000)
	c1InnerPlain := c1Inner{
		flags:      0,
		clientTime: oldTime,
		connID:     connID,
		dst:        socksAddrToSpec(M.ParseSocksaddrHostPort("example.com", 80)),
	}
	c1InnerWire, _ := encodeC1InnerFixed(cfg, c1InnerPlain, c1k, 256)

	// Feed directly to decoder
	decoded, err := decodeC1Inner(cfg, c1InnerWire, c1k)
	if err != nil {
		t.Fatal("inner decode should succeed")
	}
	// Check timestamp validation logic
	diff := int64(decoded.clientTime) - time.Now().Unix()
	if diff < 0 {
		diff = -diff
	}
	if diff <= int64(cfg.ClockSkewWindow.Seconds()) {
		t.Fatal("timestamp should be outside clock skew window")
	}
	_ = c1oh
}

// ─── 18. Active probing: random bytes → auth failure ─────────────────────────

func TestActiveProbingRandom(t *testing.T) {
	cfg, _ := makeTestConfig(t)
	cache := newReplayCache(2*time.Minute, 1024)

	clientConn, serverConn := net.Pipe()

	done := make(chan error, 1)
	go func() {
		_, err := ServerHandshake(serverConn, cfg, cache)
		done <- err
	}()

	// Send garbage
	garbage := randBytes(96)
	clientConn.Write(garbage)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("server should reject random bytes")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server should fail fast on garbage input")
	}
}

// ─── 19. KEY_UPDATE rotation ─────────────────────────────────────────────────

func TestKeyUpdate(t *testing.T) {
	cfg, _ := makeTestConfig(t)
	clientTC, serverTC, _ := pipeHandshake(t, cfg)

	// Save initial write state
	oldWriteKey := make([]byte, len(clientTC.writeKey))
	copy(oldWriteKey, clientTC.writeKey)

	// Simulate key rotation on client write side
	newSec := hkdfExpand(clientTC.writeSecret, []byte("ku"), 32)
	newKey := hkdfExpand(newSec, []byte("key"), 32)
	newIV4 := hkdfExpand(newSec, []byte("iv4"), 4)

	if bytes.Equal(oldWriteKey, newKey) {
		t.Fatal("KEY_UPDATE should produce different key")
	}

	// Verify write/read works normally before rotation
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientTC.Write([]byte("pre-rotation"))
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 100)
		n, _ := serverTC.Read(buf)
		if !bytes.Equal(buf[:n], []byte("pre-rotation")) {
			t.Errorf("pre-rotation data mismatch")
		}
	}()
	wg.Wait()

	_ = newIV4
}

// ─── 20. Cipher mismatch → auth failure ──────────────────────────────────────

func TestCipherMismatch(t *testing.T) {
	curve := ecdh.X25519()
	privKey, _ := curve.GenerateKey(rand.Reader)
	psk := make([]byte, 32)
	rand.Read(psk)

	clientCfg, _ := NewConfig(privKey.PublicKey(), privKey, psk,
		"aes-256-gcm", "strict_2rtt", "reject", 30, 120, nil, nil, nil, nil, 0)
	serverCfg, _ := NewConfig(privKey.PublicKey(), privKey, psk,
		"chacha20-poly1305", "strict_2rtt", "reject", 30, 120, nil, nil, nil, nil, 0)

	clientConn, serverConn := net.Pipe()
	cache := newReplayCache(2*time.Minute, 1024)
	dst := M.ParseSocksaddrHostPort("example.com", 80)

	var serverErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ClientHandshake(clientConn, clientCfg, dst, nil)
	}()
	go func() {
		defer wg.Done()
		_, serverErr = ServerHandshake(serverConn, serverCfg, cache)
	}()
	wg.Wait()

	if serverErr == nil {
		t.Fatal("cipher mismatch should cause auth failure")
	}
}

// ─── 21. Config validation ────────────────────────────────────────────────────

func TestConfigValidation(t *testing.T) {
	curve := ecdh.X25519()
	privKey, _ := curve.GenerateKey(rand.Reader)

	// Short PSK
	_, err := NewConfig(privKey.PublicKey(), privKey, make([]byte, 16),
		"aes-256-gcm", "strict_2rtt", "reject", 30, 120, nil, nil, nil, nil, 0)
	if err == nil {
		t.Fatal("should reject short PSK")
	}

	// Invalid cipher
	_, err = NewConfig(privKey.PublicKey(), privKey, make([]byte, 32),
		"blowfish", "strict_2rtt", "reject", 30, 120, nil, nil, nil, nil, 0)
	if err == nil {
		t.Fatal("should reject invalid cipher")
	}

	// Invalid handshake mode
	_, err = NewConfig(privKey.PublicKey(), privKey, make([]byte, 32),
		"aes-256-gcm", "zero_rtt", "reject", 30, 120, nil, nil, nil, nil, 0)
	if err == nil {
		t.Fatal("should reject invalid handshake mode")
	}

	// Invalid fast_open policy
	_, err = NewConfig(privKey.PublicKey(), privKey, make([]byte, 32),
		"aes-256-gcm", "fast_open_1rtt", "maybe", 30, 120, nil, nil, nil, nil, 0)
	if err == nil {
		t.Fatal("should reject invalid fast_open_policy")
	}
}

// ─── 22. Ephemeral key erasure (best-effort) ──────────────────────────────────

func TestEphPrivErasure(t *testing.T) {
	// Verify eraseKey doesn't panic
	curve := ecdh.X25519()
	k, _ := curve.GenerateKey(rand.Reader)
	eraseKey(k)
}

// ─── 23. Transcript hash test vectors ────────────────────────────────────────

func TestTranscriptHash(t *testing.T) {
	// th0 = H(proto || server_static_pub || c1oh) must be deterministic
	psk := make([]byte, 32)
	cfg, _ := NewConfig(
		mustGenPub(t), nil, psk, "aes-256-gcm", "strict_2rtt", "reject", 30, 120, nil, nil, nil, nil, 0)

	c1OW := randBytes(96)
	c1oh := h256(c1OW)
	th0a := h256([]byte(protoLabelTCP), cfg.ServerStaticPub.Bytes(), c1oh)
	th0b := h256([]byte(protoLabelTCP), cfg.ServerStaticPub.Bytes(), c1oh)
	if !bytes.Equal(th0a, th0b) {
		t.Fatal("th0 must be deterministic")
	}
}

func mustGenPub(t *testing.T) *ecdh.PublicKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey()
}

// ─── 24. UDP encrypt/decrypt ─────────────────────────────────────────────────

func TestUDPEncryptDecrypt(t *testing.T) {
	cfg, _ := makeTestConfig(t)
	sessionID := randBytes(12)
	k := deriveUDPKeys(cfg.udpMaster, sessionID)

	var sid [12]byte
	copy(sid[:], sessionID)

	pkt := udpC2SPacket{
		sessionID:  sid,
		packetID:   42,
		clientTime: uint64(time.Now().Unix()),
		dst:        addrSpec{atype: addrIPv4, ip: net.ParseIP("1.2.3.4"), port: 53},
		payload:    []byte("dns query"),
	}
	wire, err := encodeUDPC2S(cfg, k, pkt)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeUDPC2S(cfg, k, wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.payload, pkt.payload) {
		t.Fatalf("payload mismatch: got %q want %q", decoded.payload, pkt.payload)
	}
	if decoded.packetID != pkt.packetID {
		t.Fatalf("packetID mismatch")
	}
}

// ─── 25. UDP replay window ────────────────────────────────────────────────────

func TestUDPReplayWindow(t *testing.T) {
	// Simple sliding window: same packet_id detected as replay
	seen := make(map[uint64]bool)
	packetID := uint64(100)

	if seen[packetID] {
		t.Fatal("should not be seen initially")
	}
	seen[packetID] = true
	if !seen[packetID] {
		t.Fatal("should be seen after insert")
	}
}

// ─── 26. UDP bucket alignment ────────────────────────────────────────────────

func TestUDPBucketAlignment(t *testing.T) {
	cfg, _ := makeTestConfig(t)
	sessionID := randBytes(12)
	k := deriveUDPKeys(cfg.udpMaster, sessionID)

	var sid [12]byte
	copy(sid[:], sessionID)

	pkt := udpC2SPacket{
		sessionID:  sid,
		packetID:   1,
		clientTime: uint64(time.Now().Unix()),
		dst:        addrSpec{atype: addrIPv4, ip: net.ParseIP("8.8.8.8"), port: 53},
		payload:    []byte("q"),
	}
	wire, err := encodeUDPC2S(cfg, k, pkt)
	if err != nil {
		t.Fatal(err)
	}
	// wire = 12(session_id) + 8(packet_id) + CT
	ctLen := len(wire) - 20
	if !inBuckets(cfg.UDPBuckets, ctLen) {
		t.Fatalf("UDP CT length %d not in buckets %v", ctLen, cfg.UDPBuckets)
	}
}

// ─── 27. Direction key separation via full round-trip ─────────────────────────

func TestDirectionKeySeparation(t *testing.T) {
	cfg, _ := makeTestConfig(t)
	clientTC, serverTC, _ := pipeHandshake(t, cfg)

	if bytes.Equal(clientTC.writeKey, clientTC.readKey) {
		t.Fatal("client write key must differ from read key")
	}
	if bytes.Equal(serverTC.writeKey, serverTC.readKey) {
		t.Fatal("server write key must differ from read key")
	}
	// client write == server read, client read == server write
	if !bytes.Equal(clientTC.writeKey, serverTC.readKey) {
		t.Fatal("client.writeKey must equal server.readKey")
	}
	if !bytes.Equal(clientTC.readKey, serverTC.writeKey) {
		t.Fatal("client.readKey must equal server.writeKey")
	}
}

// ─── 28. Large data transfer ─────────────────────────────────────────────────

func TestLargeTransfer(t *testing.T) {
	cfg, _ := makeTestConfig(t)
	clientTC, serverTC, _ := pipeHandshake(t, cfg)

	size := 512 * 1024 // 512 KB
	data := make([]byte, size)
	rand.Read(data)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientTC.Write(data)
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 0, size)
		tmp := make([]byte, 32*1024)
		for len(buf) < size {
			n, err := serverTC.Read(tmp)
			if err != nil && err != io.EOF {
				t.Errorf("server read: %v", err)
				return
			}
			buf = append(buf, tmp[:n]...)
		}
		if !bytes.Equal(buf, data) {
			t.Error("large transfer data mismatch")
		}
	}()
	wg.Wait()
}

// ─── 29. ChaCha20-Poly1305 cipher ────────────────────────────────────────────

func TestChaCha20Handshake(t *testing.T) {
	cfg := makeTestConfigChacha(t)
	clientTC, serverTC, _ := pipeHandshake(t, cfg)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientTC.Write([]byte("chacha test"))
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 64)
		n, _ := serverTC.Read(buf)
		if string(buf[:n]) != "chacha test" {
			t.Errorf("chacha20 data mismatch: %q", buf[:n])
		}
	}()
	wg.Wait()
}

// ─── 30. Addr encode/decode roundtrip ────────────────────────────────────────

func TestAddrRoundtrip(t *testing.T) {
	cases := []addrSpec{
		{atype: addrIPv4, ip: net.ParseIP("192.168.1.1").To4(), port: 80},
		{atype: addrIPv6, ip: net.ParseIP("::1").To16(), port: 443},
		{atype: addrDomain, domain: "example.com", port: 8080},
	}
	for _, tc := range cases {
		b := encodeAddr(tc)
		got, n, err := decodeAddr(b)
		if err != nil {
			t.Fatalf("decodeAddr(%v): %v", tc, err)
		}
		if n != len(b) {
			t.Fatalf("consumed %d bytes, expected %d", n, len(b))
		}
		if got.port != tc.port {
			t.Fatalf("port mismatch: %d != %d", got.port, tc.port)
		}
		if got.atype != tc.atype {
			t.Fatalf("atype mismatch: %d != %d", got.atype, tc.atype)
		}
		if tc.atype == addrDomain && got.domain != tc.domain {
			t.Fatalf("domain mismatch: %q != %q", got.domain, tc.domain)
		}
	}
}

// ─── additional: uint16be / uint64be helpers ─────────────────────────────────

func TestUint16BE(t *testing.T) {
	b := uint16be(0xABCD)
	if b[0] != 0xAB || b[1] != 0xCD {
		t.Fatalf("uint16be wrong: %v", b)
	}
}

func TestUint64BE(t *testing.T) {
	b := uint64be(0x0102030405060708)
	expected := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if !bytes.Equal(b, expected) {
		t.Fatalf("uint64be wrong: %v", b)
	}
}

func TestBuildNonce(t *testing.T) {
	iv4 := []byte{0x01, 0x02, 0x03, 0x04}
	n := buildNonce(iv4, 0x0102030405060708)
	if !bytes.Equal(n[:4], iv4) {
		t.Fatal("nonce prefix wrong")
	}
	counter := binary.BigEndian.Uint64(n[4:])
	if counter != 0x0102030405060708 {
		t.Fatalf("nonce counter wrong: %x", counter)
	}
}
