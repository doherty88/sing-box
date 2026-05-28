package option

type PrivXInboundOptions struct {
	ListenOptions
	PrivXOptions
}

type PrivXOutboundOptions struct {
	DialerOptions
	ServerOptions
	PrivXOptions
}

// PrivXOptions are shared between inbound and outbound.
type PrivXOptions struct {
	// ServerPublicKey is the base64-encoded X25519 public key of the server (32 bytes).
	ServerPublicKey string `json:"server_public_key,omitempty"`
	// ServerPrivateKey is the base64-encoded X25519 private key (server-side only, 32 bytes).
	ServerPrivateKey string `json:"server_private_key,omitempty"`
	// PSK is the base64-encoded 32-byte pre-shared key (high-entropy random).
	PSK string `json:"psk"`
	// Cipher selects the AEAD: "aes-256-gcm" (default) or "chacha20-poly1305".
	Cipher string `json:"cipher,omitempty"`
	// HandshakeMode is "strict_2rtt" (default) or "fast_open_1rtt".
	HandshakeMode string `json:"handshake_mode,omitempty"`
	// FastOpenPolicy is "reject" (default) or "accept". Only used in fast_open_1rtt mode.
	FastOpenPolicy string `json:"fast_open_policy,omitempty"`
	// ClockSkewWindow is the allowed timestamp drift in seconds (default 30).
	ClockSkewWindow int `json:"clock_skew_window,omitempty"`
	// TCPReplayWindow is the replay cache TTL in seconds (default 120).
	TCPReplayWindow int `json:"tcp_replay_window,omitempty"`
	// C1InnerBuckets defines allowed C1 inner ciphertext sizes (bucket-aligned padding).
	C1InnerBuckets []int `json:"c1_inner_buckets,omitempty"`
	// S1InnerBuckets defines allowed S1 inner ciphertext sizes.
	S1InnerBuckets []int `json:"s1_inner_buckets,omitempty"`
	// RecordBuckets defines transport frame sizes.
	RecordBuckets []int `json:"record_buckets,omitempty"`
	// UDPBuckets defines UDP ciphertext sizes.
	UDPBuckets []int `json:"udp_buckets,omitempty"`
	// PadUpProbability is the chance of rounding up to the next bucket (0.0–1.0, default 0.15).
	PadUpProbability float64 `json:"pad_up_probability,omitempty"`
}
