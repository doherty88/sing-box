package privx

import (
	"context"
	"encoding/base64"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"crypto/ecdh"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.PrivXInboundOptions](registry, C.TypePrivX, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	router   adapter.ConnectionRouterEx
	logger   log.ContextLogger
	listener *listener.Listener
	cfg      *Config
	cache    *replayCache
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.PrivXInboundOptions) (adapter.Inbound, error) {
	cfg, err := parseConfig(options.PrivXOptions, true)
	if err != nil {
		return nil, err
	}

	cache := newReplayCache(cfg.TCPReplayWindow, 65536)

	ib := &Inbound{
		Adapter: inbound.NewAdapter(C.TypePrivX, tag),
		router:  router,
		logger:  logger,
		cfg:     cfg,
		cache:   cache,
	}
	ib.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: ib,
	})
	return ib, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return h.listener.Close()
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	result, err := ServerHandshake(conn, h.cfg, h.cache)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "handshake from ", metadata.Source))
		return
	}

	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Destination = result.Dst
	h.logger.InfoContext(ctx, "inbound connection to ", result.Dst)

	var tcpConn net.Conn = result.Conn
	if len(result.EarlyData) > 0 {
		tcpConn = &prependConn{Conn: result.Conn, prepend: result.EarlyData}
	}

	h.router.RouteConnectionEx(ctx, tcpConn, metadata, onClose)
}

// prependConn prepends already-decrypted early data before reads from the underlying conn.
type prependConn struct {
	net.Conn
	prepend []byte
}

func (c *prependConn) Read(b []byte) (int, error) {
	if len(c.prepend) > 0 {
		n := copy(b, c.prepend)
		c.prepend = c.prepend[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// ─── config parsing ───────────────────────────────────────────────────────────

func parseConfig(opts option.PrivXOptions, isServer bool) (*Config, error) {
	psk, err := base64.StdEncoding.DecodeString(opts.PSK)
	if err != nil {
		return nil, E.Cause(err, "privx: invalid PSK base64")
	}

	curve := ecdh.X25519()
	pubBytes, err := base64.StdEncoding.DecodeString(opts.ServerPublicKey)
	if err != nil {
		return nil, E.Cause(err, "privx: invalid server_public_key base64")
	}
	pubKey, err := curve.NewPublicKey(pubBytes)
	if err != nil {
		return nil, E.Cause(err, "privx: invalid server_public_key")
	}

	var privKey *ecdh.PrivateKey
	if isServer {
		privBytes, err := base64.StdEncoding.DecodeString(opts.ServerPrivateKey)
		if err != nil {
			return nil, E.Cause(err, "privx: invalid server_private_key base64")
		}
		privKey, err = curve.NewPrivateKey(privBytes)
		if err != nil {
			return nil, E.Cause(err, "privx: invalid server_private_key")
		}
	}

	return NewConfig(
		pubKey, privKey, psk,
		opts.Cipher,
		opts.HandshakeMode,
		opts.FastOpenPolicy,
		opts.ClockSkewWindow,
		opts.TCPReplayWindow,
		opts.C1InnerBuckets,
		opts.S1InnerBuckets,
		opts.RecordBuckets,
		opts.UDPBuckets,
		opts.PadUpProbability,
	)
}

func addrFromSocksaddr(addr M.Socksaddr) addrSpec {
	return socksAddrToSpec(addr)
}
