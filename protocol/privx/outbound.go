package privx

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.PrivXOutboundOptions](registry, C.TypePrivX, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger     log.ContextLogger
	dialer     N.Dialer
	serverAddr M.Socksaddr
	cfg        *Config
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.PrivXOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	cfg, err := parseConfig(options.PrivXOptions, false)
	if err != nil {
		return nil, err
	}

	return &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypePrivX, tag, []string{N.NetworkTCP}, options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		cfg:        cfg,
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.dialTCP(ctx, destination)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("privx: UDP not supported in outbound (use TCP)")
}

func (h *Outbound) dialTCP(ctx context.Context, dst M.Socksaddr) (net.Conn, error) {
	conn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	tc, retransmit, err := ClientHandshake(conn, h.cfg, dst, nil)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "privx handshake")
	}
	if len(retransmit) > 0 {
		if _, err = tc.Write(retransmit); err != nil {
			tc.Close()
			return nil, err
		}
	}
	return tc, nil
}
