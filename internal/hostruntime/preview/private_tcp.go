package preview

import (
	"context"
	"errors"
	"io"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/privatepreview"
	"github.com/pinksaucepasta/paperboat/internal/privatepreviewproxy"
)

var (
	ErrPrivateTCPClientInvalid     = errors.New("invalid private preview TCP client")
	ErrPrivateTCPClientUnavailable = errors.New("private preview TCP carrier unavailable")
)

// AuthorizedPrivateTCPStreamSource opens one already-authorized, ephemeral
// carrier stream. The source owns control-plane grant acquisition and current
// route/session fencing. This package never receives or stores the grant.
type AuthorizedPrivateTCPStreamSource func(context.Context) (io.ReadWriteCloser, error)

// PrivateTCPProxyConfig describes a literal-loopback client for one private
// preview target. The listener is always created by privatepreviewproxy on
// 127.0.0.1. TargetPort is sent through the bounded private-preview preface;
// no origin address or credential is sent to the carrier source.
type PrivateTCPProxyConfig struct {
	ListenPort         uint16
	TargetPort         uint16
	MaximumConnections int
	OpenStream         AuthorizedPrivateTCPStreamSource
}

// PrivateTCPAccessRequest is the narrow hostd API seam used by the future
// `pb access tunnel` command. RouteID is server-owned safe metadata. The
// caller cannot supply an origin address, carrier identity, or credential.
type PrivateTCPAccessRequest struct {
	RouteID            string
	ListenPort         uint16
	MaximumConnections int
}

// StartPrivateTCPAccess creates the access-only listener from the stable
// runtime source. Every accepted local connection performs fresh discovery,
// grant issuance, and exact private_access_tcp carrier authorization.
func (r *MachinePreviewRuntime) StartPrivateTCPAccess(ctx context.Context, request PrivateTCPAccessRequest) (*privatepreviewproxy.Proxy, error) {
	if r == nil || ctx == nil || request.RouteID == "" {
		return nil, ErrPrivateTCPClientInvalid
	}
	r.mu.Lock()
	if r.closed || r.private == nil {
		r.mu.Unlock()
		return nil, ErrMachinePreviewRuntimeClosed
	}
	source := r.private
	r.mu.Unlock()
	return privatepreviewproxy.Start(ctx, privatepreviewproxy.Config{
		ListenPort: request.ListenPort, MaximumConnections: request.MaximumConnections,
		Dial: func(openContext context.Context) (io.ReadWriteCloser, error) {
			stream, err := source.OpenPrivateTCP(openContext, request.RouteID)
			if err != nil {
				return nil, errors.Join(ErrPrivateTCPClientUnavailable, err)
			}
			return stream, nil
		},
	})
}

// StartPrivateTCPProxy starts a bounded loopback listener whose each accepted
// connection uses a fresh authorized carrier stream. privatepreview.Open
// performs the literal loopback target handshake before the proxy exposes the
// stream to the local client. The first authorized stream is preflighted by
// privatepreviewproxy.Start and then consumed by the first local connection.
func StartPrivateTCPProxy(ctx context.Context, config PrivateTCPProxyConfig) (*privatepreviewproxy.Proxy, error) {
	if ctx == nil || config.TargetPort == 0 || config.OpenStream == nil {
		return nil, ErrPrivateTCPClientInvalid
	}
	proxy, err := privatepreviewproxy.Start(ctx, privatepreviewproxy.Config{
		ListenPort:         config.ListenPort,
		MaximumConnections: config.MaximumConnections,
		Dial: func(dialContext context.Context) (io.ReadWriteCloser, error) {
			stream, err := config.OpenStream(dialContext)
			if err != nil {
				return nil, errors.Join(ErrPrivateTCPClientUnavailable, err)
			}
			if stream == nil {
				return nil, ErrPrivateTCPClientUnavailable
			}
			if err := privatepreview.Open(dialContext, stream, config.TargetPort); err != nil {
				_ = stream.Close()
				return nil, errors.Join(ErrPrivateTCPClientUnavailable, err)
			}
			return stream, nil
		},
	})
	if err != nil {
		return nil, err
	}
	return proxy, nil
}
