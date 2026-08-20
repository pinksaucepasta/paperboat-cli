//go:build windows

package availability

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
)

const windowsHostServicePipe = `\\.\pipe\PaperboatHostService`

func dialAvailabilityHostService(ctx context.Context, path string, timeout time.Duration) (net.Conn, error) {
	if path != windowsHostServicePipe || timeout <= 0 {
		return nil, ErrInvalid
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return winio.DialPipeContext(dialCtx, path)
}

// Named pipes preserve message completion without a half-close. The server
// parses one bounded JSON request, then replies on the same duplex pipe.
func closeAvailabilityHostServiceWrite(net.Conn) error { return nil }

func NewHostClient(socketPath string, timeout time.Duration) (*HostClient, error) {
	if !strings.EqualFold(socketPath, windowsHostServicePipe) || timeout <= 0 {
		return nil, ErrInvalid
	}
	return &HostClient{socketPath: windowsHostServicePipe, timeout: timeout}, nil
}
