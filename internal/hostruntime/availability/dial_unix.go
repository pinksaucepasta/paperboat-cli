//go:build darwin || linux

package availability

import (
	"context"
	"net"
	"strings"
	"time"
)

func NewHostClient(socketPath string, timeout time.Duration) (*HostClient, error) {
	if !strings.HasPrefix(socketPath, "/") || timeout <= 0 {
		return nil, ErrInvalid
	}
	return &HostClient{socketPath: socketPath, timeout: timeout}, nil
}

func dialAvailabilityHostService(ctx context.Context, path string, timeout time.Duration) (net.Conn, error) {
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", path)
}

func closeAvailabilityHostServiceWrite(connection net.Conn) error {
	return connection.(interface{ CloseWrite() error }).CloseWrite()
}
