//go:build darwin || linux

package localapi

import (
	"context"
	"net"
	"path/filepath"
	"time"
)

func NewClient(socketPath string, timeout time.Duration) (*Client, error) {
	if !filepath.IsAbs(socketPath) || len(socketPath) > maxUnixSocketPath || timeout <= 0 || timeout > time.Minute {
		return nil, ErrInvalidConfig
	}
	return newClient(socketPath, timeout), nil
}

func dialLocal(ctx context.Context, socketPath string, timeout time.Duration) (net.Conn, error) {
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", socketPath)
}
