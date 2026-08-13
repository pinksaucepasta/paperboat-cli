//go:build darwin || linux

package managedssh

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

func ProbeAgentIdentity(ctx context.Context, socket string, expected [32]byte, timeout time.Duration) error {
	if ctx == nil || !filepath.IsAbs(socket) || expected == [32]byte{} || timeout <= 0 || timeout > 30*time.Second {
		return ErrAgentDenied
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(probeCtx, "unix", filepath.Clean(socket))
	if err != nil {
		return errors.Join(ErrAgentDenied, err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	keys, err := agent.NewClient(connection).List()
	if err != nil {
		return errors.Join(ErrAgentDenied, err)
	}
	for _, key := range keys {
		if sha256.Sum256(key.Marshal()) == expected {
			return nil
		}
	}
	return ErrAgentDenied
}
