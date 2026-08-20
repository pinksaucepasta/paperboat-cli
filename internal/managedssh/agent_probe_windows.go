//go:build windows

package managedssh

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"
)

func ProbeAgentIdentity(ctx context.Context, socket string, expected [32]byte, timeout time.Duration) error {
	if ctx == nil || !validWindowsAgentPipe(socket) || expected == [32]byte{} || timeout <= 0 || timeout > 30*time.Second {
		return ErrAgentDenied
	}
	probeContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := winio.DialPipeContext(probeContext, socket)
	if err != nil {
		return errors.Join(ErrAgentDenied, err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return errors.Join(ErrAgentDenied, err)
	}
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
