// Package tunnel abstracts reaching a project VM's terminal. In production the
// connection is carried through agentunnel (never a raw exposed port); the
// Tunnel/Conn interfaces keep the production transport testable through injected doubles.
package tunnel

import (
	"context"
	"errors"
	"io"

	"github.com/pujan-modha/paperboat-cli/internal/resolver"
)

var ErrInputEOFUnsupported = errors.New("terminal protocol does not support stdin EOF")

// Conn is an attached remote terminal: a bidirectional byte stream plus the
// out-of-band controls a PTY needs.
type Conn interface {
	io.ReadWriteCloser
	// Resize propagates a local terminal resize to the remote PTY.
	Resize(rows, cols uint16) error
	// Wait blocks until the remote session ends and returns its exit code.
	Wait() (exitCode int, err error)
}

type InputHalfCloser interface {
	CloseWrite() error
}

// Tunnel dials a project VM and attaches its terminal.
type Tunnel interface {
	Dial(ctx context.Context, info resolver.ConnectInfo) (Conn, error)
}
