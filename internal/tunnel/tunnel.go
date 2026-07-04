// Package tunnel abstracts reaching a project VM's terminal. In production the
// connection is carried through agentunnel (never a raw exposed port); the
// Tunnel/Conn interfaces keep that transport swappable. A local dev stub spawns
// a shell so the wrapper is exercisable before agentunnel wiring lands.
package tunnel

import (
	"context"
	"io"

	"github.com/pujan-modha/paperboat-cli/internal/resolver"
)

// Conn is an attached remote terminal: a bidirectional byte stream plus the
// out-of-band controls a PTY needs.
type Conn interface {
	io.ReadWriteCloser
	// Resize propagates a local terminal resize to the remote PTY.
	Resize(rows, cols uint16) error
	// Wait blocks until the remote session ends and returns its exit code.
	Wait() (exitCode int, err error)
}

// Tunnel dials a project VM and attaches its terminal.
type Tunnel interface {
	Dial(ctx context.Context, info resolver.ConnectInfo) (Conn, error)
}
