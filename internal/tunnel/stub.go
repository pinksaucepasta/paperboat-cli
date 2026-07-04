package tunnel

import (
	"context"
	"errors"
	"os"
	"os/exec"

	"github.com/creack/pty"
	"github.com/pujan-modha/paperboat-cli/internal/resolver"
)

// StubTunnel attaches a local shell PTY instead of a remote VM. It lets the
// full wrapper (raw mode, resize, paste bridge, exit-code passthrough) be
// exercised end-to-end before agentunnel wiring exists. Swap in an
// agentunnel-backed Tunnel behind the same interface with no session changes.
type StubTunnel struct {
	// Shell overrides the launched program; empty uses $SHELL then /bin/sh.
	Shell string
}

// NewStubTunnel returns a local-shell tunnel.
func NewStubTunnel() *StubTunnel { return &StubTunnel{} }

// Dial spawns the shell attached to a new PTY.
func (t *StubTunnel) Dial(_ context.Context, _ resolver.ConnectInfo) (Conn, error) {
	shell := t.Shell
	if shell == "" {
		shell = os.Getenv("SHELL")
	}
	if shell == "" {
		shell = "/bin/sh"
	}
	cmd := exec.Command(shell)
	cmd.Env = os.Environ()
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}
	return &stubConn{ptmx: ptmx, cmd: cmd}, nil
}

type stubConn struct {
	ptmx *os.File
	cmd  *exec.Cmd
}

func (c *stubConn) Read(p []byte) (int, error)  { return c.ptmx.Read(p) }
func (c *stubConn) Write(p []byte) (int, error) { return c.ptmx.Write(p) }
func (c *stubConn) Close() error                { return c.ptmx.Close() }

func (c *stubConn) Resize(rows, cols uint16) error {
	return pty.Setsize(c.ptmx, &pty.Winsize{Rows: rows, Cols: cols})
}

func (c *stubConn) Wait() (int, error) {
	err := c.cmd.Wait()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}
