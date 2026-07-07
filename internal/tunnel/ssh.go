package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/pujan-modha/paperboat-cli/internal/config"
	"github.com/pujan-modha/paperboat-cli/internal/resolver"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

// SSHTunnel is retained only for optional debug/operator SSH access. Production
// CLI attach now uses papercode WebSocket descriptors; implementing that
// transport is Phase 4 of the E2E tracker.
type SSHTunnel struct {
	cfg config.SSHConfig
}

// NewSSHTunnel builds the agentunnel SSH transport from SSH config.
func NewSSHTunnel(cfg config.SSHConfig) *SSHTunnel { return &SSHTunnel{cfg: cfg} }

func (t *SSHTunnel) Dial(ctx context.Context, info resolver.ConnectInfo) (Conn, error) {
	_ = ctx
	if info.Terminal == nil {
		return nil, errors.New("no terminal descriptor to dial")
	}
	return nil, errors.New("papercode WebSocket terminal transport is not implemented yet")
}

func (t *SSHTunnel) dialDebugSSH(ctx context.Context, host string, port int, user string) (Conn, error) {
	_, _, _, _ = ctx, host, port, user
	return nil, errors.New("debug SSH transport is not wired to production cli-connect descriptors")
}

func (t *SSHTunnel) authMethods() ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	// The running SSH agent is the primary source of credentials, matching a
	// normal `ssh` invocation.
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			methods = append(methods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}

	// An explicit identity file, or the user's default keys, are offered too.
	for _, path := range t.identityFiles() {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			// Encrypted keys without an agent are not handled here; skip rather
			// than prompt, and let the agent path cover the common case.
			continue
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if len(methods) == 0 {
		return nil, errors.New("no SSH credentials available: start ssh-agent or set ssh.identity_file in the CLI config")
	}
	return methods, nil
}

func (t *SSHTunnel) identityFiles() []string {
	if t.cfg.IdentityFile != "" {
		return []string{expandHome(t.cfg.IdentityFile)}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	candidates := []string{"id_ed25519", "id_ecdsa", "id_rsa"}
	paths := make([]string, 0, len(candidates))
	for _, name := range candidates {
		paths = append(paths, filepath.Join(home, ".ssh", name))
	}
	return paths
}

func (t *SSHTunnel) hostKeyCallback() (ssh.HostKeyCallback, error) {
	if t.cfg.InsecureSkipHostKeyCheck {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	path := t.cfg.KnownHostsFile
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home dir for known_hosts: %w", err)
		}
		path = filepath.Join(home, ".ssh", "known_hosts")
	} else {
		path = expandHome(path)
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("known_hosts file %s not found; add the tunnel host key or set ssh.insecure_skip_host_key_check for a trusted dev tunnel", path)
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %s: %w", path, err)
	}
	return cb, nil
}

func expandHome(path string) string {
	if len(path) == 0 || path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[1:])
}

func terminalType() string {
	if t := os.Getenv("TERM"); t != "" {
		return t
	}
	return "xterm-256color"
}

// sessStderr discards nothing — it forwards remote stderr to the local stderr so
// remote error output is visible. Implemented as an io.Writer to the process
// stderr; the session package owns stdout/stdin muxing for the paste bridge.
type sessStderr struct{}

func (sessStderr) Write(p []byte) (int, error) { return os.Stderr.Write(p) }

type sshConn struct {
	client *ssh.Client
	sess   *ssh.Session
	stdin  interface {
		Write([]byte) (int, error)
		Close() error
	}
	stdout interface {
		Read([]byte) (int, error)
	}
}

func (c *sshConn) Read(p []byte) (int, error)  { return c.stdout.Read(p) }
func (c *sshConn) Write(p []byte) (int, error) { return c.stdin.Write(p) }

func (c *sshConn) Close() error {
	_ = c.stdin.Close()
	_ = c.sess.Close()
	return c.client.Close()
}

func (c *sshConn) Resize(rows, cols uint16) error {
	return c.sess.WindowChange(int(rows), int(cols))
}

func (c *sshConn) Wait() (int, error) {
	err := c.sess.Wait()
	if err == nil {
		return 0, nil
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus(), nil
	}
	var missing *ssh.ExitMissingError
	if errors.As(err, &missing) {
		// Clean close without an explicit exit status: treat as success.
		return 0, nil
	}
	return 1, err
}

// initialWindowSize returns the current local terminal geometry (rows, cols),
// falling back to a standard 24x80 when stdout is not a terminal.
func initialWindowSize() (rows, cols int) {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		return 24, 80
	}
	return h, w
}

var _ Tunnel = (*SSHTunnel)(nil)
