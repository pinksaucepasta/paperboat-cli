//go:build windows

package localdaemon

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

const windowsManagedAgentPipe = managedssh.WindowsInstalledAgentPipe

const (
	windowsManagedSSHMarker      = "paperboat-managed-ssh-v1"
	windowsManagedSSHBeginMarker = "# BEGIN paperboat-managed-ssh-v1"
	windowsManagedSSHEndMarker   = "# END paperboat-managed-ssh-v1"
	windowsManagedSSHMaxConfig   = 1 << 20
)

type ManagedSSHRuntime struct {
	closeFn func() error
	once    sync.Once
	err     error
}

func StartManagedSSH(ctx context.Context, cfg ManagedSSHConfig) (*ManagedSSHRuntime, error) {
	if ctx == nil || strings.TrimSpace(cfg.ServerURL) == "" || cfg.Auth == nil || cfg.Store.Path == "" || strings.TrimSpace(cfg.CLIClientSessionID) == "" || !filepath.IsAbs(cfg.Home) || !filepath.IsAbs(cfg.RuntimeDirectory) || !filepath.IsAbs(cfg.Executable) {
		return nil, ErrInvalidInventoryConfig
	}
	identity, err := cfg.Store.ManagedSSHIdentity(cfg.ServerURL, cfg.CLIClientSessionID)
	if err != nil {
		return nil, err
	}
	credential, err := cfg.Auth.Credential()
	if err != nil {
		return nil, err
	}
	registerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	client := api.New(cfg.ServerURL, credential, nil)
	_, err = client.RegisterManagedSSHClientKey(registerCtx, identity.PublicKey, identity.Fingerprint, "managed-ssh-register-"+hex.EncodeToString(identity.Fingerprint[:16]))
	cancel()
	if err != nil {
		return nil, err
	}
	capabilities, err := managedssh.ProbeOpenSSH(ctx, "ssh.exe", 5*time.Second)
	if err != nil || !capabilities.Ready() {
		return nil, errors.Join(managedssh.ErrOpenSSHUnavailable, err)
	}
	agentRuntime, err := startWindowsAgent(ctx, identity.Signer, cfg.InheritedAgentSocket)
	if err != nil {
		return nil, err
	}
	targets, err := managedSSHAliasTargets(ctx, client)
	if err != nil {
		_ = agentRuntime.Close()
		return nil, err
	}
	if err := installWindowsOpenSSHConfig(cfg, agentRuntime.socket, identity.PublicKey, targets); err != nil {
		_ = agentRuntime.Close()
		return nil, err
	}
	return &ManagedSSHRuntime{closeFn: agentRuntime.Close}, nil
}

func (r *ManagedSSHRuntime) Close() error {
	if r == nil || r.closeFn == nil {
		return nil
	}
	r.once.Do(func() { r.err = r.closeFn() })
	return r.err
}

func ManagedSSHHealthCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, managedssh.ErrOpenSSHUnavailable), errors.Is(err, managedssh.ErrOpenSSHConfigConflict), errors.Is(err, managedssh.ErrManagedIdentityFileConflict), errors.Is(err, managedssh.ErrAgentDenied):
		return "ssh_target_not_ready"
	default:
		return "ssh_key_rejected"
	}
}

type windowsAgentRuntime struct {
	socket   string
	cancel   context.CancelFunc
	done     chan error
	delegate net.Conn
	once     sync.Once
	err      error
}

func startWindowsAgent(parent context.Context, signer ssh.Signer, inherited string) (*windowsAgentRuntime, error) {
	if parent == nil || signer == nil {
		return nil, managedssh.ErrAgentDenied
	}
	ownerSID, err := currentWindowsUserSID()
	if err != nil {
		return nil, err
	}
	listener, err := winio.ListenPipe(windowsManagedAgentPipe, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;" + ownerSID + ")",
		MessageMode:        false,
		InputBufferSize:    managedssh.MaxAgentRequestBytes + 4,
		OutputBufferSize:   managedssh.MaxAgentRequestBytes + 4,
	})
	if err != nil {
		return nil, err
	}
	managed, err := managedssh.NewAgent(signer)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	var delegate agent.ExtendedAgent
	var delegateConnection net.Conn
	if inherited != "" {
		if !validWindowsAgentPipe(inherited) || strings.EqualFold(inherited, windowsManagedAgentPipe) {
			_ = listener.Close()
			return nil, managedssh.ErrAgentDenied
		}
		delegateConnection, err = winio.DialPipeContext(parent, inherited)
		if err != nil {
			_ = listener.Close()
			return nil, err
		}
		delegate = agent.NewClient(delegateConnection)
	}
	aggregate, err := managedssh.NewAggregate(managed, delegate)
	if err != nil {
		_ = listener.Close()
		if delegateConnection != nil {
			_ = delegateConnection.Close()
		}
		return nil, err
	}
	runCtx, cancel := context.WithCancel(parent)
	runtime := &windowsAgentRuntime{socket: windowsManagedAgentPipe, cancel: cancel, done: make(chan error, 1), delegate: delegateConnection}
	go func() {
		runtime.done <- (managedssh.Server{Agent: aggregate, MaxConnections: 32, IdleTimeout: 2 * time.Minute}).Serve(runCtx, listener)
	}()
	return runtime, nil
}

func (r *windowsAgentRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		r.cancel()
		r.err = <-r.done
		if r.delegate != nil {
			r.err = errors.Join(r.err, r.delegate.Close())
		}
	})
	return r.err
}

func validWindowsAgentPipe(value string) bool {
	const prefix = "\\\\.\\pipe\\"
	return strings.HasPrefix(strings.ToLower(value), prefix) && len(value) > len(prefix) && len(value) <= 256 && !strings.ContainsAny(value[len(prefix):], "/\\\\:*?\"<>|"+"\x00\r\n")
}

func installWindowsOpenSSHConfig(cfg ManagedSSHConfig, agentSocket, publicKey string, targets []managedssh.OpenSSHAliasTarget) error {
	if err := managedssh.InstallManagedIdentityPublicKey(cfg.Home, cfg.OwnerUID, publicKey); err != nil {
		return err
	}
	identityFile := managedssh.ManagedIdentityPublicKeyPath(cfg.Home)
	executable := quoteWindowsOpenSSH(cfg.Executable)
	_, err := managedssh.InstallOpenSSHConfig(managedssh.OpenSSHConfig{
		Home: cfg.Home, OwnerUID: cfg.OwnerUID, AliasSuffix: managedssh.AliasSuffix,
		ProxyCommand:      executable + " __ssh-proxy --host %h --port %p --user %r",
		KnownHostsCommand: executable + " __ssh-known-hosts --host %h --port %p",
		AgentSocket:       agentSocket,
		IdentityFile:      identityFile,
		Targets:           targets,
	})
	return err
}

func ensureWindowsSSHDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalidInventoryConfig
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return managedssh.ErrOpenSSHConfigConflict
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return managedssh.ErrOpenSSHConfigConflict
	}
	return nil
}

func readWindowsSSHConfig(path string) (string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", managedssh.ErrOpenSSHConfigConflict
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.Size() > windowsManagedSSHMaxConfig {
		return "", managedssh.ErrOpenSSHConfigConflict
	}
	body, err := os.ReadFile(path)
	if err != nil || len(body) > windowsManagedSSHMaxConfig || strings.ContainsRune(string(body), 0) {
		return "", managedssh.ErrOpenSSHConfigConflict
	}
	return string(body), nil
}

func renderWindowsManagedSSH(executable, agentSocket, identityFile string) ([]byte, error) {
	if !filepath.IsAbs(executable) || !strings.EqualFold(filepath.Ext(executable), ".exe") || !validWindowsAgentPipe(agentSocket) || !filepath.IsAbs(identityFile) || strings.ContainsAny(identityFile, "\r\n\x00\"") {
		return nil, managedssh.ErrOpenSSHConfigConflict
	}
	command := quoteWindowsOpenSSH(executable)
	value := windowsManagedSSHBeginMarker + "\n" +
		"Host *." + managedssh.AliasSuffix + "\n" +
		"    ProxyCommand " + command + " __ssh-proxy --host %h --port %p --user %r\n" +
		"    KnownHostsCommand " + command + " __ssh-known-hosts --host %h --port %p\n" +
		"    IdentityAgent " + strings.ReplaceAll(agentSocket, "\\", "\\\\") + "\n" +
		"    IdentityFile " + quoteWindowsOpenSSH(identityFile) + "\n" +
		"    IdentitiesOnly yes\n" +
		"    BatchMode yes\n" +
		"    PasswordAuthentication no\n" +
		"    KbdInteractiveAuthentication no\n" +
		"    StrictHostKeyChecking yes\n" +
		"    CheckHostIP no\n" +
		"    UserKnownHostsFile none\n" +
		"    GlobalKnownHostsFile none\n" +
		windowsManagedSSHEndMarker + "\n"
	return []byte(value), nil
}

func quoteWindowsOpenSSH(value string) string {
	return "\"" + strings.ReplaceAll(value, "\"", "\\\"") + "\""
}
