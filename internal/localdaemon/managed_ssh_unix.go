//go:build darwin || linux

package localdaemon

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
)

type ManagedSSHConfig struct {
	ServerURL            string
	Auth                 config.AuthSource
	Store                config.ProfileStore
	CLIClientSessionID   string
	Home                 string
	RuntimeDirectory     string
	Executable           string
	OwnerUID             uint32
	InheritedAgentSocket string
}

type ManagedSSHRuntime struct {
	agent *managedssh.AgentService
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
	_, err = api.New(cfg.ServerURL, credential, nil).RegisterManagedSSHClientKey(registerCtx, identity.PublicKey, identity.Fingerprint, "managed-ssh-register-"+hex.EncodeToString(identity.Fingerprint[:16]))
	cancel()
	if err != nil {
		return nil, err
	}
	capabilities, err := managedssh.ProbeOpenSSH(ctx, "ssh", 5*time.Second)
	if err != nil || !capabilities.Ready() {
		return nil, errors.Join(managedssh.ErrOpenSSHUnavailable, err)
	}
	agent, err := managedssh.StartAgentService(ctx, managedssh.AgentServiceConfig{RuntimeDirectory: cfg.RuntimeDirectory, InheritedAgentSocket: cfg.InheritedAgentSocket, Signer: identity.Signer, MaxConnections: 32, IdleTimeout: 2 * time.Minute, DelegateTimeout: 3 * time.Second})
	if err != nil {
		return nil, err
	}
	command := strconv.Quote(cfg.Executable)
	_, err = managedssh.InstallOpenSSHConfig(managedssh.OpenSSHConfig{
		Home: cfg.Home, OwnerUID: cfg.OwnerUID, AliasSuffix: managedssh.AliasSuffix,
		ProxyCommand:      command + " __ssh-proxy --host %h --port %p",
		KnownHostsCommand: command + " __ssh-known-hosts --host %H --port %p",
		AgentSocket:       agent.Socket(),
	})
	if err != nil {
		_ = agent.Close()
		return nil, err
	}
	return &ManagedSSHRuntime{agent: agent}, nil
}

func (r *ManagedSSHRuntime) Close() error {
	if r == nil || r.agent == nil {
		return nil
	}
	return r.agent.Close()
}

func ManagedSSHHealthCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, managedssh.ErrOpenSSHUnavailable), errors.Is(err, managedssh.ErrOpenSSHConfigConflict), errors.Is(err, managedssh.ErrAgentDenied):
		return "ssh_target_not_ready"
	default:
		return "ssh_key_rejected"
	}
}
