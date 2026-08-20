//go:build windows

package localdaemon

import (
	"context"
	"net"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transportmanager"
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

type DaemonConfig struct {
	Paths                   localapi.Paths
	Source                  MachineSource
	OwnerUID                int
	OwnerGID                int
	OwnerSID                string
	RefreshInterval         time.Duration
	RequestTimeout          time.Duration
	Clock                   func() time.Time
	ManagedSSH              *ManagedSSHConfig
	TransportManager        *transportmanager.Manager
	OpenPeerStream          func(context.Context, localapi.Peer, localapi.PeerStreamRequest, *transportmanager.Manager) (net.Conn, error)
	ProbePeer               func(context.Context, localapi.Peer, localapi.PeerStreamRequest) (localapi.PeerProbeResult, error)
	InvalidatePeerAuthority func(string)
	WarmPeerMetadata        func(context.Context, []api.UserMachine) error
	IssuePeerStream         func(context.Context, localapi.PeerStreamRequest) (localapi.PeerStreamRequest, error)
	FileTransfers           localapi.FileTransferBroker
}

func Run(ctx context.Context, config DaemonConfig) error { return runWindowsDaemon(ctx, config) }

// CurrentUserPaths returns the stable per-user state layout. Windows has no
// numeric UID, so the path resolver receives a validated non-negative marker;
// authorization is carried by the current user's SID through DaemonConfig and
// the named-pipe server.
func CurrentUserPaths() (localapi.Paths, error) { return localapi.CurrentPaths(0) }

// CurrentUserSID is exported for callers that construct a daemon explicitly
// or need to display the enrolled Windows owner in diagnostics.
func CurrentUserSID() (string, error) { return currentWindowsUserSID() }

func InstallCurrentUserService(ctx context.Context, executable, configPath, serverURL string) error {
	return installWindowsCurrentUserService(ctx, executable, configPath, serverURL)
}

func RemoveCurrentUserService(ctx context.Context, executable string) error {
	return removeWindowsCurrentUserService(ctx, executable)
}
