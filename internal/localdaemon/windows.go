//go:build windows

package localdaemon

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transportmanager"
)

// ErrWindowsHostModeUnavailable is deliberately explicit. Windows release
// artifacts are buildable now, but host-mode local API and ConPTY brokering
// are not enabled until the Windows service implementation is complete.
var ErrWindowsHostModeUnavailable = errors.New("Windows host mode is not available yet")

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

func Run(context.Context, DaemonConfig) error { return ErrWindowsHostModeUnavailable }

func CurrentUserPaths() (localapi.Paths, error) {
	return localapi.CurrentPaths(os.Getuid())
}

func InstallCurrentUserService(context.Context, string, string, string) error {
	return ErrWindowsHostModeUnavailable
}

func RemoveCurrentUserService(context.Context, string) error {
	return ErrWindowsHostModeUnavailable
}
