//go:build darwin || linux

package localdaemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/diagnostics"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transportmanager"
)

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

func Run(ctx context.Context, config DaemonConfig) error {
	if config.Source == nil || config.OwnerUID < 0 || config.OwnerGID < 0 || config.Paths.SocketPath == "" || config.Paths.LockPath == "" {
		return ErrInvalidInventoryConfig
	}
	lock, err := acquireProcessLock(config.Paths.LockPath, config.OwnerUID)
	if err != nil {
		return err
	}
	defer lock.Close()
	peerTransports := config.TransportManager
	if peerTransports == nil {
		peerTransports, err = transportmanager.New()
		if err != nil {
			return err
		}
	}
	go func() {
		<-ctx.Done()
		_ = peerTransports.Close()
	}()
	defer peerTransports.Close()
	if closer, ok := config.FileTransfers.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	recorder, err := diagnostics.NewRecorder(diagnostics.DiskConfig{Directory: filepath.Join(config.Paths.StateRoot, "diagnostics"), OwnerUID: config.OwnerUID, Clock: config.Clock})
	if err != nil {
		return err
	}
	transportInvalidator := NewMachineTransportInvalidator(peerTransports)
	if transportInvalidator != nil {
		transportInvalidator.authority = config.InvalidatePeerAuthority
	}
	if err := recorder.Record("daemon", "lifecycle", "info", map[string]string{"state": "starting"}); err != nil {
		_ = recorder.Close()
		return err
	}
	defer func() {
		_ = recorder.Record("daemon", "lifecycle", "info", map[string]string{"state": "stopping"})
		_ = recorder.Close()
	}()
	var managedSSHRuntime *ManagedSSHRuntime
	if config.ManagedSSH != nil {
		managedSSHRuntime, err = StartManagedSSH(ctx, *config.ManagedSSH)
		reportManagedSSHStartup(config.Source, recorder, err)
		defer func() {
			if managedSSHRuntime != nil {
				_ = managedSSHRuntime.Close()
			}
		}()
	}

	store, err := localapi.NewSnapshotStore(nil)
	if err != nil {
		return err
	}
	diagnosticClock := config.Clock
	if diagnosticClock == nil {
		diagnosticClock = time.Now
	}
	diagnosticAPI := &diagnosticService{recorder: recorder, store: store, stateRoot: config.Paths.StateRoot, ownerUID: config.OwnerUID, clock: diagnosticClock}
	inventory, err := NewInventory(InventoryConfig{Source: config.Source, Store: store, RefreshInterval: config.RefreshInterval, RequestTimeout: config.RequestTimeout, Clock: config.Clock, OnMachines: func(refreshCtx context.Context, machines []api.UserMachine) {
		transportInvalidator.Observe(machines)
		if config.WarmPeerMetadata != nil {
			warmTimeout := config.RequestTimeout
			if warmTimeout <= 0 {
				warmTimeout = defaultRequestTimeout
			}
			warmCtx, cancelWarm := context.WithTimeout(refreshCtx, warmTimeout)
			warmErr := config.WarmPeerMetadata(warmCtx, machines)
			cancelWarm()
			outcome, severity := "ready", "info"
			if warmErr != nil {
				outcome, severity = "degraded", "warning"
			}
			_ = recorder.Record("transport", "metadata_warm", severity, map[string]string{"outcome": outcome})
		}
	}})
	if err != nil {
		return err
	}
	observations, err := NewObservationStore(ObservationConfig{Store: store, OwnerUID: config.OwnerUID, Clock: config.Clock})
	if err != nil {
		return err
	}
	// A degraded snapshot is still authoritative local state and allows the API
	// to start while the control plane is temporarily unavailable.
	refreshErr := inventory.Refresh(ctx)
	refreshOutcome := "ready"
	refreshSeverity := "info"
	if refreshErr != nil {
		refreshOutcome = "degraded"
		refreshSeverity = "warning"
	}
	_ = recorder.Record("reconciliation", "inventory_refresh", refreshSeverity, map[string]string{"outcome": refreshOutcome})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	server, err := localapi.NewServer(localapi.ServerConfig{
		SocketPath:           config.Paths.SocketPath,
		OwnerUID:             config.OwnerUID,
		OwnerGID:             config.OwnerGID,
		Source:               store,
		Completions:          inventory,
		Diagnostics:          diagnosticAPI,
		AuthorizeDiagnostics: func(peer localapi.Peer) bool { return peer.UID == config.OwnerUID },
		Observations:         observations,
		PeerStreams:          peerStreamBroker{open: config.OpenPeerStream, manager: peerTransports, issue: config.IssuePeerStream},
		PeerProbes:           peerProbeBroker{probe: config.ProbePeer},
		FileTransfers:        config.FileTransfers,
		Stale:                lock,
	})
	if err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 3)
	go func() { results <- server.Run(runCtx) }()
	go func() { results <- inventory.runTicker(runCtx) }()
	go func() { results <- observations.Run(runCtx) }()
	first := <-results
	cancel()
	remaining := []error{<-results, <-results}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if first != nil && !errors.Is(first, context.Canceled) {
		return first
	}
	for _, result := range remaining {
		if result != nil && !errors.Is(result, context.Canceled) {
			return result
		}
	}
	return first
}

type peerStreamBroker struct {
	open    func(context.Context, localapi.Peer, localapi.PeerStreamRequest, *transportmanager.Manager) (net.Conn, error)
	manager *transportmanager.Manager
	issue   func(context.Context, localapi.PeerStreamRequest) (localapi.PeerStreamRequest, error)
}

type peerProbeBroker struct {
	probe func(context.Context, localapi.Peer, localapi.PeerStreamRequest) (localapi.PeerProbeResult, error)
}

func (b peerProbeBroker) ProbePeer(ctx context.Context, peer localapi.Peer, request localapi.PeerStreamRequest) (localapi.PeerProbeResult, error) {
	if b.probe == nil {
		return localapi.PeerProbeResult{}, errors.New("peer probe broker is unavailable")
	}
	return b.probe(ctx, peer, request)
}

func (b peerStreamBroker) OpenPeerStream(ctx context.Context, peer localapi.Peer, request localapi.PeerStreamRequest) (net.Conn, error) {
	if request.Credential == "" {
		if b.issue == nil {
			return nil, ErrInvalidInventoryConfig
		}
		var err error
		request, err = b.issue(ctx, request)
		if err != nil {
			return nil, err
		}
	}
	if b.open == nil || b.manager == nil {
		return nil, errors.New("peer stream broker is unavailable")
	}
	return b.open(ctx, peer, request, b.manager)
}

func CurrentUserPaths() (localapi.Paths, error) {
	return localapi.CurrentPaths(os.Geteuid())
}
