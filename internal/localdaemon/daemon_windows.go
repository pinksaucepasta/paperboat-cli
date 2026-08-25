//go:build windows

package localdaemon

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/diagnostics"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transportmanager"
)

func runWindowsDaemon(ctx context.Context, config DaemonConfig) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if config.Source == nil || config.Paths.SocketPath == "" || config.Paths.LockPath == "" || config.Paths.StateRoot == "" {
		return ErrInvalidInventoryConfig
	}
	ownerSID, err := resolveWindowsOwnerSID(config.OwnerSID)
	if err != nil {
		return ErrInvalidInventoryConfig
	}
	lock, err := acquireProcessLock(config.Paths.LockPath, ownerSID)
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
	transportNetwork, err := newWindowsTransportNetworkWatcher(peerTransports)
	if err != nil {
		return err
	}
	defer transportNetwork.Close()

	recorder, err := diagnostics.NewRecorder(diagnostics.DiskConfig{
		Directory: filepath.Join(config.Paths.StateRoot, "diagnostics"),
		OwnerSID:  ownerSID,
		OwnerUID:  -1,
		Clock:     config.Clock,
	})
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
		if err != nil {
			// Keep the daemon available when optional SSH integration is degraded;
			// inventory health exposes the repairable condition to the client.
			managedSSHRuntime = nil
		}
		defer func() {
			if managedSSHRuntime != nil {
				_ = managedSSHRuntime.Close()
			}
		}()
	}

	diagnosticClock := config.Clock
	if diagnosticClock == nil {
		diagnosticClock = time.Now
	}
	// Publish local readiness before the first control-plane refresh. A refresh
	// has a bounded network timeout and must not keep the named pipe absent long
	// enough for the first command after logon or reboot to fail. Inventory.Run
	// replaces this starting snapshot as soon as reconciliation completes.
	store, err := localapi.NewSnapshotStore(&localapi.Snapshot{
		Schema:      localapi.SnapshotSchemaV1,
		Generation:  1,
		ObservedAt:  diagnosticClock().UTC(),
		DaemonState: "starting",
	})
	if err != nil {
		return err
	}
	diagnosticAPI := &diagnosticService{
		recorder:  recorder,
		store:     store,
		stateRoot: config.Paths.StateRoot,
		ownerSID:  ownerSID,
		clock:     diagnosticClock,
	}
	inventory, err := NewInventory(InventoryConfig{
		Source:          config.Source,
		Store:           store,
		RefreshInterval: config.RefreshInterval,
		RequestTimeout:  config.RequestTimeout,
		Clock:           config.Clock,
		OnMachines: func(refreshCtx context.Context, machines []api.UserMachine) {
			if transportInvalidator != nil {
				transportInvalidator.Observe(machines)
			}
			if managedSSHRuntime != nil {
				sshCtx, cancelSSH := context.WithTimeout(refreshCtx, 15*time.Second)
				if refreshErr := managedSSHRuntime.Refresh(sshCtx); refreshErr != nil {
					_ = recorder.Record("ssh", "managed_refresh", "warning", map[string]string{"outcome": "degraded", "reason": ManagedSSHHealthCode(refreshErr)})
				}
				cancelSSH()
			}
			if config.WarmPeerMetadata == nil {
				return
			}
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
		},
	})
	if err != nil {
		return err
	}
	observations, err := NewObservationStore(ObservationConfig{Store: store, OwnerUID: -1, OwnerSID: ownerSID, Clock: config.Clock})
	if err != nil {
		return err
	}
	server, err := localapi.NewServer(localapi.ServerConfig{
		SocketPath:           config.Paths.SocketPath,
		OwnerUID:             -1,
		OwnerGID:             -1,
		OwnerSID:             ownerSID,
		Source:               store,
		Completions:          inventory,
		Diagnostics:          diagnosticAPI,
		AuthorizeDiagnostics: func(peer localapi.Peer) bool { return peer.SID == ownerSID },
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
	go func() {
		refreshErr := inventory.Refresh(runCtx)
		refreshOutcome, refreshSeverity := "ready", "info"
		if refreshErr != nil {
			refreshOutcome, refreshSeverity = "degraded", "warning"
		}
		_ = recorder.Record("reconciliation", "inventory_refresh", refreshSeverity, map[string]string{"outcome": refreshOutcome})
		if runCtx.Err() != nil {
			results <- runCtx.Err()
			return
		}
		results <- inventory.runTicker(runCtx)
	}()
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

type peerProbeBroker struct {
	probe func(context.Context, localapi.Peer, localapi.PeerStreamRequest) (localapi.PeerProbeResult, error)
}

func (b peerProbeBroker) ProbePeer(ctx context.Context, peer localapi.Peer, request localapi.PeerStreamRequest) (localapi.PeerProbeResult, error) {
	if b.probe == nil {
		return localapi.PeerProbeResult{}, errors.New("peer probe broker is unavailable")
	}
	return b.probe(ctx, peer, request)
}

var _ localapi.PeerStreamBroker = peerStreamBroker{}
var _ localapi.PeerProbeBroker = peerProbeBroker{}
