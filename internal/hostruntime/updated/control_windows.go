//go:build windows

package updated

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/autoupdate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
	"github.com/pinksaucepasta/paperboat/internal/selfupdate"
)

var ErrWindowsActivationUnavailable = errors.New("Windows updater activation is unavailable")

var windowsActivationHandoffDelay = 2 * time.Second
var startWindowsActivator = startWindowsActivatorService

type windowsController struct {
	activeVersion string
	ownerSID      string
	socketPath    string
	resolve       workerupdate.Resolver
	scheduler     *autoupdate.Scheduler
	mu            sync.Mutex
	checkMu       sync.Mutex
	config        WindowsConfig
	handoff       chan struct{}
	handoffOnce   sync.Once
}

func newWindowsController(config WindowsConfig) (*windowsController, error) {
	resolve := config.ResolveRelease
	if resolve == nil {
		source := workerupdate.TUFSource{
			RepositoryURL: config.RepositoryURL,
			StateRoot:     filepath.Join(config.StateRoot, "tuf"),
			MachineID:     config.MachineID,
		}
		resolve = source.Resolve
	}
	controller := &windowsController{
		activeVersion: config.ActiveVersion,
		ownerSID:      config.OwnerSID,
		socketPath:    config.ControlSocket,
		resolve:       resolve,
		config:        config,
		handoff:       make(chan struct{}),
	}
	scheduler, err := autoupdate.New(autoupdate.Config{Check: controller.checkRelease})
	if err != nil {
		return nil, err
	}
	controller.scheduler = scheduler
	return controller, nil
}

func (c *windowsController) run(ctx context.Context) error {
	if c == nil || c.scheduler == nil || !validPipePath(c.socketPath) {
		return ErrInvalidWindowsConfig
	}
	listener, err := winio.ListenPipe(c.socketPath, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GRGW;;;SY)(A;;GRGW;;;" + c.ownerSID + ")",
		InputBufferSize:    16 << 10,
		OutputBufferSize:   16 << 10,
	})
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		select {
		case <-ctx.Done():
		case <-c.handoff:
		}
		_ = listener.Close()
	}()
	go func() { _ = c.scheduler.Run(ctx) }()
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil || activationRequested(c.handoff) || errors.Is(acceptErr, net.ErrClosed) || errors.Is(acceptErr, winio.ErrPipeListenerClosed) {
				return nil
			}
			return acceptErr
		}
		activationPending, _ := c.handle(connection)
		_ = connection.Close()
		if activationPending {
			delay := windowsActivationHandoffDelay
			if delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
				}
			}
			if err := startWindowsActivator(); err != nil {
				continue
			}
			c.handoffOnce.Do(func() { close(c.handoff) })
			return nil
		}
	}
}

func (c *windowsController) handle(connection net.Conn) (bool, error) {
	if connection == nil {
		return false, ErrInvalidControl
	}
	_ = connection.SetDeadline(time.Now().Add(maxUpdateControlTimeout))
	reader := bufio.NewReaderSize(io.LimitReader(connection, (4<<10)+1), (4<<10)+1)
	body, err := reader.ReadBytes('\n')
	if err != nil || len(body) == 0 || len(body) > 4<<10 {
		return false, json.NewEncoder(connection).Encode(ControlResponse{Schema: ControlProtocolV1, Status: "error", ErrorCode: "invalid_request"})
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var request ControlRequest
	var extra any
	if decoder.Decode(&request) != nil || decoder.Decode(&extra) != io.EOF || request.Schema != ControlProtocolV1 || !validControlRequest(request) {
		return false, json.NewEncoder(connection).Encode(ControlResponse{Schema: ControlProtocolV1, Status: "error", ErrorCode: "invalid_request"})
	}
	response, invokeErr := c.invoke(context.Background(), request)
	if invokeErr != nil {
		response.Schema = ControlProtocolV1
		response.Status = "error"
		response.ErrorCode = controlErrorCodeWindows(invokeErr)
		response.ErrorMessage = boundedControlErrorMessage(invokeErr)
	}
	if response.Schema == "" {
		response.Schema = ControlProtocolV1
	}
	if response.Status == "" {
		response.Status = "ok"
	}
	if err := json.NewEncoder(connection).Encode(response); err != nil {
		return false, err
	}
	return response.Pending, nil
}

func (c *windowsController) invoke(ctx context.Context, request ControlRequest) (ControlResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	response := ControlResponse{Schema: ControlProtocolV1, Status: "ok", Version: c.activeVersion, Observation: c.scheduler.Snapshot()}
	blocked, blockErr := c.activationBlocked()
	if blockErr != nil {
		return response, blockErr
	}
	if blocked && request.Operation != "status" {
		return response, ErrWindowsActivationUnavailable
	}
	switch request.Operation {
	case "status":
		if journal, err := loadWindowsActivationJournal(c.config); err == nil {
			if journal.Version == c.activeVersion {
				response.Pending = journal.Stage != windowsActivationCommitted
				response.Updated = journal.Stage == windowsActivationCommitted
			} else if journal.PreviousVersion == c.activeVersion && journal.Stage == windowsActivationRolledBack {
				response.ActivationFailure = "activation_failed"
			}
		}
		return response, nil
	case "check":
		// A manual check is read-only. Calling Scheduler.CheckNow here used the
		// automatic activation callback and could stage, stop services, and roll
		// back a release merely because the user asked what version was current.
		c.checkMu.Lock()
		result, err := resolveRelease(ctx, c.activeVersion, c.resolve)
		c.checkMu.Unlock()
		response.Version, response.Updated, response.Observation = result.Version, false, c.scheduler.Snapshot()
		return response, err
	case "update":
		if c.config.RepositoryURL == "" {
			return response, ErrWindowsActivationUnavailable
		}
		c.checkMu.Lock()
		defer c.checkMu.Unlock()
		source := workerupdate.TUFSource{RepositoryURL: c.config.RepositoryURL, StateRoot: filepath.Join(c.config.StateRoot, "tuf"), MachineID: c.config.MachineID}
		release, found, err := source.ResolveManual(ctx)
		if err != nil || !found {
			return response, err
		}
		comparison, compareErr := selfupdate.CompareVersions(release.Version, c.activeVersion)
		if compareErr != nil || comparison < 0 {
			return response, workerupdate.ErrInvalidRelease
		}
		if comparison == 0 {
			return response, nil
		}
		if _, err := stageWindowsActivation(ctx, c.config, release); err != nil {
			return response, err
		}
		response.Version, response.Pending = release.Version, true
		return response, nil
	case "approve-maintenance":
		if c.config.RepositoryURL == "" {
			return response, ErrWindowsActivationUnavailable
		}
		c.checkMu.Lock()
		defer c.checkMu.Unlock()
		source := workerupdate.TUFSource{RepositoryURL: c.config.RepositoryURL, StateRoot: filepath.Join(c.config.StateRoot, "tuf"), MachineID: c.config.MachineID}
		release, found, err := source.ResolveSupervisorManual(ctx)
		if err != nil || !found {
			return response, err
		}
		if release.Version != request.Release {
			return response, workerupdate.ErrInvalidRelease
		}
		comparison, compareErr := selfupdate.CompareVersions(release.Version, c.activeVersion)
		if compareErr != nil || comparison <= 0 {
			return response, workerupdate.ErrInvalidRelease
		}
		if _, err := stageWindowsActivation(ctx, c.config, release); err != nil {
			return response, err
		}
		response.Version, response.Pending = release.Version, true
		response.Supervisor.StagedVersion, response.Supervisor.MaintenanceRequired, response.Supervisor.Stage = release.Version, true, "activation_pending"
		return response, nil
	default:
		return ControlResponse{}, ErrInvalidControl
	}
}

func activationRequested(channel <-chan struct{}) bool {
	select {
	case <-channel:
		return true
	default:
		return false
	}
}

func (c *windowsController) checkRelease(ctx context.Context) (autoupdate.Result, error) {
	c.checkMu.Lock()
	defer c.checkMu.Unlock()
	blocked, err := c.activationBlocked()
	if err != nil {
		return autoupdate.Result{Version: c.activeVersion}, err
	}
	if blocked {
		return autoupdate.Result{Version: c.activeVersion}, nil
	}
	release, found, err := c.resolve(ctx)
	if err != nil {
		return autoupdate.Result{Version: c.activeVersion}, err
	}
	if !found {
		return autoupdate.Result{Version: c.activeVersion}, nil
	}
	if c.config.AutomaticActivation {
		comparison, compareErr := selfupdate.CompareVersions(release.Version, c.activeVersion)
		if compareErr != nil || comparison < 0 {
			return autoupdate.Result{Version: c.activeVersion}, workerupdate.ErrInvalidRelease
		}
		if comparison == 0 {
			return autoupdate.Result{Version: c.activeVersion}, nil
		}
		if _, err := stageWindowsActivation(ctx, c.config, release); err != nil {
			return autoupdate.Result{Version: c.activeVersion}, err
		}
		if err := startWindowsActivatorService(); err != nil {
			return autoupdate.Result{Version: c.activeVersion}, err
		}
		c.handoffOnce.Do(func() { close(c.handoff) })
		return autoupdate.Result{Version: release.Version, Updated: true}, nil
	}
	return autoupdate.Result{Version: release.Version}, nil
}

func (c *windowsController) activationBlocked() (bool, error) {
	journal, err := loadWindowsActivationJournal(c.config)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	return windowsActivationBlocksVersion(journal, c.activeVersion), nil
}

func controlErrorCodeWindows(err error) string {
	if errors.Is(err, ErrWindowsActivationUnavailable) {
		return "activation_unavailable"
	}
	return "check_failed"
}
