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
	"path/filepath"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/autoupdate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

var ErrWindowsActivationUnavailable = errors.New("Windows updater activation is unavailable")

type windowsController struct {
	activeVersion string
	ownerSID      string
	socketPath    string
	resolve       workerupdate.Resolver
	scheduler     *autoupdate.Scheduler
	mu            sync.Mutex
	checkMu       sync.Mutex
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
		<-ctx.Done()
		_ = listener.Close()
	}()
	go func() { _ = c.scheduler.Run(ctx) }()
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed) || errors.Is(acceptErr, winio.ErrPipeListenerClosed) {
				return nil
			}
			return acceptErr
		}
		_ = c.handle(connection)
		_ = connection.Close()
	}
}

func (c *windowsController) handle(connection net.Conn) error {
	if connection == nil {
		return ErrInvalidControl
	}
	_ = connection.SetDeadline(time.Now().Add(maxUpdateControlTimeout))
	reader := bufio.NewReaderSize(io.LimitReader(connection, (4<<10)+1), (4<<10)+1)
	body, err := reader.ReadBytes('\n')
	if err != nil || len(body) == 0 || len(body) > 4<<10 {
		return json.NewEncoder(connection).Encode(ControlResponse{Schema: ControlProtocolV1, Status: "error", ErrorCode: "invalid_request"})
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var request ControlRequest
	var extra any
	if decoder.Decode(&request) != nil || decoder.Decode(&extra) != io.EOF || request.Schema != ControlProtocolV1 || !validControlRequest(request) {
		return json.NewEncoder(connection).Encode(ControlResponse{Schema: ControlProtocolV1, Status: "error", ErrorCode: "invalid_request"})
	}
	response, invokeErr := c.invoke(context.Background(), request)
	if invokeErr != nil {
		response.Schema = ControlProtocolV1
		response.Status = "error"
		response.ErrorCode = controlErrorCodeWindows(invokeErr)
	}
	if response.Schema == "" {
		response.Schema = ControlProtocolV1
	}
	if response.Status == "" {
		response.Status = "ok"
	}
	return json.NewEncoder(connection).Encode(response)
}

func (c *windowsController) invoke(ctx context.Context, request ControlRequest) (ControlResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	response := ControlResponse{Schema: ControlProtocolV1, Status: "ok", Version: c.activeVersion, Observation: c.scheduler.Snapshot()}
	switch request.Operation {
	case "status":
		return response, nil
	case "check":
		result, err := c.scheduler.CheckNow(ctx)
		response.Version, response.Updated, response.Observation = result.Version, false, c.scheduler.Snapshot()
		return response, err
	case "update", "approve-maintenance":
		return response, ErrWindowsActivationUnavailable
	default:
		return ControlResponse{}, ErrInvalidControl
	}
}

func (c *windowsController) checkRelease(ctx context.Context) (autoupdate.Result, error) {
	c.checkMu.Lock()
	defer c.checkMu.Unlock()
	release, found, err := c.resolve(ctx)
	if err != nil {
		return autoupdate.Result{Version: c.activeVersion}, err
	}
	if !found {
		return autoupdate.Result{Version: c.activeVersion}, nil
	}
	return autoupdate.Result{Version: release.Version}, nil
}

func controlErrorCodeWindows(err error) string {
	if errors.Is(err, ErrWindowsActivationUnavailable) {
		return "activation_unavailable"
	}
	return "check_failed"
}
