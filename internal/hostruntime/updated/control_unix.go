//go:build darwin || linux

package updated

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/autoupdate"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/supervisorupdate"
	"github.com/pinksaucepasta/paperboat/internal/ospeer"
)

const ControlProtocolV1 = "paperboat.updated/v1"

const maxUpdateControlTimeout = 15 * time.Minute

var (
	ErrInvalidControl = errors.New("invalid paperboat-updated control request")
	ErrControlDenied  = errors.New("paperboat-updated control peer is not the enrolled user")
)

// ControlRequest intentionally has no artifact, path, command, environment,
// or arbitrary target selector. The only accepted release value is an exact
// version for the one-use maintenance approval operation; the updater still
// resolves and verifies the signed index itself.
type ControlRequest struct {
	Schema    string `json:"schema"`
	Operation string `json:"operation"`
	Release   string `json:"release,omitempty"`
}

type ControlResponse struct {
	Schema            string                  `json:"schema"`
	Status            string                  `json:"status"`
	Version           string                  `json:"version,omitempty"`
	Updated           bool                    `json:"updated"`
	Pending           bool                    `json:"pending,omitempty"`
	ActivationFailure string                  `json:"activation_failure,omitempty"`
	Observation       autoupdate.Observation  `json:"observation"`
	ErrorCode         string                  `json:"error_code,omitempty"`
	Supervisor        supervisorupdate.Result `json:"supervisor,omitempty"`
}

type controlServer struct {
	socketPath    string
	uid           int
	gid           int
	invoke        func(context.Context, string) (ControlResponse, error) // legacy test seam
	invokeRequest func(context.Context, ControlRequest) (ControlResponse, error)
}

func (s *controlServer) listen() (*net.UnixListener, error) {
	if !filepath.IsAbs(s.socketPath) || !validUnixWorkerIdentity(s.uid, s.gid) || s.invoke == nil && s.invokeRequest == nil {
		return nil, ErrInvalidConfig
	}
	directory := filepath.Dir(s.socketPath)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o755 {
		return nil, ErrInvalidConfig
	}
	if owner, ok := info.Sys().(*syscall.Stat_t); !ok || owner.Uid != 0 {
		return nil, ErrInvalidConfig
	}
	if info, err := os.Lstat(s.socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrInvalidConfig
		}
		if err := os.Remove(s.socketPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.socketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chown(s.socketPath, s.uid, s.gid); err != nil {
		_ = listener.Close()
		return nil, err
	}
	if err := os.Chmod(s.socketPath, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

// serve deliberately treats malformed or unauthorized requests as local
// caller failures. They cannot take down the mandatory scheduler.
func (s *controlServer) serve(ctx context.Context, listener *net.UnixListener) {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		_ = s.handle(connection)
		_ = connection.Close()
	}
}

func (s *controlServer) handle(connection *net.UnixConn) error {
	identity, err := ospeer.Get(connection)
	if err != nil || identity.UID != s.uid {
		return ErrControlDenied
	}
	_ = connection.SetDeadline(time.Now().Add(maxUpdateControlTimeout))
	decoder := json.NewDecoder(io.LimitReader(connection, 4<<10))
	decoder.DisallowUnknownFields()
	var request ControlRequest
	if err := decoder.Decode(&request); err != nil {
		return s.respond(connection, ControlResponse{Schema: ControlProtocolV1, Status: "error", ErrorCode: "invalid_request"})
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || request.Schema != ControlProtocolV1 || !validControlRequest(request) {
		return s.respond(connection, ControlResponse{Schema: ControlProtocolV1, Status: "error", ErrorCode: "invalid_request"})
	}
	var response ControlResponse
	var invokeErr error
	if s.invokeRequest != nil {
		response, invokeErr = s.invokeRequest(context.Background(), request)
	} else {
		response, invokeErr = s.invoke(context.Background(), request.Operation)
	}
	if invokeErr != nil {
		response.Schema = ControlProtocolV1
		response.Status = "error"
		response.ErrorCode = controlErrorCode(invokeErr)
	}
	return s.respond(connection, response)
}

var exactReleasePattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)

func validControlRequest(request ControlRequest) bool {
	switch request.Operation {
	case "status", "check", "update":
		return request.Release == ""
	case "approve-maintenance":
		return exactReleasePattern.MatchString(request.Release)
	default:
		return false
	}
}

func controlErrorCode(err error) string {
	switch {
	case errors.Is(err, supervisorupdate.ErrMaintenanceRequired):
		return "maintenance_required"
	case errors.Is(err, supervisorupdate.ErrApprovalExpired):
		return "approval_expired"
	case errors.Is(err, supervisorupdate.ErrStaleWorkloads):
		return "stale_workloads"
	case errors.Is(err, supervisorupdate.ErrBlocked):
		return "recovery_required"
	case errors.Is(err, supervisorupdate.ErrInvalidRelease):
		return "release_not_found"
	default:
		return "update_failed"
	}
}

func (s *controlServer) respond(writer io.Writer, response ControlResponse) error {
	if response.Schema == "" {
		response.Schema = ControlProtocolV1
	}
	if response.Status == "" {
		response.Status = "ok"
	}
	return json.NewEncoder(writer).Encode(response)
}

func (s *Service) controlRequest(ctx context.Context, operation string) (ControlResponse, error) {
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	return s.controlRequestWithRequest(ctx, ControlRequest{Operation: operation})
}

func (s *Service) controlRequestWithRequest(ctx context.Context, request ControlRequest) (ControlResponse, error) {
	switch request.Operation {
	case "status":
		response := ControlResponse{Schema: ControlProtocolV1, Status: "ok", Observation: s.Snapshot()}
		response.Version = s.manager.ActiveVersion()
		response.Supervisor = s.supervisor.Status()
		return response, nil
	case "check":
		response := ControlResponse{Schema: ControlProtocolV1, Status: "ok", Observation: s.Snapshot()}
		result, err := s.Check(ctx)
		response.Version, response.Updated = result.Version, result.Updated
		response.Supervisor = s.supervisor.Status()
		return response, err
	case "update":
		response := ControlResponse{Schema: ControlProtocolV1, Status: "ok", Observation: s.Snapshot()}
		result, err := s.UpdateNow(ctx)
		response.Version, response.Updated = result.Version, result.Updated
		response.Observation = s.Snapshot()
		response.Supervisor = s.supervisor.Status()
		return response, err
	case "approve-maintenance":
		response := ControlResponse{Schema: ControlProtocolV1, Status: "ok", Observation: s.Snapshot()}
		result, err := s.ApproveMaintenance(ctx, request.Release)
		response.Version, response.Updated, response.Supervisor = result.Version, result.Applied, result
		return response, err
	default:
		return ControlResponse{}, ErrInvalidControl
	}
}
