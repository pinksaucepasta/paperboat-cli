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
	"syscall"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/autoupdate"
	"github.com/pinksaucepasta/paperboat/internal/ospeer"
)

const ControlProtocolV1 = "paperboat.updated/v1"

var (
	ErrInvalidControl = errors.New("invalid paperboat-updated control request")
	ErrControlDenied  = errors.New("paperboat-updated control peer is not the enrolled user")
)

// ControlRequest intentionally has no artifact, path, command, environment,
// or release selector. The updater alone resolves a fixed signed index.
type ControlRequest struct {
	Schema    string `json:"schema"`
	Operation string `json:"operation"`
}

type ControlResponse struct {
	Schema      string                 `json:"schema"`
	Status      string                 `json:"status"`
	Version     string                 `json:"version,omitempty"`
	Updated     bool                   `json:"updated"`
	Observation autoupdate.Observation `json:"observation"`
	ErrorCode   string                 `json:"error_code,omitempty"`
}

type controlServer struct {
	socketPath string
	uid        int
	gid        int
	invoke     func(context.Context, string) (ControlResponse, error)
}

func (s *controlServer) listen() (*net.UnixListener, error) {
	if !filepath.IsAbs(s.socketPath) || s.uid <= 0 || s.gid < 0 || s.invoke == nil {
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
	_ = connection.SetDeadline(time.Now().Add(3 * time.Minute))
	decoder := json.NewDecoder(io.LimitReader(connection, 4<<10))
	decoder.DisallowUnknownFields()
	var request ControlRequest
	if err := decoder.Decode(&request); err != nil {
		return s.respond(connection, ControlResponse{Schema: ControlProtocolV1, Status: "error", ErrorCode: "invalid_request"})
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || request.Schema != ControlProtocolV1 || (request.Operation != "status" && request.Operation != "check" && request.Operation != "update") {
		return s.respond(connection, ControlResponse{Schema: ControlProtocolV1, Status: "error", ErrorCode: "invalid_request"})
	}
	response, invokeErr := s.invoke(context.Background(), request.Operation)
	if invokeErr != nil {
		response = ControlResponse{Schema: ControlProtocolV1, Status: "error", ErrorCode: "update_failed"}
	}
	return s.respond(connection, response)
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
	response := ControlResponse{Schema: ControlProtocolV1, Status: "ok", Observation: s.Snapshot()}
	switch operation {
	case "status":
		response.Version = s.manager.ActiveVersion()
		return response, nil
	case "check":
		result, err := s.Check(ctx)
		response.Version, response.Updated = result.Version, result.Updated
		return response, err
	case "update":
		result, err := s.UpdateNow(ctx)
		response.Version, response.Updated = result.Version, result.Updated
		response.Observation = s.Snapshot()
		return response, err
	default:
		return ControlResponse{}, ErrInvalidControl
	}
}
