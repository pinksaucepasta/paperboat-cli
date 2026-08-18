//go:build windows

package hostservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"golang.org/x/sys/windows"
)

const (
	ProtocolV1 = "paperboat.host-service/v1"
	AllowSleep = "allow_sleep"
	KeepAwake  = "keep_awake"
)

var (
	ErrInvalidConfig  = errors.New("invalid host-service configuration")
	ErrInvalidRequest = errors.New("invalid host-service request")
	ErrPeerDenied     = errors.New("host-service named-pipe peer is not enrolled")
	ErrStalePolicy    = errors.New("availability policy version is stale")
)

type Request struct {
	Schema    string                    `json:"schema"`
	Operation string                    `json:"operation"`
	Mode      string                    `json:"mode,omitempty"`
	Version   int64                     `json:"version,omitempty"`
	Artifact  *bootstrap.ArtifactTarget `json:"artifact,omitempty"`
}
type Response struct {
	Schema             string    `json:"schema"`
	Status             string    `json:"status"`
	DesiredMode        string    `json:"desired_mode"`
	DesiredVersion     int64     `json:"desired_version"`
	ObservedMode       string    `json:"observed_mode,omitempty"`
	ObservedVersion    int64     `json:"observed_version,omitempty"`
	ObservedAt         time.Time `json:"observed_at,omitempty"`
	ErrorCode          string    `json:"error_code,omitempty"`
	HostServiceVersion string    `json:"host_service_version"`
	Scope              string    `json:"scope"`
	UpdateVersion      string    `json:"update_version,omitempty"`
	UpdateRollbacks    uint64    `json:"update_rollbacks"`
	UpdateHealth       string    `json:"update_health"`
}
type State struct {
	Schema          string    `json:"schema"`
	DesiredMode     string    `json:"desired_mode"`
	DesiredVersion  int64     `json:"desired_version"`
	ObservedMode    string    `json:"observed_mode,omitempty"`
	ObservedVersion int64     `json:"observed_version,omitempty"`
	ObservedAt      time.Time `json:"observed_at,omitempty"`
	Status          string    `json:"status"`
	ErrorCode       string    `json:"error_code,omitempty"`
}
type Applier interface {
	Apply(context.Context, string) error
	Close(context.Context) error
}
type UpdateActivator interface {
	Activate(context.Context, bootstrap.ArtifactTarget) (string, error)
}
type UpdateDiagnostics interface {
	RollbackCount() uint64
	UpdateHealth() string
}
type Config struct {
	SocketPath        string
	StatePath         string
	UID               int
	GID               int
	SID               string
	Applier           Applier
	Now               func() time.Time
	Version           string
	Updates           UpdateActivator
	Ready             func() error
	Heartbeat         func() error
	HeartbeatInterval time.Duration
}
type Server struct {
	config Config
	mu     sync.Mutex
	state  State
}

func New(config Config) (*Server, error) {
	if !validPipePath(config.SocketPath) || !filepath.IsAbs(config.StatePath) || config.Applier == nil || config.Version == "" || config.HeartbeatInterval < 0 || config.HeartbeatInterval > 0 && config.Heartbeat == nil || config.SID != "" && !validSID(config.SID) {
		return nil, ErrInvalidConfig
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	server := &Server{config: config, state: State{Schema: ProtocolV1, DesiredMode: KeepAwake, Status: "pending"}}
	if err := server.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return server, nil
}

func (s *Server) Run(ctx context.Context) error {
	s.mu.Lock()
	mode, version := s.state.DesiredMode, s.state.DesiredVersion
	s.mu.Unlock()
	if mode == KeepAwake {
		if err := s.apply(ctx, mode, version); err != nil {
			return err
		}
	}
	listener, err := winio.ListenPipe(s.config.SocketPath, &winio.PipeConfig{SecurityDescriptor: hostServiceSecurityDescriptor(s.config.SID), InputBufferSize: 16 << 10, OutputBufferSize: 16 << 10})
	if err != nil {
		return err
	}
	defer listener.Close()
	if s.config.Ready != nil {
		if err := s.config.Ready(); err != nil {
			return err
		}
	}
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed) || errors.Is(acceptErr, winio.ErrPipeListenerClosed) {
				return errors.Join(ctx.Err(), s.config.Applier.Close(context.Background()))
			}
			return acceptErr
		}
		_ = s.serve(connection)
		_ = connection.Close()
	}
}

func (s *Server) serve(connection net.Conn) error {
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	decoder := json.NewDecoder(io.LimitReader(connection, 16<<10))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return s.respond(connection, s.errorResponse("invalid_request"))
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || request.Schema != ProtocolV1 {
		return s.respond(connection, s.errorResponse("invalid_request"))
	}
	if request.Operation == "diagnostics" {
		if request.Mode != "" || request.Version != 0 || request.Artifact != nil {
			return s.respond(connection, s.errorResponse("invalid_request"))
		}
		s.mu.Lock()
		current := s.state
		s.mu.Unlock()
		return s.respond(connection, s.response(current))
	}
	if request.Operation == "activate_update" {
		if request.Mode != "" || request.Version != 0 || request.Artifact == nil || s.config.Updates == nil {
			return s.respond(connection, s.errorResponse("invalid_request"))
		}
		version, activateErr := s.config.Updates.Activate(context.Background(), *request.Artifact)
		if activateErr != nil {
			return s.respond(connection, s.errorResponse("update_activation_failed"))
		}
		response := s.errorResponse("")
		response.UpdateVersion = version
		return s.respond(connection, response)
	}
	if request.Operation != "apply_availability" || request.Artifact != nil || !validMode(request.Mode) || request.Version < 0 {
		return s.respond(connection, s.errorResponse("invalid_request"))
	}
	s.mu.Lock()
	current := s.state
	s.mu.Unlock()
	if request.Version < current.DesiredVersion || request.Version == current.DesiredVersion && request.Mode != current.DesiredMode {
		return s.respond(connection, s.errorResponse("stale_policy"))
	}
	if request.Version == current.DesiredVersion && current.Status == "applied" {
		return s.respond(connection, s.response(current))
	}
	if err := s.apply(context.Background(), request.Mode, request.Version); err != nil {
		s.mu.Lock()
		result := s.state
		s.mu.Unlock()
		return s.respond(connection, s.response(result))
	}
	s.mu.Lock()
	result := s.state
	s.mu.Unlock()
	return s.respond(connection, s.response(result))
}

func (s *Server) apply(ctx context.Context, mode string, version int64) error {
	s.mu.Lock()
	s.state.DesiredMode, s.state.DesiredVersion, s.state.Status, s.state.ErrorCode = mode, version, "pending", ""
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	err := s.config.Applier.Apply(ctx, mode)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.state.ObservedMode, s.state.ObservedVersion = mode, version
		s.state.ObservedAt, s.state.Status, s.state.ErrorCode = s.config.Now().UTC(), "error", "availability_apply_failed"
		return errors.Join(err, s.persistLocked())
	}
	s.state.ObservedMode, s.state.ObservedVersion = mode, version
	s.state.ObservedAt, s.state.Status, s.state.ErrorCode = s.config.Now().UTC(), "applied", ""
	return s.persistLocked()
}
func (s *Server) State() State { s.mu.Lock(); defer s.mu.Unlock(); return s.state }
func (s *Server) load() error {
	body, err := os.ReadFile(s.config.StatePath)
	if err != nil {
		return err
	}
	if len(body) > 16<<10 {
		return ErrInvalidConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var state State
	var extra any
	if decoder.Decode(&state) != nil || decoder.Decode(&extra) != io.EOF || state.Schema != ProtocolV1 || !validMode(state.DesiredMode) || state.DesiredVersion < 0 || !validStatus(state.Status) {
		return ErrInvalidConfig
	}
	s.state = state
	return nil
}
func (s *Server) persistLocked() error {
	body, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.config.StatePath), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(s.config.StatePath, body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}
func (s *Server) respond(writer io.Writer, value Response) error {
	return json.NewEncoder(writer).Encode(value)
}
func (s *Server) errorResponse(code string) Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	value := s.response(s.state)
	value.ErrorCode = code
	return value
}
func (s *Server) response(state State) Response {
	var rollbacks uint64
	if diagnostics, ok := s.config.Updates.(UpdateDiagnostics); ok {
		rollbacks = diagnostics.RollbackCount()
	}
	health := "unknown"
	if diagnostics, ok := s.config.Updates.(UpdateDiagnostics); ok {
		health = diagnostics.UpdateHealth()
	}
	return Response{Schema: ProtocolV1, Status: state.Status, DesiredMode: state.DesiredMode, DesiredVersion: state.DesiredVersion, ObservedMode: state.ObservedMode, ObservedVersion: state.ObservedVersion, ObservedAt: state.ObservedAt, ErrorCode: state.ErrorCode, HostServiceVersion: s.config.Version, Scope: "system", UpdateRollbacks: rollbacks, UpdateHealth: health}
}
func validMode(mode string) bool { return mode == AllowSleep || mode == KeepAwake }
func validStatus(status string) bool {
	return status == "applied" || status == "pending" || status == "error"
}
func validPipePath(path string) bool {
	const prefix = `\\.\pipe\`
	return strings.HasPrefix(strings.ToLower(path), prefix) && len(path) > len(prefix) && len(path) <= 256 && !strings.ContainsAny(path[len(prefix):], `/\:*?"<>|`)
}
func validSID(value string) bool {
	sid, err := windows.StringToSid(value)
	return err == nil && sid != nil && sid.String() == value
}
func hostServiceSecurityDescriptor(sid string) string {
	if validSID(sid) {
		return "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + sid + ")"
	}
	return "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
}
