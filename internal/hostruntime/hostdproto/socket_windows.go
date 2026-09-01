//go:build windows

package hostdproto

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"golang.org/x/sys/windows"
)

var (
	ErrSocketConfig = errors.New("invalid hostd worker named-pipe configuration")
	ErrUnauthorized = errors.New("hostd worker named-pipe peer is unauthorized")
)

const (
	installationTokenBytes = 32
	defaultRequestTimeout  = 5 * time.Second
	defaultMaxConcurrent   = 8
	maxConcurrent          = 64
)

// SocketConfig describes the authenticated hostd lifecycle pipe. The
// protected DACL admits only the enrolled SID and SYSTEM; the installation
// capability is still required in-band for every request.
type SocketConfig struct {
	SocketPath string
	StatePath  string
	SID        string
	Token      []byte
	APIMin     uint16
	APIMax     uint16
	Random     io.Reader

	RequestTimeout time.Duration
	MaxConcurrent  int
	Workloads      func() WorkloadStatus
	UpdateGate     UpdateGateHandler
}

type Server struct {
	config     SocketConfig
	controller *Controller
}

func NewServer(config SocketConfig) (*Server, error) {
	if !validPipePath(config.SocketPath) || !filepath.IsAbs(config.StatePath) || len(config.Token) != installationTokenBytes || !validRange(config.APIMin, config.APIMax) || !validSID(config.SID) {
		return nil, ErrSocketConfig
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = defaultRequestTimeout
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = defaultMaxConcurrent
	}
	if config.RequestTimeout < 100*time.Millisecond || config.RequestTimeout > 31*time.Minute || config.MaxConcurrent < 1 || config.MaxConcurrent > maxConcurrent {
		return nil, ErrSocketConfig
	}
	if err := secureStatePathWindows(config.StatePath, config.SID); err != nil {
		return nil, err
	}
	state, err := LoadFenceState(config.StatePath)
	if err != nil {
		return nil, err
	}
	controller, err := NewController(ControllerConfig{
		APIMin: config.APIMin, APIMax: config.APIMax, Random: config.Random,
		InitialEpoch: state.Epoch,
		PersistActivation: func(status Status) error {
			if status.State != StateActive || status.validate() != nil {
				return ErrInvalidFrame
			}
			body := []byte(fmt.Sprintf(`{"schema":%q,"worker_id":%q,"api_version":%d,"epoch":%d}`+"\n", stateSchemaV1, status.WorkerID, status.APIVersion, status.Epoch))
			return atomicfile.Write(config.StatePath, body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1,
				SecurityDescriptor: "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + config.SID + ")"})
		},
	})
	if err != nil {
		return nil, err
	}
	return &Server{config: config, controller: controller}, nil
}

func (s *Server) Status() Status { return s.controller.Status() }

func (s *Server) Run(ctx context.Context) error {
	listener, err := winio.ListenPipe(s.config.SocketPath, &winio.PipeConfig{
		SecurityDescriptor: pipeSecurityDescriptor(s.config.SID),
		MessageMode:        false,
		InputBufferSize:    MaxFrameBytes + installationTokenBytes + 4,
		OutputBufferSize:   MaxFrameBytes + 4,
	})
	if err != nil {
		return err
	}
	defer listener.Close()
	return s.serve(ctx, listener)
}

func (s *Server) serve(ctx context.Context, listener net.Listener) error {
	semaphore := make(chan struct{}, s.config.MaxConcurrent)
	var workers sync.WaitGroup
	defer workers.Wait()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, winio.ErrPipeListenerClosed) {
				return nil
			}
			return err
		}
		select {
		case semaphore <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-semaphore }()
				s.serveOne(connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (s *Server) serveOne(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(s.config.RequestTimeout))
	// The enrolled SID is enforced by the protected named-pipe DACL. SYSTEM
	// is admitted for the privileged updater. The capability token prevents a
	// second process under either identity from using the endpoint.
	token := make([]byte, installationTokenBytes)
	if _, err := io.ReadFull(connection, token); err != nil || subtle.ConstantTimeCompare(token, s.config.Token) != 1 {
		return
	}
	request, err := ReadFrame(connection)
	if err != nil {
		s.writeError(connection, err)
		return
	}
	var response Message
	if gate, ok := request.(*UpdateGateRequest); ok {
		if s.config.UpdateGate == nil {
			s.writeError(connection, ErrNotReady)
			return
		}
		gateCtx, cancel := context.WithTimeout(context.Background(), s.config.RequestTimeout)
		value, gateErr := s.config.UpdateGate.HandleUpdateGate(gateCtx, *gate)
		cancel()
		response, err = value, gateErr
	} else {
		response, err = s.controller.Handle(request)
	}
	if err != nil {
		s.writeError(connection, err)
		return
	}
	if _, ok := request.(*Status); ok && s.config.Workloads != nil {
		if status, ok := response.(*Status); ok {
			workload := s.config.Workloads()
			status.WorkloadGeneration = workload.Generation
			status.ProtectedWorkloads = workload.Protected
		}
	}
	_ = WriteFrame(connection, response)
}

func (s *Server) writeError(connection io.Writer, err error) {
	code := "invalid"
	switch {
	case errors.Is(err, ErrIncompatible):
		code = "incompatible"
	case errors.Is(err, ErrFenced):
		code = "fenced"
	case errors.Is(err, ErrNotReady):
		code = "not_ready"
	}
	_ = WriteFrame(connection, Error{Code: code})
}

type Client struct {
	socketPath string
	token      []byte
	timeout    time.Duration
}

func NewClient(socketPath string, token []byte, timeout time.Duration) (*Client, error) {
	if !validPipePath(socketPath) || len(token) != installationTokenBytes {
		return nil, ErrSocketConfig
	}
	if timeout == 0 {
		timeout = defaultRequestTimeout
	}
	if timeout < 100*time.Millisecond || timeout > 31*time.Minute {
		return nil, ErrSocketConfig
	}
	return &Client{socketPath: socketPath, token: append([]byte(nil), token...), timeout: timeout}, nil
}

func (c *Client) Request(ctx context.Context, request Message) (Message, error) {
	if request == nil || request.validate() != nil {
		return nil, ErrInvalidFrame
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	connection, err := winio.DialPipeContext(dialCtx, c.socketPath)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	deadline := time.Now().Add(c.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := writeAll(connection, c.token); err != nil {
		return nil, err
	}
	if err := WriteFrame(connection, request); err != nil {
		return nil, err
	}
	response, err := ReadFrame(connection)
	if err != nil {
		return nil, err
	}
	if remote, ok := response.(*Error); ok {
		return nil, errorForCode(remote.Code)
	}
	return response, nil
}

func (c *Client) Active(ctx context.Context) (Status, error) {
	response, err := c.Request(ctx, Status{State: StateEmpty})
	if err != nil {
		return Status{}, err
	}
	status, ok := response.(*Status)
	if !ok || status.validate() != nil {
		return Status{}, ErrInvalidFrame
	}
	return *status, nil
}

func (c *Client) UpdateGate(ctx context.Context, request UpdateGateRequest) (UpdateGateResponse, error) {
	response, err := c.Request(ctx, request)
	if err != nil {
		return UpdateGateResponse{}, err
	}
	gate, ok := response.(*UpdateGateResponse)
	if !ok || gate.validate() != nil {
		return UpdateGateResponse{}, ErrInvalidFrame
	}
	return *gate, nil
}

func errorForCode(code string) error {
	switch code {
	case "incompatible":
		return ErrIncompatible
	case "fenced":
		return ErrFenced
	case "not_ready":
		return ErrNotReady
	default:
		return ErrInvalidFrame
	}
}

func (s *Server) String() string {
	return fmt.Sprintf("hostd lifecycle named pipe %s", s.config.SocketPath)
}

func validPipePath(path string) bool {
	const prefix = `\\.\pipe\`
	if !strings.HasPrefix(strings.ToLower(path), prefix) || len(path) <= len(prefix) || len(path) > 256 {
		return false
	}
	return !strings.ContainsAny(path[len(prefix):], `/\:*?"<>|`)
}

func validSID(value string) bool {
	sid, err := windows.StringToSid(value)
	return err == nil && sid != nil && sid.String() == value
}

func pipeSecurityDescriptor(sid string) string {
	return "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + sid + ")"
}

func secureStatePathWindows(path, enrolledSID string) error {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrSocketConfig
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(parent))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || !protectedWindowsPath(parent, enrolledSID) {
		return ErrSocketConfig
	}
	if info, err := os.Lstat(path); err == nil {
		attributes, attributeErr := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || attributeErr != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || !protectedWindowsPath(path, enrolledSID) {
			return ErrSocketConfig
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func protectedWindowsPath(path, enrolledSID string) bool {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || owner.String() != enrolledSID {
		return false
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	text := descriptor.String()
	if strings.Count(text, "(A;") != 3 || strings.Contains(text, "(D;") {
		return false
	}
	allows := func(sid string) bool {
		return strings.Contains(text, ";FA;;;"+sid+")") || strings.Contains(text, ";GA;;;"+sid+")")
	}
	return allows("SY") && allows("BA") && allows(enrolledSID)
}
