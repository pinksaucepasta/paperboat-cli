//go:build darwin || linux

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
	"sync"
	"time"
)

var (
	ErrSocketConfig = errors.New("invalid hostd worker socket configuration")
	ErrUnauthorized = errors.New("hostd worker socket peer is unauthorized")
)

const (
	installationTokenBytes = 32
	defaultRequestTimeout  = 5 * time.Second
	defaultMaxConcurrent   = 8
	maxConcurrent          = 64
)

// SocketConfig defines a local lifecycle socket. The socket is intentionally
// per-user: peer credentials and the installation capability must both match
// before a request frame is parsed.
type SocketConfig struct {
	SocketPath string
	StatePath  string
	UID        int
	GID        int
	Token      []byte
	APIMin     uint16
	APIMax     uint16
	Random     io.Reader

	RequestTimeout time.Duration
	MaxConcurrent  int

	// peerUID is test-only injection for platform credential checks. Production
	// callers always use the OS-specific implementation.
	peerUID func(*net.UnixConn) (int, error)
}

// Server accepts one authenticated lifecycle request per Unix connection.
// It does not log peers, tokens, frames, or worker identities.
type Server struct {
	config     SocketConfig
	controller *Controller
}

func NewServer(config SocketConfig) (*Server, error) {
	if !filepath.IsAbs(config.SocketPath) || !filepath.IsAbs(config.StatePath) || config.UID < 0 || config.GID < 0 ||
		os.Geteuid() != config.UID || len(config.Token) != installationTokenBytes || !validRange(config.APIMin, config.APIMax) {
		return nil, ErrSocketConfig
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = defaultRequestTimeout
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = defaultMaxConcurrent
	}
	if config.RequestTimeout < 100*time.Millisecond || config.RequestTimeout > time.Minute || config.MaxConcurrent < 1 || config.MaxConcurrent > maxConcurrent {
		return nil, ErrSocketConfig
	}
	if config.peerUID == nil {
		config.peerUID = peerUID
	}
	if err := secureStatePath(config.StatePath, config.UID); err != nil {
		return nil, err
	}
	state, err := LoadFenceState(config.StatePath)
	if err != nil {
		return nil, err
	}
	controller, err := NewController(ControllerConfig{
		APIMin: config.APIMin, APIMax: config.APIMax, Random: config.Random,
		InitialEpoch: state.Epoch, PersistActivation: NewFenceStatePersister(config.StatePath, config.UID, config.GID),
	})
	if err != nil {
		return nil, err
	}
	return &Server{config: config, controller: controller}, nil
}

func (s *Server) Status() Status { return s.controller.Status() }

// Run owns the socket path for its lifetime. Cancellation closes the listener;
// in-flight requests remain bounded by RequestTimeout.
func (s *Server) Run(ctx context.Context) error {
	listener, err := s.listen()
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(s.config.SocketPath)
	}()
	return s.serve(ctx, listener)
}

func (s *Server) serve(ctx context.Context, listener *net.UnixListener) error {
	semaphore := make(chan struct{}, s.config.MaxConcurrent)
	var workers sync.WaitGroup
	defer workers.Wait()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
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

func (s *Server) serveOne(connection *net.UnixConn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(s.config.RequestTimeout))
	uid, err := s.config.peerUID(connection)
	// The enrolled worker UID may use the lifecycle API. The local root updater
	// may also connect, but it still needs the per-installation capability and
	// cannot create a valid lease for an existing worker. Root access is needed
	// only to query a persisted cutover after power loss.
	if err != nil || uid != s.config.UID && uid != 0 {
		return
	}
	token := make([]byte, installationTokenBytes)
	if _, err := io.ReadFull(connection, token); err != nil || subtle.ConstantTimeCompare(token, s.config.Token) != 1 {
		return
	}
	request, err := ReadFrame(connection)
	if err != nil {
		s.writeError(connection, err)
		return
	}
	response, err := s.controller.Handle(request)
	if err != nil {
		s.writeError(connection, err)
		return
	}
	_ = WriteFrame(connection, response)
}

func (s *Server) writeError(connection *net.UnixConn, err error) {
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

func (s *Server) listen() (*net.UnixListener, error) {
	directory := filepath.Dir(s.config.SocketPath)
	if err := secureSocketDirectory(directory, s.config.UID); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(s.config.SocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrSocketConfig
		}
		if err := os.Remove(s.config.SocketPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.config.SocketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chown(s.config.SocketPath, s.config.UID, s.config.GID); err != nil {
		listener.Close()
		return nil, err
	}
	if err := os.Chmod(s.config.SocketPath, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

func secureSocketDirectory(path string, ownerUID int) error {
	if !filepath.IsAbs(path) {
		return ErrSocketConfig
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || fileOwnerUID(info) != ownerUID {
		return ErrSocketConfig
	}
	return nil
}

func secureStatePath(path string, ownerUID int) error {
	if !filepath.IsAbs(path) {
		return ErrSocketConfig
	}
	if err := secureSocketDirectory(filepath.Dir(path), ownerUID); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || fileOwnerUID(info) != ownerUID {
		return ErrSocketConfig
	}
	return nil
}

// Client is the intentionally small worker-side lifecycle client. It carries
// the installation token only in memory and opens a fresh one-request socket
// for every call, preventing a compromised worker from retaining authority
// after a hostd restart.
type Client struct {
	socketPath string
	token      []byte
	timeout    time.Duration
}

func NewClient(socketPath string, token []byte, timeout time.Duration) (*Client, error) {
	if !filepath.IsAbs(socketPath) || len(token) != installationTokenBytes {
		return nil, ErrSocketConfig
	}
	if timeout == 0 {
		timeout = defaultRequestTimeout
	}
	if timeout < 100*time.Millisecond || timeout > time.Minute {
		return nil, ErrSocketConfig
	}
	return &Client{socketPath: socketPath, token: append([]byte(nil), token...), timeout: timeout}, nil
}

func (c *Client) Request(ctx context.Context, request Message) (Message, error) {
	if request == nil || request.validate() != nil {
		return nil, ErrInvalidFrame
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", c.socketPath)
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

// Active reads hostd's persisted worker fence through the authenticated local
// socket. It is deliberately read-only, so a root updater can resolve an
// interrupted cutover without receiving any workload-control capability.
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
	return fmt.Sprintf("hostd lifecycle socket %s", s.config.SocketPath)
}
