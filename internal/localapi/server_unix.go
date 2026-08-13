//go:build darwin || linux

package localapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maxHeaderBytes = 32 << 10
	maxJSONBytes   = 1 << 20
)

type SnapshotSource interface {
	Snapshot(context.Context) (Snapshot, error)
}

type SnapshotWatcher interface {
	Watch(context.Context, uint64) (Snapshot, error)
}

type CompletionSource interface {
	Completions(context.Context) (CompletionSnapshot, error)
}

type ObservationSink interface {
	PublishObservation(context.Context, Peer, TransportObservation) error
}

type PeerStreamBroker interface {
	OpenPeerStream(context.Context, Peer, PeerStreamRequest) (net.Conn, error)
}

type PeerProbeBroker interface {
	ProbePeer(context.Context, Peer, PeerStreamRequest) (PeerProbeResult, error)
}

type FileTransferBroker interface {
	PrepareFileTransfer(context.Context, Peer, FileTransferKeyRequest) (FileTransferKeyResult, error)
	OpenFileTransferStream(context.Context, Peer, string) (net.Conn, error)
	ReleaseFileTransfer(Peer, string) error
}

type StaleSocketAuthority interface {
	CanRemoveStaleSocket(context.Context, string) bool
}

type ReadAuthorizer func(Peer) bool

type ServerConfig struct {
	SocketPath           string
	OwnerUID             int
	OwnerGID             int
	Source               SnapshotSource
	Completions          CompletionSource
	Observations         ObservationSink
	PeerStreams          PeerStreamBroker
	PeerProbes           PeerProbeBroker
	FileTransfers        FileTransferBroker
	Authorize            ReadAuthorizer
	AuthorizeDiagnostics ReadAuthorizer
	Diagnostics          DiagnosticService
	Stale                StaleSocketAuthority
	Timeout              time.Duration
	WatchDuration        time.Duration
	MaxWatchEvents       int
}

type Server struct{ config ServerConfig }

type peerContextKey struct{}

func NewServer(config ServerConfig) (*Server, error) {
	if !filepath.IsAbs(config.SocketPath) || len(config.SocketPath) > maxUnixSocketPath || config.OwnerUID < 0 || config.OwnerGID < 0 || config.Source == nil {
		return nil, ErrInvalidConfig
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	if config.Timeout <= 0 || config.Timeout > time.Minute {
		return nil, ErrInvalidConfig
	}
	if config.WatchDuration == 0 {
		config.WatchDuration = 10 * time.Minute
	}
	if config.MaxWatchEvents == 0 {
		config.MaxWatchEvents = 1024
	}
	if config.WatchDuration <= 0 || config.WatchDuration > time.Hour || config.MaxWatchEvents < 1 || config.MaxWatchEvents > 65_536 {
		return nil, ErrInvalidConfig
	}
	if config.Authorize == nil {
		config.Authorize = func(peer Peer) bool { return peer.UID == config.OwnerUID }
	}
	if config.AuthorizeDiagnostics == nil {
		config.AuthorizeDiagnostics = func(peer Peer) bool { return peer.UID == config.OwnerUID }
	}
	return &Server{config: config}, nil
}

func (s *Server) Run(ctx context.Context) error {
	listener, err := s.listen(ctx)
	if err != nil {
		return err
	}
	socketInfo, err := os.Lstat(s.config.SocketPath)
	if err != nil {
		_ = listener.Close()
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = removeVerifiedSocket(s.config.SocketPath, socketInfo, s.config.OwnerUID)
	}()
	httpServer := &http.Server{
		Handler:           s.handler(),
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: s.config.Timeout,
		ReadTimeout:       s.config.Timeout,
		WriteTimeout:      0,
		IdleTimeout:       s.config.Timeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ConnContext: func(parent context.Context, connection net.Conn) context.Context {
			peer, err := peerIdentity(connection)
			if err != nil {
				peer = Peer{UID: -1, GID: -1, PID: -1}
			}
			return context.WithValue(parent, peerContextKey{}, peer)
		},
	}
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		// A daemon stop must interrupt in-flight local setup requests immediately;
		// graceful Shutdown can otherwise wait for a peer dial until systemd's
		// stop deadline. Hijacked application streams own their separate bridge
		// lifetime and are closed by their transport lease.
		_ = httpServer.Close()
	}()
	err = httpServer.Serve(listener)
	if ctx.Err() != nil && errors.Is(err, http.ErrServerClosed) {
		<-shutdownDone
		return ctx.Err()
	}
	return err
}

func (s *Server) handler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestID := request.Header.Get("X-Paperboat-Request-ID")
		if !validRequestID(requestID) {
			requestID = localRequestID()
		}
		writer.Header().Set("X-Paperboat-Request-ID", requestID)
		writer.Header().Set("Cache-Control", "no-store")
		peer, ok := request.Context().Value(peerContextKey{}).(Peer)
		if !ok || !s.config.Authorize(peer) {
			writeError(writer, http.StatusForbidden, requestID, "permission_denied", "local API access denied")
			return
		}
		if request.URL.Path == "/v1/diagnostics" || request.URL.Path == "/v1/diagnostics/bugreport-marker" || request.URL.Path == "/v1/bugreports" {
			if !s.config.AuthorizeDiagnostics(peer) {
				writeError(writer, http.StatusForbidden, requestID, "permission_denied", "diagnostic access denied")
				return
			}
			s.serveDiagnostics(writer, request, requestID)
			return
		}
		if request.URL.Path == "/v1/watch" {
			s.watch(writer, request, requestID)
			return
		}
		if request.URL.Path == "/v1/observations/transport" {
			s.observeTransport(writer, request, requestID, peer)
			return
		}
		if request.URL.Path == "/v1/completions" {
			s.completions(writer, request, requestID)
			return
		}
		if request.URL.Path == "/v1/peer-streams" {
			s.peerStream(writer, request, requestID, peer)
			return
		}
		if request.URL.Path == "/v1/peer-probes" {
			s.peerProbe(writer, request, requestID, peer)
			return
		}
		if request.URL.Path == "/v1/file-transfer-keys" {
			s.fileTransferKey(writer, request, requestID, peer)
			return
		}
		if request.URL.Path == "/v1/file-transfer-streams" {
			s.fileTransferStream(writer, request, requestID, peer)
			return
		}
		if request.URL.Path != "/v1/snapshot" || request.URL.RawQuery != "" {
			writeError(writer, http.StatusNotFound, requestID, "not_found", "local API resource not found")
			return
		}
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			writeError(writer, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "local API method not allowed")
			return
		}
		if request.ContentLength != 0 || request.Header.Get("Content-Type") != "" {
			writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "snapshot request must not contain a body")
			return
		}
		requestCtx, cancel := context.WithTimeout(request.Context(), s.config.Timeout)
		defer cancel()
		snapshot, err := s.config.Source.Snapshot(requestCtx)
		if err != nil || snapshot.Validate() != nil {
			writeError(writer, http.StatusServiceUnavailable, requestID, "snapshot_unavailable", "local snapshot is unavailable")
			return
		}
		encoded, err := json.Marshal(snapshot)
		if err != nil || len(encoded) > maxJSONBytes {
			writeError(writer, http.StatusServiceUnavailable, requestID, "snapshot_unavailable", "local snapshot is unavailable")
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Paperboat-Protocol", ProtocolV1)
		_, _ = writer.Write(append(encoded, '\n'))
	})
}

func (s *Server) fileTransferKey(writer http.ResponseWriter, request *http.Request, requestID string, peer Peer) {
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || request.Header.Get("Content-Type") != "application/json" || request.ContentLength < 0 || request.ContentLength > maxJSONBytes || s.config.FileTransfers == nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "file transfer key request is invalid")
		return
	}
	var value FileTransferKeyRequest
	if decodeStrictJSON(io.LimitReader(request.Body, maxJSONBytes+1), &value) != nil || value.Validate(time.Now().UTC()) != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_file_transfer", "file transfer key request is invalid")
		return
	}
	result, err := s.config.FileTransfers.PrepareFileTransfer(request.Context(), peer, value)
	if err != nil || len(result.PeerContext) == 0 {
		if result.Handle != "" {
			_ = s.config.FileTransfers.ReleaseFileTransfer(peer, result.Handle)
		}
		message := "file transfer key delivery is unavailable"
		if err != nil {
			message += ": " + safeErrorMessage(err)
		}
		writeError(writer, http.StatusServiceUnavailable, requestID, "file_transfer_unavailable", message)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		if result.Handle != "" {
			_ = s.config.FileTransfers.ReleaseFileTransfer(peer, result.Handle)
		}
		writeError(writer, http.StatusInternalServerError, requestID, "upgrade_unavailable", "local stream upgrade is unavailable")
		return
	}
	local, buffered, err := hijacker.Hijack()
	if err != nil {
		if result.Handle != "" {
			_ = s.config.FileTransfers.ReleaseFileTransfer(peer, result.Handle)
		}
		return
	}
	if err := local.SetDeadline(time.Time{}); err != nil {
		_ = local.Close()
		if result.Handle != "" {
			_ = s.config.FileTransfers.ReleaseFileTransfer(peer, result.Handle)
		}
		return
	}
	encodedContext := base64.RawURLEncoding.EncodeToString(result.PeerContext)
	headers := "HTTP/1.1 200 OK\r\nX-Paperboat-Protocol: " + ProtocolV1 + "\r\nX-Paperboat-Peer-Context: " + encodedContext + "\r\nConnection: close\r\n"
	if result.Handle != "" {
		headers += "X-Paperboat-Transfer-Handle: " + result.Handle + "\r\n"
	}
	if _, err = buffered.WriteString(headers + "\r\n"); err != nil || buffered.Flush() != nil {
		_ = local.Close()
		if result.Handle != "" {
			_ = s.config.FileTransfers.ReleaseFileTransfer(peer, result.Handle)
		}
		return
	}
	if result.Handle == "" {
		_ = local.Close()
		return
	}
	go func() {
		defer local.Close()
		defer s.config.FileTransfers.ReleaseFileTransfer(peer, result.Handle)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		watchPeerHangup(ctx, local, peer, cancel)
	}()
}

func (s *Server) fileTransferStream(writer http.ResponseWriter, request *http.Request, requestID string, peer Peer) {
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || request.ContentLength != 0 || request.Header.Get("Content-Type") != "" || s.config.FileTransfers == nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "file transfer stream request is invalid")
		return
	}
	handle := request.Header.Get("X-Paperboat-Transfer-Handle")
	if !safeValue(handle) {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_file_transfer", "file transfer stream request is invalid")
		return
	}
	stream, err := s.config.FileTransfers.OpenFileTransferStream(request.Context(), peer, handle)
	if err != nil || stream == nil {
		if stream != nil {
			_ = stream.Close()
		}
		message := "file transfer stream is unavailable"
		if err != nil {
			message += ": " + safeErrorMessage(err)
		}
		writeError(writer, http.StatusServiceUnavailable, requestID, "file_transfer_stream_unavailable", message)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		_ = stream.Close()
		writeError(writer, http.StatusInternalServerError, requestID, "upgrade_unavailable", "local stream upgrade is unavailable")
		return
	}
	local, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = stream.Close()
		return
	}
	if err := local.SetDeadline(time.Time{}); err != nil {
		_ = local.Close()
		_ = stream.Close()
		return
	}
	if _, err = buffered.WriteString("HTTP/1.1 200 OK\r\nX-Paperboat-Protocol: " + ProtocolV1 + "\r\nConnection: close\r\n\r\n"); err != nil || buffered.Flush() != nil {
		_ = local.Close()
		_ = stream.Close()
		return
	}
	streamCtx, cancel := context.WithCancel(context.Background())
	go watchPeerHangup(streamCtx, local, peer, cancel)
	go func() { defer cancel(); bridgePeerStream(streamCtx, local, stream) }()
}

func (s *Server) peerProbe(writer http.ResponseWriter, request *http.Request, requestID string, peer Peer) {
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || request.Header.Get("Content-Type") != "application/json" || request.ContentLength < 0 || request.ContentLength > maxJSONBytes || s.config.PeerProbes == nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "peer probe request is invalid")
		return
	}
	var value PeerStreamRequest
	if err := decodeStrictJSON(io.LimitReader(request.Body, maxJSONBytes+1), &value); err != nil || value.Consumer != "health_probe" || value.Validate(time.Now().UTC()) != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_peer_probe", "peer probe request is invalid")
		return
	}
	ctx, cancel := context.WithDeadline(request.Context(), value.Deadline)
	defer cancel()
	result, err := s.config.PeerProbes.ProbePeer(ctx, peer, value)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, requestID, "peer_probe_unavailable", "peer probe is unavailable: "+safeErrorMessage(err))
		return
	}
	if result.Transport == "" || result.ConnectionNanoseconds < 0 || result.RTTNanoseconds <= 0 {
		writeError(writer, http.StatusServiceUnavailable, requestID, "peer_probe_unavailable", "peer probe is unavailable")
		return
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, requestID, "peer_probe_unavailable", "peer probe is unavailable")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Paperboat-Protocol", ProtocolV1)
	_, _ = writer.Write(append(encoded, '\n'))
}

func (s *Server) peerStream(writer http.ResponseWriter, request *http.Request, requestID string, peer Peer) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeError(writer, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "peer stream method not allowed")
		return
	}
	if request.URL.RawQuery != "" || request.Header.Get("Content-Type") != "application/json" || request.ContentLength < 0 || request.ContentLength > maxJSONBytes || s.config.PeerStreams == nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "peer stream request is invalid")
		return
	}
	var value PeerStreamRequest
	if err := decodeStrictJSON(io.LimitReader(request.Body, maxJSONBytes+1), &value); err != nil || value.ValidatePending(time.Now().UTC()) != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_peer_stream", "peer stream request is invalid")
		return
	}
	setupCtx, cancelSetup := context.WithCancel(request.Context())
	processExit, closeProcessExit := watchProcessExit(peer.PID)
	setupDone := make(chan struct{})
	go func() {
		defer close(setupDone)
		select {
		case <-processExit:
			cancelSetup()
		case <-setupCtx.Done():
		}
	}()
	stream, err := s.config.PeerStreams.OpenPeerStream(setupCtx, peer, value)
	cancelSetup()
	<-setupDone
	closeProcessExit()
	if err != nil || stream == nil {
		if stream != nil {
			_ = stream.Close()
		}
		message := "peer stream is unavailable"
		if err != nil {
			message += ": " + safeErrorMessage(err)
		}
		code := "peer_stream_unavailable"
		var coded interface{ LocalAPICode() string }
		if errors.As(err, &coded) && coded.LocalAPICode() == "exec_start_uncertain" {
			code = coded.LocalAPICode()
		}
		writeError(writer, http.StatusServiceUnavailable, requestID, code, message)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		_ = stream.Close()
		writeError(writer, http.StatusInternalServerError, requestID, "upgrade_unavailable", "local stream upgrade is unavailable")
		return
	}
	local, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = stream.Close()
		return
	}
	if err := local.SetDeadline(time.Time{}); err != nil {
		_ = local.Close()
		_ = stream.Close()
		return
	}
	if _, err = buffered.WriteString("HTTP/1.1 200 OK\r\nX-Paperboat-Protocol: " + ProtocolV1 + "\r\nConnection: close\r\n\r\n"); err != nil || buffered.Flush() != nil {
		_ = local.Close()
		_ = stream.Close()
		return
	}
	// Admission already validated the credential deadline. The hijacked stream
	// is canceled by either endpoint closing, not by credential expiry.
	streamCtx, cancel := context.WithCancel(context.Background())
	go watchPeerHangup(streamCtx, local, peer, cancel)
	go func() { defer cancel(); bridgePeerStream(streamCtx, local, stream) }()
}

func watchPeerHangup(ctx context.Context, connection net.Conn, peer Peer, cancel context.CancelFunc) {
	systemConnection, ok := connection.(syscall.Conn)
	if !ok {
		return
	}
	raw, err := systemConnection.SyscallConn()
	if err != nil {
		return
	}
	fileDescriptor := -1
	if err := raw.Control(func(value uintptr) { fileDescriptor = int(value) }); err != nil || fileDescriptor < 0 {
		return
	}
	processExit, closeProcessExit := watchProcessExit(peer.PID)
	defer closeProcessExit()
	for ctx.Err() == nil {
		select {
		case <-processExit:
			cancel()
			return
		default:
		}
		poll := []unix.PollFd{{Fd: int32(fileDescriptor), Events: unix.POLLHUP | unix.POLLERR}}
		count, pollErr := unix.Poll(poll, 250)
		if errors.Is(pollErr, unix.EINTR) {
			continue
		}
		if pollErr != nil {
			return
		}
		if count > 0 && poll[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			cancel()
			return
		}
	}
}

func safeErrorMessage(err error) string {
	if err == nil {
		return "unknown error"
	}
	message := strings.Join(strings.FieldsFunc(err.Error(), func(value rune) bool {
		return value < 0x20 || value == 0x7f
	}), "; ")
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

func bridgePeerStream(ctx context.Context, local, remote net.Conn) {
	done := make(chan error, 2)
	copyOne := func(destination, source net.Conn) {
		_, err := io.Copy(destination, source)
		if closer, ok := destination.(interface{ CloseWrite() error }); ok {
			err = errors.Join(err, closer.CloseWrite())
		}
		done <- err
	}
	go copyOne(remote, local)
	go copyOne(local, remote)
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				_ = local.Close()
				_ = remote.Close()
			}
		case <-ctx.Done():
			_ = local.Close()
			_ = remote.Close()
		}
	}
	_ = local.Close()
	_ = remote.Close()
}

func (s *Server) completions(writer http.ResponseWriter, request *http.Request, requestID string) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeError(writer, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "completion method not allowed")
		return
	}
	if request.URL.RawQuery != "" || request.ContentLength != 0 || request.Header.Get("Content-Type") != "" || s.config.Completions == nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "completion request is invalid")
		return
	}
	requestCtx, cancel := context.WithTimeout(request.Context(), s.config.Timeout)
	defer cancel()
	snapshot, err := s.config.Completions.Completions(requestCtx)
	if err != nil || snapshot.Validate() != nil {
		writeError(writer, http.StatusServiceUnavailable, requestID, "completion_unavailable", "completion inventory is unavailable")
		return
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || len(encoded) > maxJSONBytes {
		writeError(writer, http.StatusServiceUnavailable, requestID, "completion_unavailable", "completion inventory is unavailable")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Paperboat-Protocol", ProtocolV1)
	_, _ = writer.Write(append(encoded, '\n'))
}

func (s *Server) observeTransport(writer http.ResponseWriter, request *http.Request, requestID string, peer Peer) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeError(writer, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "transport observation method not allowed")
		return
	}
	if request.URL.RawQuery != "" || request.Header.Get("Content-Type") != "application/json" || request.ContentLength < 0 || request.ContentLength > maxJSONBytes || s.config.Observations == nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "transport observation request is invalid")
		return
	}
	requestCtx, cancel := context.WithTimeout(request.Context(), s.config.Timeout)
	defer cancel()
	var observation TransportObservation
	if err := decodeStrictJSON(io.LimitReader(request.Body, maxJSONBytes+1), &observation); err != nil || observation.Validate() != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_observation", "transport observation is invalid")
		return
	}
	if err := s.config.Observations.PublishObservation(requestCtx, peer, observation); err != nil {
		if errors.Is(err, ErrStaleObservation) {
			writeError(writer, http.StatusConflict, requestID, "stale_observation", "transport observation is stale")
			return
		}
		if errors.Is(err, ErrObservationLimit) {
			writeError(writer, http.StatusTooManyRequests, requestID, "observation_limit", "transport observation capacity is exhausted")
			return
		}
		writeError(writer, http.StatusServiceUnavailable, requestID, "observation_unavailable", "transport observation could not be committed")
		return
	}
	writer.Header().Set("X-Paperboat-Protocol", ProtocolV1)
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) watch(writer http.ResponseWriter, request *http.Request, requestID string) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeError(writer, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "local API method not allowed")
		return
	}
	if request.ContentLength != 0 || request.Header.Get("Content-Type") != "" || request.Header.Get("Accept") != "application/x-ndjson" {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "watch request is invalid")
		return
	}
	values := request.URL.Query()
	afterValues, ok := values["after"]
	if !ok || len(afterValues) != 1 || len(values) != 1 {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "watch cursor is required")
		return
	}
	after, err := strconv.ParseUint(afterValues[0], 10, 64)
	if err != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "watch cursor is invalid")
		return
	}
	watcher, ok := s.config.Source.(SnapshotWatcher)
	if !ok {
		writeError(writer, http.StatusNotImplemented, requestID, "capability_required", "snapshot watch is unavailable")
		return
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		writeError(writer, http.StatusInternalServerError, requestID, "stream_unavailable", "snapshot watch stream is unavailable")
		return
	}
	watchCtx, cancel := context.WithTimeout(request.Context(), s.config.WatchDuration)
	defer cancel()
	writer.Header().Set("Content-Type", "application/x-ndjson")
	writer.Header().Set("X-Paperboat-Protocol", ProtocolV1)
	writer.WriteHeader(http.StatusOK)
	flusher.Flush()
	for count := 0; count < s.config.MaxWatchEvents; count++ {
		snapshot, err := watcher.Watch(watchCtx, after)
		if err != nil {
			return
		}
		if snapshot.Validate() != nil || snapshot.Generation <= after {
			return
		}
		event := StatusEvent{Schema: StatusEventSchemaV1, Snapshot: snapshot}
		encoded, err := json.Marshal(event)
		if err != nil || len(encoded) > maxJSONBytes {
			return
		}
		if _, err := writer.Write(append(encoded, '\n')); err != nil {
			return
		}
		flusher.Flush()
		after = snapshot.Generation
	}
}

func (s *Server) listen(ctx context.Context) (*net.UnixListener, error) {
	directory := filepath.Dir(s.config.SocketPath)
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || fileOwner(info) != s.config.OwnerUID {
		return nil, ErrUnsafeSocket
	}
	if info, err := os.Lstat(s.config.SocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || fileOwner(info) != s.config.OwnerUID {
			return nil, ErrUnsafeSocket
		}
		connection, dialErr := net.DialTimeout("unix", s.config.SocketPath, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, ErrAlreadyRunning
		}
		if s.config.Stale == nil || !s.config.Stale.CanRemoveStaleSocket(ctx, s.config.SocketPath) {
			return nil, ErrUnsafeSocket
		}
		if err := removeVerifiedSocket(s.config.SocketPath, info, s.config.OwnerUID); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.config.SocketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	if os.Geteuid() == 0 {
		err = os.Chown(s.config.SocketPath, s.config.OwnerUID, s.config.OwnerGID)
	}
	if err == nil {
		err = os.Chmod(s.config.SocketPath, 0o600)
	}
	if err != nil {
		_ = listener.Close()
		_ = os.Remove(s.config.SocketPath)
		return nil, err
	}
	return listener, nil
}

func removeVerifiedSocket(path string, expected os.FileInfo, ownerUID int) error {
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.Mode()&os.ModeSocket == 0 || current.Mode()&os.ModeSymlink != 0 || fileOwner(current) != ownerUID || !os.SameFile(expected, current) {
		return ErrUnsafeSocket
	}
	return os.Remove(path)
}

func writeError(writer http.ResponseWriter, status int, requestID, code, message string) {
	if len(message) > 512 {
		message = message[:512]
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Paperboat-Protocol", ProtocolV1)
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(struct {
		Schema    string `json:"schema"`
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}{ProtocolV1, code, message, requestID})
}

func localRequestID() string {
	var value [12]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err == nil {
		return "req_" + hex.EncodeToString(value[:])
	}
	return "req_" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

func fileOwner(info os.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}

func validRequestID(value string) bool {
	return strings.HasPrefix(value, "req_") && safeValue(value)
}
