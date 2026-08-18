//go:build darwin || linux

package localapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/diagnostics"
)

type FileTransferLease struct {
	PeerContext []byte
	Handle      string
	control     net.Conn
	client      *Client
	transport   *http.Transport
	once        sync.Once
	err         error
}

func (l *FileTransferLease) RoundTrip(request *http.Request) (*http.Response, error) {
	if l == nil || l.transport == nil {
		return nil, net.ErrClosed
	}
	return l.transport.RoundTrip(request)
}

func (l *FileTransferLease) CloseIdleConnections() {
	if l != nil && l.transport != nil {
		l.transport.CloseIdleConnections()
	}
}

func (l *FileTransferLease) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.transport != nil {
			l.transport.CloseIdleConnections()
		}
		if l.control != nil {
			l.err = l.control.Close()
		}
	})
	return l.err
}

type Client struct {
	http    *http.Client
	timeout time.Duration
	socket  string
}

func (c *Client) Watch(ctx context.Context, after uint64) (<-chan Snapshot, <-chan error) {
	updates := make(chan Snapshot, 1)
	errorsOut := make(chan error, 1)
	go func() {
		defer close(updates)
		defer close(errorsOut)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://paperboat.local/v1/watch?after="+strconv.FormatUint(after, 10), nil)
		if err != nil {
			errorsOut <- err
			return
		}
		request.Header.Set("Accept", "application/x-ndjson")
		request.Header.Set("X-Paperboat-Request-ID", localRequestID())
		response, err := c.http.Do(request)
		if err != nil {
			errorsOut <- err
			return
		}
		defer response.Body.Close()
		if response.Header.Get("X-Paperboat-Protocol") != ProtocolV1 {
			errorsOut <- ErrVersionMismatch
			return
		}
		if response.StatusCode != http.StatusOK {
			errorsOut <- decodeRemoteError(response)
			return
		}
		if response.Header.Get("Content-Type") != "application/x-ndjson" {
			errorsOut <- ErrInvalidResponse
			return
		}
		scanner := bufio.NewScanner(response.Body)
		scanner.Buffer(make([]byte, 64<<10), maxJSONBytes+1)
		cursor := after
		for scanner.Scan() {
			var event StatusEvent
			if err := decodeStrictJSON(bytes.NewReader(scanner.Bytes()), &event); err != nil || event.Schema != StatusEventSchemaV1 || event.Snapshot.Validate() != nil || event.Snapshot.Generation <= cursor {
				errorsOut <- ErrInvalidResponse
				return
			}
			cursor = event.Snapshot.Generation
			select {
			case updates <- cloneSnapshot(event.Snapshot):
			case <-ctx.Done():
				errorsOut <- ctx.Err()
				return
			}
		}
		if err := scanner.Err(); err != nil {
			errorsOut <- err
			return
		}
		errorsOut <- io.EOF
	}()
	return updates, errorsOut
}

func NewClient(socketPath string, timeout time.Duration) (*Client, error) {
	if !filepath.IsAbs(socketPath) || len(socketPath) > maxUnixSocketPath || timeout <= 0 || timeout > time.Minute {
		return nil, ErrInvalidConfig
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", socketPath)
	}, DisableCompression: true, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: timeout}
	return &Client{http: &http.Client{Transport: transport}, timeout: timeout, socket: socketPath}, nil
}

// OpenPeerStream upgrades one authenticated local Unix HTTP request into a
// full-duplex byte stream owned by the daemon's peer transport manager.
func (c *Client) OpenPeerStream(ctx context.Context, value PeerStreamRequest) (net.Conn, error) {
	if c == nil || ctx == nil || value.ValidatePending(time.Now().UTC()) != nil {
		return nil, ErrInvalidConfig
	}
	body, err := json.Marshal(value)
	if err != nil || len(body) > maxJSONBytes {
		return nil, ErrInvalidConfig
	}
	connection, err := (&net.Dialer{Timeout: c.timeout}).DialContext(ctx, "unix", c.socket)
	if err != nil {
		return nil, err
	}
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-watchDone:
		}
	}()
	defer close(watchDone)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://paperboat.local/v1/peer-streams", bytes.NewReader(body))
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Paperboat-Request-ID", localRequestID())
	request.Header.Set("Connection", "close")
	if err := request.Write(connection); err != nil {
		_ = connection.Close()
		return nil, err
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Paperboat-Protocol") != ProtocolV1 {
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, decodeRemoteError(response)
		}
		return nil, ErrVersionMismatch
	}
	return &peerStreamConn{Conn: connection, reader: response.Body}, nil
}

func (c *Client) PrepareFileTransfer(ctx context.Context, value FileTransferKeyRequest) (*FileTransferLease, error) {
	if c == nil || ctx == nil || value.Validate(time.Now().UTC()) != nil {
		return nil, ErrInvalidConfig
	}
	body, err := json.Marshal(value)
	if err != nil || len(body) > maxJSONBytes {
		return nil, ErrInvalidConfig
	}
	connection, err := (&net.Dialer{Timeout: c.timeout}).DialContext(ctx, "unix", c.socket)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://paperboat.local/v1/file-transfer-keys", bytes.NewReader(body))
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Paperboat-Request-ID", localRequestID())
	request.Header.Set("Connection", "close")
	if err := request.Write(connection); err != nil {
		_ = connection.Close()
		return nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Paperboat-Protocol") != ProtocolV1 {
		defer response.Body.Close()
		_ = connection.Close()
		if response.StatusCode != http.StatusOK {
			return nil, decodeRemoteError(response)
		}
		return nil, ErrVersionMismatch
	}
	peerContext, err := base64.RawURLEncoding.Strict().DecodeString(response.Header.Get("X-Paperboat-Peer-Context"))
	if err != nil || len(peerContext) == 0 {
		_ = response.Body.Close()
		_ = connection.Close()
		return nil, ErrInvalidResponse
	}
	handle := response.Header.Get("X-Paperboat-Transfer-Handle")
	lease := &FileTransferLease{PeerContext: peerContext, Handle: handle, control: connection, client: c}
	if handle == "" {
		_ = response.Body.Close()
		_ = connection.Close()
		lease.control = nil
		return lease, nil
	}
	lease.transport = &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     false,
		MaxConnsPerHost:       2,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		DialTLSContext: func(streamCtx context.Context, _, _ string) (net.Conn, error) {
			return c.OpenFileTransferStream(streamCtx, handle)
		},
	}
	return lease, nil
}

func (c *Client) OpenFileTransferStream(ctx context.Context, handle string) (net.Conn, error) {
	if c == nil || ctx == nil || !safeValue(handle) {
		return nil, ErrInvalidConfig
	}
	connection, err := (&net.Dialer{Timeout: c.timeout}).DialContext(ctx, "unix", c.socket)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://paperboat.local/v1/file-transfer-streams", nil)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	request.Header.Set("X-Paperboat-Request-ID", localRequestID())
	request.Header.Set("X-Paperboat-Transfer-Handle", handle)
	request.Header.Set("Connection", "close")
	if err := request.Write(connection); err != nil {
		_ = connection.Close()
		return nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Paperboat-Protocol") != ProtocolV1 {
		defer response.Body.Close()
		_ = connection.Close()
		if response.StatusCode != http.StatusOK {
			return nil, decodeRemoteError(response)
		}
		return nil, ErrVersionMismatch
	}
	return &peerStreamConn{Conn: connection, reader: response.Body}, nil
}

type peerStreamConn struct {
	net.Conn
	reader io.ReadCloser
}

func (c *peerStreamConn) Read(value []byte) (int, error) { return c.reader.Read(value) }
func (c *peerStreamConn) Close() error                   { return errors.Join(c.Conn.Close(), c.reader.Close()) }
func (c *peerStreamConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return net.ErrClosed
}

func (c *Client) Snapshot(ctx context.Context) (Snapshot, error) {
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://paperboat.local/v1/snapshot", nil)
	if err != nil {
		return Snapshot{}, err
	}
	request.Header.Set("X-Paperboat-Request-ID", localRequestID())
	response, err := c.http.Do(request)
	if err != nil {
		return Snapshot{}, err
	}
	defer response.Body.Close()
	if response.Header.Get("X-Paperboat-Protocol") != ProtocolV1 {
		return Snapshot{}, ErrVersionMismatch
	}
	limited := io.LimitReader(response.Body, maxJSONBytes+1)
	if response.StatusCode != http.StatusOK {
		return Snapshot{}, decodeRemoteErrorReader(response.StatusCode, limited)
	}
	if response.Header.Get("Content-Type") != "application/json" {
		return Snapshot{}, ErrInvalidResponse
	}
	var snapshot Snapshot
	if err := decodeStrictJSON(limited, &snapshot); err != nil || snapshot.Validate() != nil {
		return Snapshot{}, ErrInvalidResponse
	}
	return snapshot, nil
}

func (c *Client) Completions(ctx context.Context) (CompletionSnapshot, error) {
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://paperboat.local/v1/completions", nil)
	if err != nil {
		return CompletionSnapshot{}, err
	}
	request.Header.Set("X-Paperboat-Request-ID", localRequestID())
	response, err := c.http.Do(request)
	if err != nil {
		return CompletionSnapshot{}, err
	}
	defer response.Body.Close()
	if response.Header.Get("X-Paperboat-Protocol") != ProtocolV1 {
		return CompletionSnapshot{}, ErrVersionMismatch
	}
	limited := io.LimitReader(response.Body, maxJSONBytes+1)
	if response.StatusCode != http.StatusOK {
		return CompletionSnapshot{}, decodeRemoteErrorReader(response.StatusCode, limited)
	}
	if response.Header.Get("Content-Type") != "application/json" {
		return CompletionSnapshot{}, ErrInvalidResponse
	}
	var snapshot CompletionSnapshot
	if err := decodeStrictJSON(limited, &snapshot); err != nil || snapshot.Validate() != nil {
		return CompletionSnapshot{}, ErrInvalidResponse
	}
	return snapshot, nil
}

func (c *Client) Diagnostics(ctx context.Context) (DiagnosticSnapshot, error) {
	var snapshot DiagnosticSnapshot
	if err := c.getJSON(ctx, "/v1/diagnostics", &snapshot); err != nil {
		return DiagnosticSnapshot{}, err
	}
	if snapshot.Validate() != nil {
		return DiagnosticSnapshot{}, ErrInvalidResponse
	}
	return snapshot, nil
}

func (c *Client) RecordBugreportMarker(ctx context.Context, phase string) error {
	marker := BugreportMarker{Schema: BugreportMarkerSchemaV1, Phase: phase}
	if marker.Validate() != nil {
		return ErrInvalidConfig
	}
	body, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, "http://paperboat.local/v1/diagnostics/bugreport-marker", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Paperboat-Request-ID", localRequestID())
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.Header.Get("X-Paperboat-Protocol") != ProtocolV1 {
		return ErrVersionMismatch
	}
	if response.StatusCode != http.StatusNoContent {
		return decodeRemoteError(response)
	}
	return nil
}

func (c *Client) CreateBugreport(ctx context.Context) (diagnostics.Bundle, error) {
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, "http://paperboat.local/v1/bugreports", nil)
	if err != nil {
		return diagnostics.Bundle{}, err
	}
	request.Header.Set("X-Paperboat-Request-ID", localRequestID())
	response, err := c.http.Do(request)
	if err != nil {
		return diagnostics.Bundle{}, err
	}
	defer response.Body.Close()
	if response.Header.Get("X-Paperboat-Protocol") != ProtocolV1 {
		return diagnostics.Bundle{}, ErrVersionMismatch
	}
	limited := io.LimitReader(response.Body, maxJSONBytes+1)
	if response.StatusCode != http.StatusOK {
		return diagnostics.Bundle{}, decodeRemoteErrorReader(response.StatusCode, limited)
	}
	if response.Header.Get("Content-Type") != "application/json" {
		return diagnostics.Bundle{}, ErrInvalidResponse
	}
	var bundle diagnostics.Bundle
	if err := decodeStrictJSON(limited, &bundle); err != nil || bundle.Validate() != nil {
		return diagnostics.Bundle{}, ErrInvalidResponse
	}
	return bundle, nil
}

func (c *Client) ProbePeer(ctx context.Context, value PeerStreamRequest) (PeerProbeResult, error) {
	var result PeerProbeResult
	if c == nil || ctx == nil || value.Consumer != "health_probe" || value.Validate(time.Now().UTC()) != nil {
		return result, ErrInvalidConfig
	}
	body, err := json.Marshal(value)
	if err != nil || len(body) > maxJSONBytes {
		return result, ErrInvalidConfig
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, "http://paperboat.local/v1/peer-probes", bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Paperboat-Request-ID", localRequestID())
	response, err := c.http.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	if response.Header.Get("X-Paperboat-Protocol") != ProtocolV1 {
		return result, ErrVersionMismatch
	}
	if response.StatusCode != http.StatusOK {
		return result, decodeRemoteError(response)
	}
	if response.Header.Get("Content-Type") != "application/json" || decodeStrictJSON(io.LimitReader(response.Body, maxJSONBytes+1), &result) != nil || result.Transport == "" || result.ConnectionNanoseconds < 0 || result.RTTNanoseconds <= 0 {
		return PeerProbeResult{}, ErrInvalidResponse
	}
	return result, nil
}

func (c *Client) getJSON(ctx context.Context, path string, destination any) error {
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://paperboat.local"+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("X-Paperboat-Request-ID", localRequestID())
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.Header.Get("X-Paperboat-Protocol") != ProtocolV1 {
		return ErrVersionMismatch
	}
	limited := io.LimitReader(response.Body, maxJSONBytes+1)
	if response.StatusCode != http.StatusOK {
		return decodeRemoteErrorReader(response.StatusCode, limited)
	}
	if response.Header.Get("Content-Type") != "application/json" || decodeStrictJSON(limited, destination) != nil {
		return ErrInvalidResponse
	}
	return nil
}

func (c *Client) PublishTransportObservation(ctx context.Context, observation TransportObservation) error {
	if observation.Validate() != nil {
		return ErrInvalidConfig
	}
	body, err := json.Marshal(observation)
	if err != nil || len(body) > maxJSONBytes {
		return ErrInvalidConfig
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, "http://paperboat.local/v1/observations/transport", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Paperboat-Request-ID", localRequestID())
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.Header.Get("X-Paperboat-Protocol") != ProtocolV1 {
		return ErrVersionMismatch
	}
	if response.StatusCode != http.StatusNoContent {
		return decodeRemoteError(response)
	}
	if response.ContentLength > 0 {
		return ErrInvalidResponse
	}
	return nil
}

func decodeRemoteError(response *http.Response) error {
	return decodeRemoteErrorReader(response.StatusCode, io.LimitReader(response.Body, maxJSONBytes+1))
}

// RemoteError preserves the server diagnostic while retaining a stable code.
type RemoteError struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
	cause      error
}

func (e *RemoteError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message == "" || e.Message == e.Code {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

func (e *RemoteError) Unwrap() error { return e.cause }

func decodeRemoteErrorReader(status int, reader io.Reader) error {
	var remote struct {
		Schema    string `json:"schema"`
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}
	if decodeStrictJSON(reader, &remote) != nil || remote.Schema != ProtocolV1 || !safeValue(remote.Code) || !safeText(remote.Message) || !validRequestID(remote.RequestID) {
		return ErrInvalidResponse
	}
	var cause error
	if status == http.StatusForbidden {
		cause = ErrPermission
	}
	if remote.Code == "stale_observation" {
		cause = ErrStaleObservation
	}
	if remote.Code == "observation_limit" {
		cause = ErrObservationLimit
	}
	if remote.Code == "exec_start_uncertain" {
		cause = ErrExecStartUncertain
	}
	return &RemoteError{StatusCode: status, Code: remote.Code, Message: remote.Message, RequestID: remote.RequestID, cause: cause}
}

func decodeStrictJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrInvalidResponse
	}
	return nil
}
