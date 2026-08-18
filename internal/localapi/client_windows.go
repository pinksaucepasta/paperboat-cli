//go:build windows

package localapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/diagnostics"
)

// ErrWindowsLocalAPIUnavailable is returned instead of silently pretending
// that the Unix-domain local API works on Windows. The named-pipe transport,
// peer-token verification, and ConPTY broker are intentionally kept behind a
// later Windows runtime implementation. This file exists so the CLI and
// release artifacts can be built for Windows now with an explicit failure if
// a caller reaches the unsupported local API path.
var ErrWindowsLocalAPIUnavailable = errors.New("local API is not available on Windows yet")

type FileTransferLease struct {
	PeerContext []byte
	Handle      string
}

func (l *FileTransferLease) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, ErrWindowsLocalAPIUnavailable
}

func (*FileTransferLease) CloseIdleConnections() {}

func (*FileTransferLease) Close() error { return ErrWindowsLocalAPIUnavailable }

type Client struct {
	socket  string
	timeout time.Duration
}

func (c *Client) Watch(ctx context.Context, _ uint64) (<-chan Snapshot, <-chan error) {
	updates := make(chan Snapshot)
	errorsOut := make(chan error, 1)
	go func() {
		defer close(updates)
		defer close(errorsOut)
		if ctx == nil {
			errorsOut <- ErrInvalidConfig
			return
		}
		select {
		case errorsOut <- ErrWindowsLocalAPIUnavailable:
		case <-ctx.Done():
			errorsOut <- ctx.Err()
		}
	}()
	return updates, errorsOut
}

func NewClient(socketPath string, timeout time.Duration) (*Client, error) {
	if !strings.HasPrefix(socketPath, `\\.\pipe\`) || strings.ContainsAny(socketPath, "\x00\r\n") || timeout <= 0 || timeout > time.Minute {
		return nil, ErrInvalidConfig
	}
	return &Client{socket: socketPath, timeout: timeout}, nil
}

func (*Client) OpenPeerStream(context.Context, PeerStreamRequest) (net.Conn, error) {
	return nil, ErrWindowsLocalAPIUnavailable
}

func (*Client) PrepareFileTransfer(context.Context, FileTransferKeyRequest) (*FileTransferLease, error) {
	return nil, ErrWindowsLocalAPIUnavailable
}

func (*Client) OpenFileTransferStream(context.Context, string) (net.Conn, error) {
	return nil, ErrWindowsLocalAPIUnavailable
}

func (*Client) Snapshot(context.Context) (Snapshot, error) {
	return Snapshot{}, ErrWindowsLocalAPIUnavailable
}

func (*Client) Completions(context.Context) (CompletionSnapshot, error) {
	return CompletionSnapshot{}, ErrWindowsLocalAPIUnavailable
}

func (*Client) Diagnostics(context.Context) (DiagnosticSnapshot, error) {
	return DiagnosticSnapshot{}, ErrWindowsLocalAPIUnavailable
}

func (*Client) RecordBugreportMarker(context.Context, string) error {
	return ErrWindowsLocalAPIUnavailable
}

func (*Client) CreateBugreport(context.Context) (diagnostics.Bundle, error) {
	return diagnostics.Bundle{}, ErrWindowsLocalAPIUnavailable
}

func (*Client) ProbePeer(context.Context, PeerStreamRequest) (PeerProbeResult, error) {
	return PeerProbeResult{}, ErrWindowsLocalAPIUnavailable
}

func (*Client) PublishTransportObservation(context.Context, TransportObservation) error {
	return ErrWindowsLocalAPIUnavailable
}
