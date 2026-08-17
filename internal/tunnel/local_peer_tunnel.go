package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

type LocalPeerTunnel struct {
	Client    *localapi.Client
	Transport TerminalTransport
}

func (t LocalPeerTunnel) request(info resolver.ConnectInfo, consumer, operationID string, payload any) (localapi.PeerStreamRequest, error) {
	if t.Client == nil || info.ProjectID == "" || info.MachineGeneration == 0 || info.Terminal == nil || info.Terminal.EnvironmentID == "" {
		return localapi.PeerStreamRequest{}, fmt.Errorf("%w: missing local peer target (client=%t project=%q generation=%d terminal=%t environment=%q)", ErrPeerTerminalInvalid, t.Client != nil, info.ProjectID, info.MachineGeneration, info.Terminal != nil, func() string {
			if info.Terminal == nil {
				return ""
			}
			return info.Terminal.EnvironmentID
		}())
	}
	deadline := time.Now().Add(2 * time.Minute)
	var err error
	if info.Terminal.Auth.ExpiresAt != "" {
		deadline, err = time.Parse(time.RFC3339, info.Terminal.Auth.ExpiresAt)
		if err != nil {
			return localapi.PeerStreamRequest{}, err
		}
	}
	var encoded json.RawMessage
	if payload != nil {
		encoded, err = json.Marshal(payload)
		if err != nil {
			return localapi.PeerStreamRequest{}, err
		}
	}
	var request localapi.PeerStreamRequest
	if info.Terminal.Auth.Token == "" {
		request, err = localapi.NewPendingPeerStreamRequest(info.ProjectID, info.Terminal.EnvironmentID, info.MachineGeneration, consumer, operationID, deadline, 1<<40, encoded)
	} else {
		request, err = localapi.NewPeerStreamRequest(info.ProjectID, info.Terminal.EnvironmentID, info.MachineGeneration, consumer, operationID, info.Terminal.Auth.Token, deadline, 1<<40, encoded)
	}
	if err != nil {
		return localapi.PeerStreamRequest{}, err
	}
	request.Transport = string(t.Transport)
	if request.Transport == "" {
		request.Transport = string(TerminalTransportAuto)
	}
	if request.Credential == "" {
		if validationErr := request.ValidatePending(time.Now().UTC()); validationErr != nil {
			return request, fmt.Errorf("%w: pending peer request: %v", ErrPeerTerminalInvalid, validationErr)
		}
		return request, nil
	}
	if validationErr := request.Validate(time.Now().UTC()); validationErr != nil {
		return request, fmt.Errorf("%w: peer request: %v", ErrPeerTerminalInvalid, validationErr)
	}
	return request, nil
}

func terminalLocalPayload(target *resolver.TerminalTarget) localapi.PeerTerminalPayload {
	return localapi.PeerTerminalPayload{Protocol: target.Protocol, ThreadID: target.ThreadID, TerminalID: target.TerminalID, SessionID: target.SessionID, CWD: target.CWD, Environment: target.Env, Columns: target.Cols, Rows: target.Rows, RestartIfNotRunning: target.RestartIfNotRunning, ReplayHistory: target.ReplayHistory, AfterSequence: target.AfterSequence, InputAttachmentID: target.InputAttachmentID}
}

func (t LocalPeerTunnel) Dial(ctx context.Context, info resolver.ConnectInfo) (Conn, error) {
	operationID := info.Terminal.SessionID
	if operationID == "" {
		operationID = "operation_terminal_attach"
	}
	request, err := t.request(info, "terminal", operationID, terminalLocalPayload(info.Terminal))
	if err != nil {
		return nil, err
	}
	stream, err := t.Client.OpenPeerStream(ctx, request)
	if err != nil {
		return nil, err
	}
	connection, err := NewLocalPeerConn(stream)
	if err != nil {
		_ = stream.Close()
	}
	return connection, err
}

func (t LocalPeerTunnel) DialExec(ctx context.Context, info resolver.ConnectInfo, value ExecRequest) (ExecConn, error) {
	request, err := t.request(info, "exec", value.OperationID, value)
	if err != nil {
		return nil, err
	}
	stream, err := t.Client.OpenPeerStream(ctx, request)
	if err != nil {
		return nil, err
	}
	connection, err := NewLocalExecPeerConn(stream)
	if err != nil {
		_ = stream.Close()
	}
	return connection, err
}

func (t LocalPeerTunnel) DialSSH(ctx context.Context, info resolver.ConnectInfo, operationID string) (Conn, error) {
	request, err := t.request(info, "ssh", operationID, terminalLocalPayload(info.Terminal))
	if err != nil {
		return nil, err
	}
	stream, err := t.Client.OpenPeerStream(ctx, request)
	if err != nil {
		return nil, err
	}
	return &sshStreamConn{ReadWriteCloser: stream}, nil
}

func (t LocalPeerTunnel) DialPrivatePreview(ctx context.Context, info resolver.ConnectInfo, port uint16) (Conn, error) {
	operationID := info.Terminal.SessionID
	if operationID == "" {
		operationID = fmt.Sprintf("operation_preview_%d", port)
	}
	request, err := t.request(info, "private_preview", operationID, localapi.PeerPreviewPayload{Port: port})
	if err != nil {
		return nil, err
	}
	stream, err := t.Client.OpenPeerStream(ctx, request)
	if err != nil {
		return nil, err
	}
	// Private preview is already one opaque HTTP/3 CONNECT byte stream at the
	// daemon boundary. Terminal framing here corrupts the browser HTTP bytes.
	return &previewStreamConn{ReadWriteCloser: stream}, nil
}

func (t LocalPeerTunnel) DialCodexHTTP(ctx context.Context, info resolver.ConnectInfo) (net.Conn, error) {
	operationID := info.Terminal.SessionID
	if operationID == "" {
		operationID = "operation_codex_connect"
	}
	request, err := t.request(info, "codex", operationID, terminalLocalPayload(info.Terminal))
	if err != nil {
		return nil, err
	}
	stream, err := t.Client.OpenPeerStream(ctx, request)
	if err != nil {
		return nil, err
	}
	connection, err := NewLocalPeerConn(stream)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	return &localPeerNetConn{Conn: connection, raw: stream}, nil
}

type localPeerNetConn struct {
	Conn
	raw net.Conn
}

func (*localPeerNetConn) LocalAddr() net.Addr                  { return localPeerAddress("local") }
func (*localPeerNetConn) RemoteAddr() net.Addr                 { return localPeerAddress("machine") }
func (c *localPeerNetConn) SetDeadline(v time.Time) error      { return c.raw.SetDeadline(v) }
func (c *localPeerNetConn) SetReadDeadline(v time.Time) error  { return c.raw.SetReadDeadline(v) }
func (c *localPeerNetConn) SetWriteDeadline(v time.Time) error { return c.raw.SetWriteDeadline(v) }

type localPeerAddress string

func (localPeerAddress) Network() string  { return "paperboat-local-peer" }
func (a localPeerAddress) String() string { return string(a) }

var _ Tunnel = LocalPeerTunnel{}
var _ net.Conn = (*localPeerNetConn)(nil)
