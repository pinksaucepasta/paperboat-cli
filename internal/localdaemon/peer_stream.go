package localdaemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/diagnosticlog"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transportmanager"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
	"github.com/pinksaucepasta/paperboat/internal/tunnel"
)

func TunnelPeerStreamOpener(peerTunnel *tunnel.PeerTerminalTunnel) func(context.Context, localapi.Peer, localapi.PeerStreamRequest, *transportmanager.Manager) (net.Conn, error) {
	return func(ctx context.Context, _ localapi.Peer, request localapi.PeerStreamRequest, _ *transportmanager.Manager) (net.Conn, error) {
		started := time.Now()
		if ctx == nil || peerTunnel == nil || request.Validate(peerTunnelNow()) != nil {
			return nil, ErrInvalidInventoryConfig
		}
		var terminalPayload localapi.PeerTerminalPayload
		if len(request.Payload) > 0 && request.Consumer != "exec" && request.Consumer != "private_preview" {
			if err := json.Unmarshal(request.Payload, &terminalPayload); err != nil {
				return nil, err
			}
		}
		target := &resolver.TerminalTarget{Protocol: terminalPayload.Protocol, Debug: terminalPayload.Debug, EnvironmentID: request.EnvironmentID, Auth: resolver.AuthTarget{Token: request.Credential, ExpiresAt: request.Deadline.UTC().Format("2006-01-02T15:04:05Z07:00")}, ThreadID: terminalPayload.ThreadID, TerminalID: terminalPayload.TerminalID, SessionID: terminalPayload.SessionID, CWD: terminalPayload.CWD, Env: terminalPayload.Environment, Cols: terminalPayload.Columns, Rows: terminalPayload.Rows, RestartIfNotRunning: terminalPayload.RestartIfNotRunning, ReplayHistory: terminalPayload.ReplayHistory, AfterSequence: terminalPayload.AfterSequence, InputAttachmentID: terminalPayload.InputAttachmentID}
		target.QUICEndpoint, target.WSSEndpoint = request.QUICEndpoint, request.WSSEndpoint
		info := resolver.ConnectInfo{TargetKind: "machine", ProjectID: request.MachineID, MachineGeneration: request.MachineGeneration, Transport: request.Transport, Terminal: target}
		// Setup is part of the local API request and must stop when the caller
		// cancels or its deadline expires. Once the HTTP handler upgrades, the
		// returned stream becomes daemon-owned and is governed by its lease.
		lifetime, cancelLifetime := context.WithCancel(context.Background())
		var handoffMu sync.Mutex
		handedOff := false
		stopCallerCancel := context.AfterFunc(ctx, func() {
			handoffMu.Lock()
			defer handoffMu.Unlock()
			if !handedOff {
				cancelLifetime()
			}
		})
		deadlineTimer := time.AfterFunc(time.Until(request.Deadline), cancelLifetime)
		stopSetupCancellation := func() bool {
			handoffMu.Lock()
			handedOff = true
			handoffMu.Unlock()
			stopCallerCancel()
			return deadlineTimer.Stop() && ctx.Err() == nil && lifetime.Err() == nil && time.Now().Before(request.Deadline)
		}
		var remote tunnel.Conn
		var err error
		diagnosticlog.TryInfo("local peer dial starting", "consumer", request.Consumer, "machine_id", request.MachineID)
		dial := func() (tunnel.Conn, error) {
			switch request.Consumer {
			case "terminal":
				return peerTunnel.Dial(lifetime, info)
			case "exec":
				var value tunnel.ExecRequest
				if json.Unmarshal(request.Payload, &value) != nil || value.OperationID != request.OperationID {
					return nil, ErrInvalidInventoryConfig
				}
				return peerTunnel.DialExec(lifetime, info, value)
			case "ssh":
				return peerTunnel.DialSSH(lifetime, info, request.OperationID)
			case "private_preview":
				var value localapi.PeerPreviewPayload
				if json.Unmarshal(request.Payload, &value) != nil || value.Port == 0 {
					return nil, ErrInvalidInventoryConfig
				}
				return peerTunnel.DialPrivatePreview(lifetime, info, value.Port)
			case "codex":
				connection, dialErr := peerTunnel.DialCodexHTTP(lifetime, info)
				if dialErr != nil {
					return nil, dialErr
				}
				remote, ok := connection.(tunnel.Conn)
				if !ok {
					return nil, errors.New("codex peer connection does not implement tunnel contract")
				}
				return remote, nil
			default:
				return nil, ErrInvalidInventoryConfig
			}
		}
		remote, err = dialWithInvalidationRetry(lifetime, dial)
		if errors.Is(err, ErrInvalidInventoryConfig) {
			stopCallerCancel()
			deadlineTimer.Stop()
			cancelLifetime()
			return nil, ErrInvalidInventoryConfig
		}
		diagnosticlog.TryInfo("local peer dial finished", "consumer", request.Consumer, "machine_id", request.MachineID, "elapsed_ms", time.Since(started).Milliseconds(), "error", err)
		if err != nil {
			stopCallerCancel()
			deadlineTimer.Stop()
			cancelLifetime()
			diagnosticlog.TryInfo("local peer stream open failed", "consumer", request.Consumer, "machine_id", request.MachineID, "error", err)
			return nil, err
		}
		if !stopSetupCancellation() {
			cancelLifetime()
			_ = remote.Close()
			return nil, context.Canceled
		}
		diagnosticlog.TryInfo("local peer stream opened", "consumer", request.Consumer, "machine_id", request.MachineID, "elapsed_ms", time.Since(started).Milliseconds())
		if request.Consumer == "ssh" || request.Consumer == "private_preview" {
			return &rawPeerConn{Conn: remote, cancel: cancelLifetime}, nil
		}
		client, server := net.Pipe()
		go func() {
			defer cancelLifetime()
			if request.Consumer == "terminal" && terminalPayload.Debug {
				_ = tunnel.ServeLocalPeerDebugConn(lifetime, server, remote)
			} else {
				_ = tunnel.ServeLocalPeerConn(lifetime, server, remote)
			}
		}()
		return client, nil
	}
}

func TunnelPeerProbe(peerTunnel *tunnel.PeerTerminalTunnel) func(context.Context, localapi.Peer, localapi.PeerStreamRequest) (localapi.PeerProbeResult, error) {
	return func(ctx context.Context, _ localapi.Peer, request localapi.PeerStreamRequest) (localapi.PeerProbeResult, error) {
		if peerTunnel == nil || request.Consumer != "health_probe" {
			return localapi.PeerProbeResult{}, ErrInvalidInventoryConfig
		}
		var targetPayload localapi.PeerTerminalPayload
		if len(request.Payload) > 0 {
			if err := json.Unmarshal(request.Payload, &targetPayload); err != nil {
				return localapi.PeerProbeResult{}, err
			}
		}
		target := resolver.ConnectInfo{TargetKind: "machine", ProjectID: request.MachineID, MachineGeneration: request.MachineGeneration, Transport: request.Transport, Terminal: &resolver.TerminalTarget{Protocol: targetPayload.Protocol, EnvironmentID: request.EnvironmentID, Auth: resolver.AuthTarget{ExpiresAt: request.Deadline.UTC().Format(time.RFC3339)}}}
		result, err := peerTunnel.PingTransport(ctx, target, request.Transport)
		if err != nil && retryablePeerProbe(ctx, err) {
			diagnosticlog.TryInfo("local peer probe retrying with a fresh path", "machine_id", request.MachineID, "error", err)
			result, err = peerTunnel.PingTransport(ctx, target, request.Transport)
		}
		if err != nil {
			diagnosticlog.TryInfo("local peer probe failed", "machine_id", request.MachineID, "error", err)
			return localapi.PeerProbeResult{}, err
		}
		path := "unknown"
		switch result.Path {
		case connectionmanager.PathDirectQUIC:
			path = "direct_quic"
		case connectionmanager.PathRelayQUIC:
			path = "relay_quic"
		case connectionmanager.PathWSS:
			path = "wss"
		}
		return localapi.PeerProbeResult{Transport: path, RelayRegion: result.RelayRegion, ConnectionNanoseconds: result.Connection.Nanoseconds(), RTTNanoseconds: result.RTT.Nanoseconds(), PTOs: result.PTOs}, nil
	}
}

func retryablePeerProbe(ctx context.Context, err error) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	var failure *connectionmanager.Failure
	if errors.As(err, &failure) {
		return failure.AllowsFallback()
	}
	return !errors.Is(err, context.Canceled)
}

type rawPeerConn struct {
	tunnel.Conn
	cancel context.CancelFunc
}

func (*rawPeerConn) LocalAddr() net.Addr              { return rawPeerAddr("daemon") }
func (*rawPeerConn) RemoteAddr() net.Addr             { return rawPeerAddr("machine") }
func (*rawPeerConn) SetDeadline(time.Time) error      { return nil }
func (*rawPeerConn) SetReadDeadline(time.Time) error  { return nil }
func (*rawPeerConn) SetWriteDeadline(time.Time) error { return nil }
func (c *rawPeerConn) CloseWrite() error {
	if closer, ok := c.Conn.(tunnel.InputHalfCloser); ok {
		return closer.CloseWrite()
	}
	return net.ErrClosed
}
func (c *rawPeerConn) Close() error {
	c.cancel()
	return c.Conn.Close()
}

type rawPeerAddr string

func (a rawPeerAddr) Network() string { return "paperboat-peer" }
func (a rawPeerAddr) String() string  { return string(a) }

func peerTunnelNow() time.Time { return time.Now().UTC() }

func dialWithInvalidationRetry(ctx context.Context, dial func() (tunnel.Conn, error)) (tunnel.Conn, error) {
	connection, err := dial()
	if err == nil || ctx.Err() != nil || !retryablePeerDial(err) {
		return connection, err
	}
	diagnosticlog.TryInfo("local peer dial retrying with a fresh machine session", "error", err)
	retryConnection, retryErr := dial()
	if retryErr != nil {
		return nil, errors.Join(fmt.Errorf("initial peer dial: %w", err), fmt.Errorf("fresh peer dial retry: %w", retryErr))
	}
	return retryConnection, nil
}

func retryablePeerDial(err error) bool {
	return errors.Is(err, transportmanager.ErrInvalid) || errors.Is(err, tunnel.ErrPeerStreamOpen) || tunnel.FallbackEligible(err) || errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}
