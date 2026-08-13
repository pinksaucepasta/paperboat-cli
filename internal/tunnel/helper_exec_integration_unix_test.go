//go:build darwin || linux

package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/auth"
	hostconfig "github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/execprocess"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/operation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/process"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/pty"
	hostruntime "github.com/pinksaucepasta/paperboat/internal/hostruntime/runtime"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/session"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

type execCanaryClock struct{ now time.Time }

func (c execCanaryClock) Now() time.Time { return c.now }

type execCanaryLauncher struct{}

func (execCanaryLauncher) Launch(context.Context, process.LaunchRequest) (session.Snapshot, error) {
	return session.Snapshot{}, errors.New("terminal launch is unavailable in exec canary")
}

type execCanaryWire struct {
	clientToServer chan execMessage
	serverToClient chan execMessage
	done           chan struct{}
	closeOnce      sync.Once
}

func newExecCanaryWire() *execCanaryWire {
	return &execCanaryWire{clientToServer: make(chan execMessage, 32), serverToClient: make(chan execMessage, 32), done: make(chan struct{})}
}

func (w *execCanaryWire) Read([]byte) (int, error) {
	return 0, errors.New("application framing required")
}
func (w *execCanaryWire) Write(value []byte) (int, error) { return len(value), nil }
func (w *execCanaryWire) Close() error {
	w.closeOnce.Do(func() { close(w.done) })
	return nil
}

func (w *execCanaryWire) ReadMessage(ctx context.Context) (helperMessageType, []byte, error) {
	select {
	case message := <-w.serverToClient:
		return message.kind, message.data, nil
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case <-w.done:
		return 0, nil, io.EOF
	}
}

func (w *execCanaryWire) WriteMessage(ctx context.Context, kind helperMessageType, data []byte) error {
	select {
	case w.clientToServer <- execMessage{kind: kind, data: append([]byte(nil), data...)}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-w.done:
		return io.ErrClosedPipe
	}
}

func (w *execCanaryWire) ReadApplication() (protocol.Frame, []byte, error) {
	select {
	case message := <-w.clientToServer:
		if message.kind == helperBinaryMessage {
			return protocol.Frame{}, message.data, nil
		}
		var frame protocol.Frame
		if message.kind != helperStructuredMessage || json.Unmarshal(message.data, &frame) != nil {
			return protocol.Frame{}, nil, errors.New("invalid canary client frame")
		}
		return frame, nil, nil
	case <-w.done:
		return protocol.Frame{}, nil, io.EOF
	}
}

func (w *execCanaryWire) WriteStructured(frame protocol.Frame) error {
	encoded, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	return w.sendServer(execMessage{kind: helperStructuredMessage, data: encoded})
}

func (w *execCanaryWire) WriteBinary(frame protocol.BinaryFrame) error {
	return w.WriteTerminalOutput(1, frame)
}

func (w *execCanaryWire) WriteTerminalOutput(streamID uint32, frame protocol.BinaryFrame) error {
	encoded, err := protocol.EncodeTerminalOutputAdaptive(protocol.TerminalOutputFrame{Channel: frame.Channel, StreamID: streamID, StartSequence: frame.StartSequence, Data: frame.Data}, nil)
	if err != nil {
		return err
	}
	return w.sendServer(execMessage{kind: helperBinaryMessage, data: encoded})
}

func (w *execCanaryWire) sendServer(message execMessage) error {
	select {
	case w.serverToClient <- message:
		return nil
	case <-w.done:
		return io.ErrClosedPipe
	}
}

func signExecCanaryCredential(t *testing.T, keyID string, private ed25519.PrivateKey, claims auth.Claims) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "kid": keyID, "typ": "paperboat-credential+jwt"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(signed)))
}

func TestExecApplicationProtocolCanary(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const operationID = "operation_exec_canary"
	claims := auth.Claims{
		Issuer: "https://paperboat.test", Audience: "paperboat-machine", Subject: "user_canary", JTI: "jti_exec_canary",
		IssuedAt: now.Add(-time.Second).Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(), Scope: []string{"exec:operate"}, CredentialClass: "exec_operation",
		EnvironmentID: "env_canary", UserID: "user_canary", CLIClientSessionID: "cli_canary", HelperID: "helper_canary", MachineID: "machine_canary", OperationID: operationID,
	}
	token := signExecCanaryCredential(t, "key_canary", private, claims)
	authorizers, err := hostruntime.NewStaticAuthorizer(hostruntime.StaticAuthConfig{Issuer: claims.Issuer, EnvironmentID: claims.EnvironmentID, MachineID: claims.MachineID, HelperID: claims.HelperID, Keys: map[string]ed25519.PublicKey{"key_canary": public}, Clock: execCanaryClock{now}})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := authorizers(token)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := session.NewManager(session.ManagerConfig{Launch: func(pty.Command) (session.PTYProcess, error) { return nil, errors.New("terminal unavailable") }, MaxSessions: 1})
	if err != nil {
		t.Fatal(err)
	}
	executions, err := execprocess.New(execprocess.Config{WorkspaceRoot: root, BaseEnvironment: []string{"PATH=/usr/bin:/bin", "LANG=C"}, MaximumActive: 2, ReplayBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	readiness := health.New("canary", []string{"terminal.v1", "health.v1", "exec.v1"}, nil)
	dispatcher, err := server.NewDispatcher(server.DispatcherConfig{Sessions: sessions, Health: readiness, SessionLauncher: execCanaryLauncher{}, WorkspaceRoot: root, Random: bytes.NewReader(bytes.Repeat([]byte{1}, 256)), Exec: executions})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := operation.NewJournal(32)
	if err != nil {
		t.Fatal(err)
	}
	host, err := server.New(server.Config{Negotiator: protocol.Negotiator{Profile: hostconfig.BYOD, Available: map[string]bool{"terminal.v1": true, "health.v1": true, "exec.v1": true}}, Journal: journal, Authorizer: authorizer, Handler: dispatcher, MaxConcurrent: 4, HeartbeatInterval: time.Hour, MutationDeadline: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = host.Shutdown(ctx)
		_ = sessions.Shutdown(ctx)
	})
	wire := newExecCanaryWire()
	serveDone := make(chan error, 1)
	go func() { serveDone <- host.ServeAuthenticated(wire, authorizer) }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := helperHandshake(ctx, wire); err != nil {
		t.Fatal(err)
	}
	connection := &helperExecConn{message: wire, target: &resolver.TerminalTarget{}, request: ExecRequest{OperationID: operationID, Argv: []string{"/bin/sh", "-c", `printf stdout-canary; printf stderr-canary >&2; exit 23`}, CWD: root}, events: make(chan ExecEvent, 16), done: make(chan struct{}), pending: make(map[string]chan helperFrame)}
	if err := connection.initialize(ctx); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	for event := range connection.Events() {
		switch event.Stream {
		case "stdout":
			stdout.Write(event.Data)
		case "stderr":
			stderr.Write(event.Data)
		}
	}
	exitCode, err := connection.Wait()
	if err != nil || exitCode != 23 || stdout.String() != "stdout-canary" || stderr.String() != "stderr-canary" {
		t.Fatalf("exit=%d err=%v stdout=%q stderr=%q", exitCode, err, stdout.String(), stderr.String())
	}
	_ = wire.Close()
	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("host server did not stop after canary close")
	}
}
