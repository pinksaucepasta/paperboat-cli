//go:build darwin || linux

package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/execprocess"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/operation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/process"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/pty"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/session"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
)

type healthyProber struct{}

func (healthyProber) Probe(context.Context, preview.Target) error { return nil }

type testSessionLauncher struct {
	sessions *session.Manager
	args     []string
}

func execDispatcher(t *testing.T) (*Dispatcher, string) {
	t.Helper()
	root := t.TempDir()
	adapter, err := pty.NewAdapter(root)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := session.NewManager(session.ManagerConfig{Launch: func(command pty.Command) (session.PTYProcess, error) { return adapter.Start(command) }, MaxSessions: 1})
	if err != nil {
		t.Fatal(err)
	}
	executions, err := execprocess.New(execprocess.Config{WorkspaceRoot: root, BaseEnvironment: []string{"PATH=/usr/bin:/bin", "LANG=C"}, MaximumActive: 4, ReplayBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	readiness := health.New("test", []string{"terminal.v1", "health.v1", "exec.v1"}, nil)
	dispatcher, err := NewDispatcher(DispatcherConfig{Sessions: sessions, Health: readiness, SessionLauncher: testSessionLauncher{sessions: sessions, args: []string{"-c", "exit"}}, WorkspaceRoot: root, Random: bytes.NewReader(bytes.Repeat([]byte{1}, 256)), Exec: executions})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = sessions.Shutdown(ctx)
	})
	return dispatcher, root
}

func TestExecDispatcherStreamsInputStdoutStderrAndExactExit(t *testing.T) {
	dispatcher, root := execDispatcher(t)
	authorization := Authorization{ClientID: "cli_1"}
	payload, _ := json.Marshal(map[string]any{"action": "start", "operation_id": "operation_dispatch", "argv": []string{"/bin/sh", "-c", `read line; printf "out:%s" "$line"; printf "err:%s" "$line" >&2; exit 7`}, "cwd": root})
	outcome := dispatcher.Handle(context.Background(), authorization, "exec.v1", payload)
	if outcome.ErrorCode != "" {
		t.Fatalf("outcome=%#v", outcome)
	}
	stream, opened, err := dispatcher.OpenStream(context.Background(), authorization, "exec.v1", payload, outcome, false)
	if err != nil || !opened {
		t.Fatalf("opened=%v err=%v", opened, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		execution, getErr := dispatcher.config.Exec.Get("operation_dispatch")
		if getErr == nil && execution.Snapshot().State == execprocess.StateRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("exec did not reach running state")
		}
		time.Sleep(time.Millisecond)
	}
	if err := dispatcher.HandleExecInput(context.Background(), authorization, "operation_dispatch", []byte("value\n")); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	var lastEventSequence uint64
	for {
		frame, nextErr := stream.Next(context.Background())
		if nextErr == nil {
			if len(frame.Data) < 9 || frame.Data[0] != execOutputEnvelopeVersion {
				t.Fatalf("invalid exec output envelope: %x", frame.Data)
			}
			eventSequence := binary.BigEndian.Uint64(frame.Data[1:9])
			if eventSequence <= lastEventSequence {
				t.Fatalf("event sequence = %d after %d", eventSequence, lastEventSequence)
			}
			lastEventSequence = eventSequence
			if frame.Channel == protocol.Stdout {
				stdout.Write(frame.Data[9:])
			} else if frame.Channel == protocol.Stderr {
				stderr.Write(frame.Data[9:])
			}
			if frame.Release != nil {
				frame.Release()
			}
			continue
		}
		var end *StreamEnd
		if !errors.As(nextErr, &end) {
			t.Fatal(nextErr)
		}
		var terminal struct {
			State    string `json:"state"`
			Sequence uint64 `json:"sequence"`
			Result   struct {
				Code int `json:"code"`
			} `json:"result"`
		}
		if json.Unmarshal(end.Payload, &terminal) != nil || terminal.State != "exited" || terminal.Result.Code != 7 || terminal.Sequence <= lastEventSequence {
			t.Fatalf("end=%s", end.Payload)
		}
		break
	}
	if stdout.String() != "out:value" || stderr.String() != "err:value" {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestExecDispatcherLiveStreamExceedsReplayBudgetWithoutGap(t *testing.T) {
	dispatcher, root := execDispatcher(t)
	authorization := Authorization{ClientID: "cli_1"}
	payload, _ := json.Marshal(map[string]any{"action": "start", "operation_id": "operation_large_live", "argv": []string{"/bin/sh", "-c", `head -c 262144 /dev/zero`}, "cwd": root})
	outcome := dispatcher.Handle(context.Background(), authorization, "exec.v1", payload)
	if outcome.ErrorCode != "" {
		t.Fatalf("outcome=%#v", outcome)
	}
	stream, opened, err := dispatcher.OpenStream(context.Background(), authorization, "exec.v1", payload, outcome, false)
	if err != nil || !opened {
		t.Fatalf("opened=%v err=%v", opened, err)
	}
	defer stream.Close()
	var received int
	for {
		frame, nextErr := stream.Next(context.Background())
		if nextErr == nil {
			if len(frame.Data) < 9 {
				t.Fatalf("short frame: %d", len(frame.Data))
			}
			received += len(frame.Data) - 9
			if frame.Release != nil {
				frame.Release()
			}
			continue
		}
		var end *StreamEnd
		if !errors.As(nextErr, &end) {
			t.Fatal(nextErr)
		}
		break
	}
	if received != 262144 {
		t.Fatalf("received=%d", received)
	}
}

func TestSSHDispatcherBridgesOpaqueBytesAndEOF(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	host, err := managedssh.NewHost(managedssh.HostConfig{MaxStreams: 2, ProbeTimeout: time.Second, DialTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	if _, err := host.ReconcileTarget(context.Background(), 4, port); err != nil {
		t.Fatal(err)
	}
	dispatcher, _ := execDispatcher(t)
	dispatcher.config.SSH = host
	authorization := Authorization{ClientID: "cli_1"}
	payload := json.RawMessage(`{"operation_id":"operation_ssh_0001","generation":4}`)
	outcome := dispatcher.HandleOperation(context.Background(), authorization, "ssh.v1", "operation_ssh_0001", payload)
	if outcome.ErrorCode != "" {
		t.Fatalf("outcome=%#v", outcome)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, opened, err := dispatcher.OpenStream(ctx, authorization, "ssh.v1", payload, outcome, false)
	if err != nil || !opened {
		t.Fatalf("opened=%v err=%v", opened, err)
	}
	defer stream.Close()
	if err := dispatcher.HandleSSHInput(ctx, authorization, "operation_ssh_0001", []byte("opaque-ssh-bytes")); err != nil {
		t.Fatal(err)
	}
	frame, err := stream.Next(ctx)
	if err != nil || string(frame.Data) != "opaque-ssh-bytes" || frame.Channel != protocol.Stdout {
		t.Fatalf("frame=%#v err=%v", frame, err)
	}
	if err := dispatcher.HandleSSHEOF(ctx, authorization, "operation_ssh_0001"); err != nil {
		t.Fatal(err)
	}
}

func TestExecDispatcherResumesFromJournalSequenceWithoutOutputReplay(t *testing.T) {
	dispatcher, root := execDispatcher(t)
	authorization := Authorization{ClientID: "cli_1"}
	payload, _ := json.Marshal(map[string]any{"action": "start", "operation_id": "operation_resume", "argv": []string{"/bin/sh", "-c", `printf one; sleep 0.1; printf two`}, "cwd": root})
	outcome := dispatcher.Handle(context.Background(), authorization, "exec.v1", payload)
	stream, opened, err := dispatcher.OpenStream(context.Background(), authorization, "exec.v1", payload, outcome, false)
	if err != nil || !opened {
		t.Fatalf("opened=%v err=%v outcome=%#v", opened, err, outcome)
	}
	first, err := stream.Next(context.Background())
	if err != nil || len(first.Data) < 9 || string(first.Data[9:]) != "one" {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	from := binary.BigEndian.Uint64(first.Data[1:9]) + 1
	attachPayload, _ := json.Marshal(map[string]any{"action": "start", "operation_id": "operation_resume", "argv": []string{"/bin/sh", "-c", `printf one; sleep 0.1; printf two`}, "cwd": root, "from_sequence": from})
	replay := dispatcher.Handle(context.Background(), authorization, "exec.v1", attachPayload)
	resumed, opened, err := dispatcher.OpenStream(context.Background(), authorization, "exec.v1", attachPayload, replay, true)
	if err != nil || !opened || replay.ErrorCode != "" {
		t.Fatalf("opened=%v err=%v replay=%#v", opened, err, replay)
	}
	second, err := resumed.Next(context.Background())
	if err != nil || len(second.Data) < 9 || string(second.Data[9:]) != "two" {
		t.Fatalf("second=%#v err=%v", second, err)
	}
	if sequence := binary.BigEndian.Uint64(second.Data[1:9]); sequence < from {
		t.Fatalf("resumed sequence = %d, want >= %d", sequence, from)
	}
}

func TestExecStreamBindingAcceptsBinaryInputAndResizeOnlyForPTY(t *testing.T) {
	dispatcher, root := execDispatcher(t)
	authorization := Authorization{ClientID: "cli_1"}
	payload, _ := json.Marshal(map[string]any{"action": "start", "operation_id": "operation_binding", "argv": []string{"/bin/sh", "-c", "read line; printf %s \"$line\""}, "cwd": root})
	outcome := dispatcher.Handle(context.Background(), authorization, "exec.v1", payload)
	state := newTerminalConnectionState()
	streamID, err := state.bind(authorization, protocol.Frame{Capability: "exec.v1", Payload: payload}, outcome)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		execution, getErr := dispatcher.config.Exec.Get("operation_binding")
		if getErr == nil && execution.Snapshot().State == execprocess.StateRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("exec did not start")
		}
		time.Sleep(time.Millisecond)
	}
	wire, _ := protocol.EncodeTerminalInput(protocol.TerminalInputFrame{StreamID: streamID, Sequence: 1, Data: []byte("bound\n")}, nil)
	server := &Server{config: Config{Handler: dispatcher}}
	if err := server.handleTerminalData(context.Background(), wire, state); err != nil {
		t.Fatal(err)
	}
	resize, _ := protocol.EncodeTerminalResize(protocol.TerminalResizeFrame{StreamID: streamID, Sequence: 1, Columns: 100, Rows: 30}, nil)
	if err := server.handleTerminalData(context.Background(), resize, state); !errors.Is(err, execprocess.ErrInvalid) {
		t.Fatalf("non-PTY resize err=%v", err)
	}
}

func TestExecProtocolOperationIDMustMatchPayload(t *testing.T) {
	dispatcher, root := execDispatcher(t)
	payload, _ := json.Marshal(map[string]any{"action": "start", "operation_id": "operation_payload", "argv": []string{"/bin/true"}, "cwd": root})
	outcome := dispatcher.HandleOperation(context.Background(), Authorization{ClientID: "cli_1"}, "exec.v1", "operation_frame", payload)
	if outcome.ErrorCode != "invalid_request" {
		t.Fatalf("outcome=%#v", outcome)
	}
	if _, err := dispatcher.config.Exec.Get("operation_payload"); !errors.Is(err, execprocess.ErrNotFound) {
		t.Fatalf("mismatched operation started: %v", err)
	}
}

func TestExecAttachReusesExistingExecution(t *testing.T) {
	dispatcher, root := execDispatcher(t)
	operationID := "operation_attach"
	startPayload, _ := json.Marshal(map[string]any{"action": "start", "operation_id": operationID, "argv": []string{"/bin/true"}, "cwd": root})
	if outcome := dispatcher.HandleOperation(context.Background(), Authorization{ClientID: "cli_1"}, "exec.v1", operationID, startPayload); outcome.ErrorCode != "" {
		t.Fatalf("start outcome=%#v", outcome)
	}
	attachPayload, _ := json.Marshal(map[string]any{"action": "attach", "operation_id": operationID, "from_sequence": 1})
	outcome := dispatcher.HandleOperation(context.Background(), Authorization{ClientID: "cli_1"}, "exec.v1", operationID, attachPayload)
	if outcome.ErrorCode != "" {
		t.Fatalf("attach outcome=%#v", outcome)
	}
	var response struct {
		Replay bool `json:"replay"`
	}
	if err := json.Unmarshal(outcome.Result, &response); err != nil || !response.Replay {
		t.Fatalf("attach result=%s err=%v", outcome.Result, err)
	}
}

func (l testSessionLauncher) Launch(ctx context.Context, request process.LaunchRequest) (session.Snapshot, error) {
	return l.sessions.Create(ctx, session.CreateRequest{ID: request.ID, Name: request.Name, Command: pty.Command{Path: "/bin/sh", Args: append([]string(nil), l.args...), Env: []string{"PATH=/usr/bin:/bin", "TERM=xterm"}, CWD: request.CWD, Dimensions: request.Dimensions}})
}

func verticalServer(t *testing.T) *Server {
	return verticalServerCommand(t, []string{"-c", "printf stream-data; read line"})
}

func verticalServerCommand(t *testing.T, shellArgs []string) *Server {
	t.Helper()
	root := t.TempDir()
	adapter, err := pty.NewAdapter(root)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := session.NewManager(session.ManagerConfig{Launch: func(command pty.Command) (session.PTYProcess, error) { return adapter.Start(command) }, MaxSessions: 4})
	if err != nil {
		t.Fatal(err)
	}
	previews, err := preview.New(preview.Config{Prober: healthyProber{}})
	if err != nil {
		t.Fatal(err)
	}
	readiness := health.New("test", []string{"terminal.v1", "health.v1", "preview.public.v1"}, nil)
	readiness.Set("terminal.v1", health.Ready, "", 0)
	readiness.Set("health.v1", health.Ready, "", 0)
	dispatcher, err := NewDispatcher(DispatcherConfig{
		Sessions: sessions, Previews: previews, Health: readiness,
		SessionLauncher: testSessionLauncher{sessions: sessions, args: shellArgs}, WorkspaceRoot: root,
		Random: bytes.NewReader(bytes.Repeat([]byte{1}, 256)),
	})
	if err != nil {
		t.Fatal(err)
	}
	journal, _ := operation.NewJournal(32)
	server, err := New(Config{
		Negotiator: protocol.Negotiator{Profile: config.BYOD, Available: map[string]bool{"terminal.v1": true, "health.v1": true, "preview.public.v1": true}},
		Journal:    journal,
		Authorizer: authorizerFunc(func(context.Context, protocol.Frame) (Authorization, error) {
			return Authorization{JournalBinding: "env:env_test_01:user:usr_1", EnvironmentID: "env_test_01", UserID: "usr_1", ClientID: "cli_1", ResourceID: "p-abcdefghijklmnopqrstuvwxyz"}, nil
		}),
		Handler: dispatcher, MaxConcurrent: 4, HeartbeatInterval: time.Hour, MutationDeadline: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = sessions.Shutdown(ctx)
	})
	return server
}

func TestTerminalStreamEndFollowsOutputWithExactExit(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("requires /bin/sh")
	}
	for _, test := range []struct {
		name    string
		command string
		code    int
		signal  string
	}{
		{name: "zero", command: "printf final-output; exit 0", code: 0},
		{name: "nonzero", command: "printf final-output; exit 7", code: 7},
		{name: "signal", command: "printf final-output; kill -TERM $$", code: 143, signal: "terminated"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := verticalServerCommand(t, []string{"-c", test.command})
			client, peer := net.Pipe()
			go server.Serve(peer)
			hello := json.RawMessage(`{"min_version":"1.0","max_version":"1.0","capabilities":["terminal.v1","health.v1"]}`)
			_ = sendRequest(t, client, protocol.Frame{Type: "hello", RequestID: "req_hello", Version: "1.0", Payload: hello})
			created := sendRequest(t, client, request("req_create", "op_create_exit", json.RawMessage(`{"action":"create","name":"exit-test","columns":80,"rows":24}`)))
			var createResponse struct {
				Result struct {
					ID string `json:"id"`
				} `json:"result"`
			}
			if json.Unmarshal(created.Payload, &createResponse) != nil || createResponse.Result.ID == "" {
				t.Fatalf("create=%s", created.Payload)
			}
			attachPayload, _ := json.Marshal(map[string]any{"action": "attach", "session_id": createResponse.Result.ID, "from_sequence": 0})
			if attached := sendRequest(t, client, request("req_attach", "op_attach_exit", attachPayload)); attached.Type != "response" {
				t.Fatalf("attach=%s", attached.Payload)
			}
			output, err := protocol.ReadBinaryFrame(client)
			if err != nil || string(output.Data) != "final-output" {
				t.Fatalf("output=%q err=%v", output.Data, err)
			}
			end, err := protocol.ReadFrame(client)
			if err != nil || end.Type != "event" || end.Capability != "terminal.v1" {
				t.Fatalf("end=%#v err=%v", end, err)
			}
			var payload struct {
				Event         string `json:"event"`
				SessionID     string `json:"session_id"`
				State         string `json:"state"`
				FinalSequence uint64 `json:"final_sequence"`
				Exit          struct {
					Code   int    `json:"code"`
					Signal string `json:"signal"`
				} `json:"exit"`
			}
			if json.Unmarshal(end.Payload, &payload) != nil || payload.Event != "terminal_stream_end" || payload.SessionID != createResponse.Result.ID || payload.State != "exited" || payload.FinalSequence != uint64(len("final-output")) || payload.Exit.Code != test.code || payload.Exit.Signal != test.signal {
				t.Fatalf("payload=%s", end.Payload)
			}
			_ = client.Close()
		})
	}
}

func TestAttachStreamsReplayAndLiveOutputAsBinaryFrames(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("requires /bin/sh")
	}
	server := verticalServer(t)
	client, peer := net.Pipe()
	go server.Serve(peer)
	payload := json.RawMessage(`{"min_version":"1.0","max_version":"1.0","capabilities":["terminal.v1","health.v1"]}`)
	_ = sendRequest(t, client, protocol.Frame{Type: "hello", RequestID: "req_hello", Version: "1.0", Payload: payload})
	response := sendRequest(t, client, request("req_create", "op_create_0001", json.RawMessage(`{"action":"create","name":"stream","columns":80,"rows":24}`)))
	var created struct {
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Payload, &created); err != nil || created.Result.ID == "" {
		t.Fatalf("create=%s err=%v", response.Payload, err)
	}
	attachPayload, _ := json.Marshal(map[string]any{"action": "attach", "session_id": created.Result.ID, "from_sequence": 0})
	response = sendRequest(t, client, request("req_attach", "op_attach_0001", attachPayload))
	if response.Type != "response" {
		t.Fatalf("attach=%s", response.Payload)
	}
	var attached struct {
		Result struct {
			AttachmentID string `json:"attachment_id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Payload, &attached); err != nil || attached.Result.AttachmentID == "" {
		t.Fatalf("attach payload=%s err=%v", response.Payload, err)
	}
	binary, err := protocol.ReadBinaryFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	if binary.Channel != protocol.Stdout || binary.StartSequence != 0 || string(binary.Data) != "stream-data" {
		t.Fatalf("binary=%#v", binary)
	}
	control, _ := json.Marshal(map[string]any{"session_id": created.Result.ID, "attachment_id": attached.Result.AttachmentID})
	if response = sendRequest(t, client, protocol.Frame{Type: "detach", RequestID: "req_detach", Version: "1.0", Payload: control}); response.Type != "response" {
		t.Fatalf("detach=%s", response.Payload)
	}
	// A health request proves explicit detach left the connection usable.
	healthFrame := request("req_health_after_detach", "op_health_after_detach", json.RawMessage(`{}`))
	healthFrame.Capability = "health.v1"
	if response = sendRequest(t, client, healthFrame); response.Type != "response" {
		t.Fatalf("post-detach health=%s", response.Payload)
	}
	_ = client.Close()
}

func TestAttachLargeReplayUsesBinaryStreamNotStructuredResponse(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("requires /bin/sh")
	}
	server := verticalServerCommand(t, []string{"-c", "dd if=/dev/zero bs=65536 count=1 2>/dev/null; read line"})
	client, peer := net.Pipe()
	go server.Serve(peer)
	hello := json.RawMessage(`{"min_version":"1.0","max_version":"1.0","capabilities":["terminal.v1","health.v1"]}`)
	_ = sendRequest(t, client, protocol.Frame{Type: "hello", RequestID: "req_hello", Version: "1.0", Payload: hello})
	response := sendRequest(t, client, request("req_create", "op_create_large", json.RawMessage(`{"action":"create","name":"large-replay","columns":80,"rows":24}`)))
	var created struct {
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Payload, &created); err != nil || created.Result.ID == "" {
		t.Fatalf("create=%s err=%v", response.Payload, err)
	}
	// Let the PTY output enter retained history before attaching.
	time.Sleep(100 * time.Millisecond)
	attachPayload, _ := json.Marshal(map[string]any{"action": "attach", "session_id": created.Result.ID, "from_sequence": 0})
	response = sendRequest(t, client, request("req_attach", "op_attach_large", attachPayload))
	if response.Type != "response" || len(response.Payload) > protocol.MaxStructuredFrame/8 || bytes.Contains(response.Payload, []byte(`"events"`)) {
		t.Fatalf("attach response=%d bytes payload=%s", len(response.Payload), response.Payload)
	}
	frame, err := protocol.ReadBinaryFrame(client)
	if err != nil || frame.Channel != protocol.Stdout || len(frame.Data) == 0 {
		t.Fatalf("binary=%#v err=%v", frame, err)
	}
	_ = client.Close()
}

func sendRequest(t *testing.T, conn net.Conn, frame protocol.Frame) protocol.Frame {
	t.Helper()
	if err := protocol.WriteFrame(conn, frame); err != nil {
		t.Fatal(err)
	}
	response, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestVerticalFramedTerminalPreviewAndReadiness(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("requires /bin/sh")
	}
	server := verticalServer(t)
	client, peer := net.Pipe()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(peer) }()
	payload := json.RawMessage(`{"min_version":"1.0","max_version":"1.0","capabilities":["terminal.v1","health.v1","preview.public.v1"]}`)
	response := sendRequest(t, client, protocol.Frame{Type: "hello", RequestID: "req_hello", Version: "1.0", Payload: payload})
	if response.Type != "welcome" {
		t.Fatalf("welcome=%#v", response)
	}

	create := request("req_create", "op_create_0001", json.RawMessage(`{"action":"create","name":"default","cwd":".","columns":80,"rows":24}`))
	response = sendRequest(t, client, create)
	if response.Type != "response" {
		t.Fatalf("create=%s", response.Payload)
	}
	var envelope struct {
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Payload, &envelope); err != nil || envelope.Result.ID == "" {
		t.Fatalf("create payload=%s err=%v", response.Payload, err)
	}

	previewFrame := request("req_preview", "op_preview_0001", json.RawMessage(`{"action":"register","logical_name":"web","target_host":"127.0.0.1","target_port":3000,"public_acknowledgement":true}`))
	previewFrame.Capability = "preview.public.v1"
	if response = sendRequest(t, client, previewFrame); response.Type != "response" {
		t.Fatalf("preview=%s", response.Payload)
	}

	healthFrame := request("req_health", "op_health_0001", json.RawMessage(`{}`))
	healthFrame.Capability = "health.v1"
	if response = sendRequest(t, client, healthFrame); response.Type != "response" {
		t.Fatalf("health=%s", response.Payload)
	}

	closeFrame := request("req_close", "op_close_0001", json.RawMessage(`{"action":"close","session_id":"`+envelope.Result.ID+`"}`))
	if response = sendRequest(t, client, closeFrame); response.Type != "response" {
		t.Fatalf("close=%s", response.Payload)
	}
	_ = client.Close()
	<-serveDone
}

func TestDispatcherRejectsEscapedCWDAndOverriddenPreviewIdentity(t *testing.T) {
	server := verticalServer(t)
	client, peer := net.Pipe()
	go server.Serve(peer)
	payload := json.RawMessage(`{"min_version":"1.0","max_version":"1.0","capabilities":["terminal.v1","health.v1"]}`)
	_ = sendRequest(t, client, protocol.Frame{Type: "hello", RequestID: "req_hello", Version: "1.0", Payload: payload})

	previewFrame := request("req_preview", "op_preview_0001", json.RawMessage(`{"action":"register","identity":"p-attacker-controlled-identity","logical_name":"web","target_host":"127.0.0.1","target_port":3000,"public_acknowledgement":true}`))
	previewFrame.Capability = "preview.public.v1"
	if response := sendRequest(t, client, previewFrame); response.Type != "error" {
		t.Fatalf("overridden preview identity=%#v", response)
	}
	escape := filepath.Join("..", "outside")
	createPayload, _ := json.Marshal(map[string]any{"action": "create", "name": "bad", "cwd": escape, "columns": 80, "rows": 24})
	if response := sendRequest(t, client, request("req_create", "op_create_0001", createPayload)); response.Type != "error" {
		t.Fatalf("escaped cwd=%#v", response)
	}
}
