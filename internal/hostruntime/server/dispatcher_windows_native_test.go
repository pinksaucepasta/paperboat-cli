//go:build windows && paperboat_native_e2e

package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/operation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/process"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/pty"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/session"
)

type nativeWindowsSessionLauncher struct {
	sessions *session.Manager
	shell    string
	args     []string
}

func (launcher nativeWindowsSessionLauncher) Launch(ctx context.Context, request process.LaunchRequest) (session.Snapshot, error) {
	return launcher.sessions.Create(ctx, session.CreateRequest{
		ID:   request.ID,
		Name: request.Name,
		Command: pty.Command{
			Path:       launcher.shell,
			Args:       append([]string(nil), launcher.args...),
			CWD:        request.CWD,
			Dimensions: request.Dimensions,
		},
	})
}

func nativeWindowsProtocolServer(t *testing.T, shellArgs []string) *Server {
	t.Helper()
	root := t.TempDir()
	adapter, err := pty.NewAdapter(root)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := session.NewManager(session.ManagerConfig{
		Launch:          func(command pty.Command) (session.PTYProcess, error) { return adapter.Start(command) },
		MaxSessions:     4,
		HistoryBytes:    1 << 20,
		AttachmentBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	shell := os.Getenv("ComSpec")
	if shell == "" {
		shell = filepath.Join(os.Getenv("WINDIR"), "System32", "cmd.exe")
	}
	readiness := health.New("test", []string{"terminal.v1", "health.v1"}, nil)
	readiness.Set("terminal.v1", health.Ready, "", 0)
	readiness.Set("health.v1", health.Ready, "", 0)
	dispatcher, err := NewDispatcher(DispatcherConfig{
		Sessions:        sessions,
		Health:          readiness,
		SessionLauncher: nativeWindowsSessionLauncher{sessions: sessions, shell: shell, args: shellArgs},
		WorkspaceRoot:   root,
		Random:          bytes.NewReader(bytes.Repeat([]byte{1}, 256)),
	})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := operation.NewJournal(32)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		Negotiator: protocol.Negotiator{Profile: config.BYOD, Available: map[string]bool{"terminal.v1": true, "health.v1": true}},
		Journal:    journal,
		Authorizer: authorizerFunc(func(context.Context, protocol.Frame) (Authorization, error) {
			return Authorization{JournalBinding: "env:native:user:owner", EnvironmentID: "native", UserID: "owner", ClientID: "windows-client"}, nil
		}),
		Handler: dispatcher, MaxConcurrent: 4, HeartbeatInterval: time.Hour, MutationDeadline: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = sessions.Shutdown(ctx)
	})
	return server
}

func TestNativeWindowsAuthenticatedTerminalProtocolOutputAndExit(t *testing.T) {
	server := nativeWindowsProtocolServer(t, []string{"/D", "/Q", "/C", "echo PB_PROTOCOL& exit /b 7"})
	client, peer := net.Pipe()
	defer client.Close()
	go func() { _ = server.Serve(peer) }()

	hello := json.RawMessage(`{"min_version":"1.0","max_version":"1.0","capabilities":["terminal.v1","health.v1"]}`)
	if welcome := sendRequest(t, client, protocol.Frame{Type: "hello", RequestID: "req_hello", Version: "1.0", Payload: hello}); welcome.Type != "welcome" {
		t.Fatalf("welcome=%#v", welcome)
	}
	created := sendRequest(t, client, request("req_create", "op_create", json.RawMessage(`{"action":"create","name":"protocol","columns":80,"rows":24}`)))
	var createEnvelope struct {
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(created.Payload, &createEnvelope); err != nil || createEnvelope.Result.ID == "" {
		t.Fatalf("create=%s err=%v", created.Payload, err)
	}
	attachPayload, _ := json.Marshal(map[string]any{"action": "attach", "session_id": createEnvelope.Result.ID, "from_sequence": 0})
	if attached := sendRequest(t, client, request("req_attach", "op_attach", attachPayload)); attached.Type != "response" {
		t.Fatalf("attach=%s", attached.Payload)
	}

	reader := bufio.NewReader(client)
	var output strings.Builder
	var end protocol.Frame
	for {
		header, err := reader.Peek(5)
		if err != nil {
			t.Fatal(err)
		}
		if header[4] == '{' {
			end, err = protocol.ReadFrame(reader)
			if err != nil {
				t.Fatal(err)
			}
			break
		}
		binary, err := protocol.ReadBinaryFrame(reader)
		if err != nil || binary.Channel != protocol.Stdout {
			t.Fatalf("binary=%#v err=%v", binary, err)
		}
		output.Write(binary.Data)
	}
	if !strings.Contains(output.String(), "PB_PROTOCOL") || end.Type != "event" || end.Capability != "terminal.v1" {
		t.Fatalf("output=%q end=%#v", output.String(), end)
	}
	var endPayload struct {
		Event string `json:"event"`
		State string `json:"state"`
		Exit  struct {
			Code int `json:"code"`
		} `json:"exit"`
	}
	if err := json.Unmarshal(end.Payload, &endPayload); err != nil || endPayload.Event != "terminal_stream_end" || endPayload.State != "exited" || endPayload.Exit.Code != 7 {
		t.Fatalf("end payload=%s err=%v", end.Payload, err)
	}
}
