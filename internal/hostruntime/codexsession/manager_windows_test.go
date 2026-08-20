//go:build windows

package codexsession

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWindowsAppServerEndpointIsLoopbackWebSocket(t *testing.T) {
	endpoint, listen, err := codexAppServerEndpoint(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != listen {
		t.Fatalf("endpoint %q and listen %q differ", endpoint, listen)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "ws" || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" {
		t.Fatalf("endpoint %q is not a loopback websocket endpoint", endpoint)
	}
	listener, err := net.Listen("tcp", parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/readyz" {
			http.NotFound(writer, request)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Shutdown(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitCodexAppServer(ctx, endpoint, time.Second); err != nil {
		t.Fatalf("wait for loopback app server: %v", err)
	}
}

func TestWindowsCodexEndpointRejectsNonLoopbackDial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := dialCodexAppServer(ctx, "ws://127.0.0.2:4040"); err == nil {
		t.Fatal("accepted a non-approved Codex endpoint")
	}
}

func TestWindowsManagerPrepareStartsLoopbackAppServer(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	var command *windowsReadyCommand
	manager, err := New(Config{
		StateRoot: state, WorkspaceRoot: root, ReadinessTimeout: time.Second,
		Preflight: func(context.Context) (string, error) { return "1.2.3", nil },
		Command: func(_ context.Context, _ string, args ...string) Command {
			command = &windowsReadyCommand{args: append([]string(nil), args...), done: make(chan struct{})}
			return command
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := manager.Prepare(context.Background(), "session_1", "", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(descriptor.SocketPath, "ws://127.0.0.1:") {
		t.Fatalf("endpoint = %q", descriptor.SocketPath)
	}
	if command == nil || len(command.args) != 3 || command.args[0] != "app-server" || command.args[1] != "--listen" || command.args[2] != descriptor.SocketPath {
		t.Fatalf("app-server arguments = %#v", command.args)
	}
	if err := manager.Stop(context.Background(), "session_1"); err != nil {
		t.Fatal(err)
	}
}

type windowsReadyCommand struct {
	args     []string
	listener net.Listener
	server   *http.Server
	done     chan struct{}
	once     sync.Once
}

func (c *windowsReadyCommand) Start() error {
	if len(c.args) != 3 || c.args[0] != "app-server" || c.args[1] != "--listen" {
		return ErrInvalid
	}
	parsed, err := url.Parse(c.args[2])
	if err != nil {
		return err
	}
	c.listener, err = net.Listen("tcp", parsed.Host)
	if err != nil {
		return err
	}
	c.server = &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/readyz" {
			writer.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(writer, request)
	})}
	go func() { _ = c.server.Serve(c.listener) }()
	return nil
}

func (c *windowsReadyCommand) Wait() error            { <-c.done; return nil }
func (c *windowsReadyCommand) Signal(os.Signal) error { c.close(); return nil }
func (c *windowsReadyCommand) Kill() error            { c.close(); return nil }
func (c *windowsReadyCommand) close() {
	c.once.Do(func() {
		if c.server != nil {
			_ = c.server.Close()
		}
		close(c.done)
	})
}
