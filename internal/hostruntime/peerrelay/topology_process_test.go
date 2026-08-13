package peerrelay

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat/internal/api"
	clientconfig "github.com/pinksaucepasta/paperboat/internal/config"
	hostauth "github.com/pinksaucepasta/paperboat/internal/hostruntime/auth"
	hostcodex "github.com/pinksaucepasta/paperboat/internal/hostruntime/codexsession"
	hostconfig "github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/execprocess"
	hostfiletransfer "github.com/pinksaucepasta/paperboat/internal/hostruntime/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	identitystore "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/operation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/process"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/pty"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/session"
	hoststore "github.com/pinksaucepasta/paperboat/internal/hostruntime/store"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkmonitor"
	peerpreview "github.com/pinksaucepasta/paperboat/internal/peertransport/privatepreview"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/relaycarrier"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
	"golang.org/x/crypto/ssh"
)

type topologyDescriptorSource struct {
	descriptor api.PeerAttemptDescriptor
	directory  string
	seen       map[string]bool
	mu         sync.Mutex
	emitted    bool
}

func (s *topologyDescriptorSource) Next(ctx context.Context) (api.PeerAttemptDescriptor, error) {
	s.mu.Lock()
	if !s.emitted {
		s.emitted = true
		s.mu.Unlock()
		return s.descriptor, nil
	}
	s.mu.Unlock()
	if s.directory == "" {
		<-ctx.Done()
		return api.PeerAttemptDescriptor{}, ctx.Err()
	}
	for {
		entries, err := os.ReadDir(s.directory)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() || entry.Name() == "descriptor.json" || !strings.HasPrefix(entry.Name(), "descriptor-") || !strings.HasSuffix(entry.Name(), ".json") {
					continue
				}
				encoded, readErr := os.ReadFile(filepath.Join(s.directory, entry.Name()))
				var next api.PeerAttemptDescriptor
				if readErr == nil && json.Unmarshal(encoded, &next) == nil && next.IntentID != "" && !s.seen[next.IntentID] {
					s.mu.Lock()
					s.descriptor = next
					s.seen[next.IntentID] = true
					s.mu.Unlock()
					fmt.Printf("PAPERBOAT_TOPOLOGY_HOST_DESCRIPTOR intent=%s purpose=%s\n", next.IntentID, next.Purpose)
					return next, nil
				}
			}
		}
		select {
		case <-time.After(25 * time.Millisecond):
		case <-ctx.Done():
			return api.PeerAttemptDescriptor{}, ctx.Err()
		}
	}
}

func TestTopologyHostServiceProcess(t *testing.T) {
	role := os.Getenv("PAPERBOAT_TOPOLOGY_HOST_ROLE")
	if role != "service-wss-responder" && role != "terminal-ping-wss-responder" && !topologyTerminalResponderRole(role) {
		t.Skip("topology host service process mode is not configured")
	}
	processTimeout := 30 * time.Second
	if strings.HasPrefix(role, "ssh-") {
		processTimeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), processTimeout)
	defer cancel()
	var descriptor api.PeerAttemptDescriptor
	var stateRoot string
	var sshHost *managedssh.Host
	var closeSSH func()
	if strings.HasPrefix(role, "file-reverse-") {
		stateRoot = topologyPreparePingHostState(t)
	} else if strings.HasPrefix(role, "ssh-") {
		stateRoot = topologyPreparePingHostState(t)
		sshHost, closeSSH = newTopologySSHHost(t, ctx)
		t.Cleanup(closeSSH)
		descriptor = topologyFinishPingHostDescriptor(t, ctx, stateRoot)
	} else if role == "terminal-ping-wss-responder" || topologyTerminalResponderRole(role) {
		descriptor, stateRoot = topologyPingHostDescriptor(t, ctx)
	} else {
		descriptor, stateRoot = topologyHostServiceDescriptor(t)
		writeTopologyJSON(t, topologyAuthorityPath(), descriptor)
	}
	served := make(chan error, 3)
	serve := func(connection net.Conn) error {
		payload := make([]byte, 1)
		_, readErr := io.ReadFull(connection, payload)
		if readErr == nil {
			_, readErr = connection.Write(payload)
		}
		served <- readErr
		return readErr
	}
	if topologyTerminalResponderRole(role) {
		serve = newTopologyTerminalServe(t, ctx, stateRoot, sshHost)
	}
	var fingerprints *networkmonitor.Monitor
	if role == "terminal-direct-quic-responder" || role == "terminal-cancel-direct-quic-responder" || role == "exec-direct-quic-responder" || role == "ssh-direct-quic-responder" || role == "codex-direct-quic-responder" || role == "preview-direct-quic-responder" || role == "file-direct-quic-responder" || role == "file-reverse-direct-quic-responder" {
		store, err := identitystore.Open(identitystore.Config{StateRoot: stateRoot})
		if err != nil {
			t.Fatal(err)
		}
		secret, err := store.NetworkFingerprintSecret()
		if err != nil {
			t.Fatal(err)
		}
		fingerprints, err = networkmonitor.NewFingerprinting(secret, nil, func(networkmonitor.Event) {})
		clear(secret)
		if err != nil {
			t.Fatal(err)
		}
		if err := fingerprints.Start(); err != nil {
			t.Fatal(err)
		}
		defer fingerprints.Close()
	}
	var transferKeys *transfercrypto.KeyVault
	var transferService *hostfiletransfer.Service
	var serveTransfer func(context.Context, net.Conn) error
	if topologyFileResponderRole(role) {
		var transferHandler http.Handler
		transferKeys, transferService, transferHandler = newTopologyFileTransferHandler(t, ctx, stateRoot)
		if strings.HasPrefix(role, "file-reverse-") {
			stageTopologyReverseFileTransfer(t, ctx, transferKeys, transferService, role)
		}
		serveTransfer = func(serveCtx context.Context, connection net.Conn) error {
			return server.ServeHTTPConnection(serveCtx, connection, transferHandler)
		}
		if role != "file-direct-quic-responder" {
			listener, listenErr := net.Listen("tcp4", "0.0.0.0:8080")
			if listenErr != nil {
				t.Fatal(listenErr)
			}
			transferHTTP := &http.Server{Handler: transferHandler, ReadHeaderTimeout: 2 * time.Second}
			go func() { _ = transferHTTP.Serve(listener) }()
			t.Cleanup(func() { _ = transferHTTP.Shutdown(context.Background()) })
		}
	}
	if strings.HasPrefix(role, "file-reverse-") {
		descriptor = topologyFinishPingHostDescriptor(t, ctx, stateRoot)
	}
	var serveCodex func(context.Context, net.Conn) error
	if strings.HasPrefix(role, "codex-") {
		serveCodex = newTopologyCodexServe(t, stateRoot)
	}
	var servePreview func(context.Context, net.Conn) error
	if strings.HasPrefix(role, "preview-") {
		servePreview = newTopologyPrivatePreviewServe(t, ctx)
	}
	var dialWSS func(context.Context, relaycarrier.WSSDialConfig) (*relaycarrier.Connection, error)
	var dialQUIC func(context.Context, relaycarrier.QUICDialConfig) (*relaycarrier.Connection, error)
	if role != "terminal-relay-quic-responder" && role != "terminal-cancel-relay-quic-responder" && role != "exec-relay-quic-responder" && role != "ssh-relay-quic-responder" && role != "codex-relay-quic-responder" && role != "preview-relay-quic-responder" {
		dialQUIC = func(dialCtx context.Context, _ relaycarrier.QUICDialConfig) (*relaycarrier.Connection, error) {
			<-dialCtx.Done()
			return nil, dialCtx.Err()
		}
	}
	if role == "terminal-direct-quic-responder" || role == "terminal-cancel-direct-quic-responder" || role == "exec-direct-quic-responder" || role == "ssh-direct-quic-responder" || role == "codex-direct-quic-responder" || role == "preview-direct-quic-responder" || role == "file-direct-quic-responder" || role == "file-reverse-direct-quic-responder" {
		dialWSS = func(dialCtx context.Context, _ relaycarrier.WSSDialConfig) (*relaycarrier.Connection, error) {
			<-dialCtx.Done()
			return nil, dialCtx.Err()
		}
	}
	descriptorSource := &topologyDescriptorSource{descriptor: descriptor}
	if strings.HasPrefix(role, "codex-") || strings.HasPrefix(role, "preview-") || strings.HasPrefix(role, "ssh-") {
		descriptorSource.directory = "/authority"
		descriptorSource.seen = map[string]bool{descriptor.IntentID: true}
	}
	service, err := New(Config{
		Source: descriptorSource, Fingerprints: fingerprints,
		StateRoot: stateRoot, TLS: topologyRelayTLS(t), Serve: serve, ServeTransfer: serveTransfer, ServeCodex: serveCodex, ServePreview: servePreview, TransferKeys: transferKeys, Dial: dialWSS, DialQUIC: dialQUIC, AttemptLimit: 32,
		ObserveError: func(err error) { fmt.Printf("PAPERBOAT_TOPOLOGY_HOST_ATTEMPT_ERROR %v\n", err) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := service.Shutdown(shutdownCtx); err != nil {
			t.Error(err)
		}
	}()
	if role == "terminal-ping-wss-responder" {
		var pingOK bool
		readTopologyJSON(t, ctx, topologyPingOKPath(), &pingOK)
		if !pingOK {
			t.Fatal("peer terminal ping did not complete")
		}
	} else if topologyTerminalResponderRole(role) {
		var workflowOK bool
		completionPath := topologyTerminalOKPath()
		if strings.HasPrefix(role, "codex-") {
			completionPath = "/authority/codex-ok.json"
		} else if strings.HasPrefix(role, "preview-") {
			completionPath = "/authority/preview-ok.json"
		}
		readTopologyJSON(t, ctx, completionPath, &workflowOK)
		if !workflowOK {
			t.Fatal("peer workflow did not complete")
		}
		if strings.HasPrefix(role, "file-reverse-") {
			transferID, batchID := topologyReverseTransferIDs(role)
			transfers, err := transferService.Batch(ctx, batchID)
			if err != nil || len(transfers) != 1 || transfers[0].State != "delivered" || transfers[0].ReceiptPath != "Paperboat Inbox/reverse-canary.txt" {
				t.Fatalf("reverse transfers=%+v error=%v", transfers, err)
			}
			if material, err := transferKeys.Load(transferID, 1); !errors.Is(err, transfercrypto.ErrKeyUnavailable) {
				material.Destroy()
				t.Fatalf("sender transfer key remains after receipt: %v", err)
			}
		} else if topologyFileResponderRole(role) {
			content, err := os.ReadFile(filepath.Join(stateRoot, "inbox", "file-canary.txt"))
			if err != nil || string(content) != "paperboat-file-canary" {
				t.Fatalf("file content=%q error=%v", content, err)
			}
		} else if strings.HasPrefix(role, "codex-") {
			fmt.Println("PAPERBOAT_TOPOLOGY_CODEX_HOST_OK")
		} else if strings.HasPrefix(role, "ssh-") {
			fmt.Println("PAPERBOAT_TOPOLOGY_SSH_HOST_OK")
		} else if strings.HasPrefix(role, "preview-") {
			fmt.Println("PAPERBOAT_TOPOLOGY_PREVIEW_HOST_OK")
		}
	} else {
		for range 3 {
			if err := <-served; err != nil {
				t.Fatal(err)
			}
		}
	}
	if role == "terminal-ping-wss-responder" {
		fmt.Println("PAPERBOAT_TOPOLOGY_TERMINAL_PING_HOST_OK")
	} else if topologyTerminalResponderRole(role) {
		fmt.Println("PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK")
	} else {
		fmt.Println("PAPERBOAT_TOPOLOGY_HOST_SERVICE_WSS_OK")
	}
	waitTopologyExitGate(t, ctx)
}

func topologyTerminalResponderRole(role string) bool {
	switch role {
	case "terminal-wss-responder", "terminal-cancel-wss-responder", "terminal-relay-quic-responder", "terminal-cancel-relay-quic-responder", "terminal-direct-quic-responder", "terminal-cancel-direct-quic-responder", "exec-wss-responder", "exec-relay-quic-responder", "exec-direct-quic-responder", "ssh-wss-responder", "ssh-relay-quic-responder", "ssh-direct-quic-responder", "codex-wss-responder", "codex-relay-quic-responder", "codex-direct-quic-responder", "preview-wss-responder", "preview-relay-quic-responder", "preview-direct-quic-responder", "file-direct-quic-responder", "file-reverse-relay-h3-responder", "file-reverse-direct-quic-responder", "file-reverse-relay-h2-responder", "file-relay-h3-responder", "file-relay-h2-responder":
		return true
	default:
		return false
	}
}

func topologyFileResponderRole(role string) bool {
	return role == "file-direct-quic-responder" || strings.HasPrefix(role, "file-reverse-") || role == "file-relay-h3-responder" || role == "file-relay-h2-responder"
}

type topologyClock struct{}

func (topologyClock) Now() time.Time { return time.Now().UTC() }

type topologyCredentialKeys struct{ public ed25519.PublicKey }

func (keys topologyCredentialKeys) Lookup(_ context.Context, keyID string) (ed25519.PublicKey, bool, error) {
	if keyID != "peer-integration" {
		return nil, false, nil
	}
	return append(ed25519.PublicKey(nil), keys.public...), true, nil
}

func (topologyCredentialKeys) Refresh(context.Context) error { return nil }

type topologyTerminalPolicy struct{}

func (topologyTerminalPolicy) Policy(frame protocol.Frame) (hostauth.Policy, error) {
	if frame.Capability == "codex.manage.v1" {
		return hostauth.Policy{Issuer: "https://authority.paperboat.test:9445", Audience: "paperboat-machine", CredentialClass: "codex_manage", Scopes: []string{"codex:prepare", "codex:browse", "codex:renew", "codex:stop"}, EnvironmentID: "environment-topology", UserID: "account-topology", CLIClientSessionID: "endpoint-cli", MachineID: "endpoint-host", SessionID: "cdx_topology", MaxLifetime: 5 * time.Minute}, nil
	}
	if frame.Capability == "codex.connect.v1" {
		return hostauth.Policy{Issuer: "https://authority.paperboat.test:9445", Audience: "paperboat-machine", CredentialClass: "codex_connect", Scopes: []string{"codex:connect"}, EnvironmentID: "environment-topology", UserID: "account-topology", CLIClientSessionID: "endpoint-cli", MachineID: "endpoint-host", SessionID: "cdx_topology", MaxLifetime: 5 * time.Minute}, nil
	}
	if frame.Capability == "file-transfer.v1" {
		return hostauth.Policy{Issuer: "https://authority.paperboat.test:9445", Audience: "paperboat-machine", CredentialClass: "file_transfer", Scopes: []string{"file:transfer"}, EnvironmentID: "environment-topology", UserID: "account-topology", CLIClientSessionID: "endpoint-cli", MachineID: "endpoint-host", SourceMachineID: "endpoint-cli", MaxLifetime: 5 * time.Minute}, nil
	}
	if frame.Capability == "exec.v1" {
		return hostauth.Policy{Issuer: "https://authority.paperboat.test:9445", Audience: "paperboat-machine", CredentialClass: "exec_operation", Scopes: []string{"exec:operate"}, EnvironmentID: "environment-topology", MachineID: "endpoint-host", OperationID: frame.OperationID, MaxLifetime: 5 * time.Minute}, nil
	}
	if frame.Capability == "ssh.v1" {
		return hostauth.Policy{Issuer: "https://authority.paperboat.test:9445", Audience: "paperboat-machine", CredentialClass: "ssh_operation", Scopes: []string{"ssh:operate"}, EnvironmentID: "environment-topology", MachineID: "endpoint-host", OperationID: frame.OperationID, MaxLifetime: 5 * time.Minute}, nil
	}
	if frame.Capability != "terminal.v1" && frame.Capability != "health.v1" {
		return hostauth.Policy{}, server.ErrCredentialPolicy
	}
	return hostauth.Policy{Issuer: "https://authority.paperboat.test:9445", Audience: "paperboat-machine", CredentialClass: "terminal_operation", Scopes: []string{"terminal:operate"}, EnvironmentID: "environment-topology", MachineID: "endpoint-host", MaxLifetime: 5 * time.Minute}, nil
}

type topologyCodexCommand struct {
	socket   string
	listener net.Listener
	done     chan error
}

func (c *topologyCodexCommand) Start() error {
	listener, err := net.Listen("unix", c.socket)
	if err != nil {
		return err
	}
	c.listener = listener
	c.done = make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, acceptErr := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if acceptErr != nil {
			return
		}
		defer connection.Close(websocket.StatusNormalClosure, "complete")
		messageType, payload, readErr := connection.Read(r.Context())
		if readErr == nil {
			_ = connection.Write(r.Context(), messageType, append([]byte("paperboat-codex-host:"), payload...))
		}
	})
	go func() { c.done <- http.Serve(listener, handler) }()
	return nil
}

func (c *topologyCodexCommand) Wait() error            { return <-c.done }
func (c *topologyCodexCommand) Signal(os.Signal) error { return c.listener.Close() }
func (c *topologyCodexCommand) Kill() error            { return c.listener.Close() }

func newTopologyCodexServe(t *testing.T, stateRoot string) func(context.Context, net.Conn) error {
	t.Helper()
	workspace := "/workspace"
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	manager, err := hostcodex.New(hostcodex.Config{
		StateRoot: filepath.Join(stateRoot, "codex"), WorkspaceRoot: workspace,
		Preflight: func(context.Context) (string, error) { return "0.146.0", nil },
		Command: func(_ context.Context, _ string, args ...string) hostcodex.Command {
			socket := strings.TrimPrefix(args[len(args)-1], "unix://")
			return &topologyCodexCommand{socket: socket}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	public := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{'i'}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	verifier := hostauth.Verifier{Keys: topologyCredentialKeys{public: public}, Clock: topologyClock{}, ClockSkew: time.Minute}
	authorizer := func(token string) (server.Authorizer, error) {
		return &server.CredentialAuthorizer{Verifier: verifier, Resolver: topologyTerminalPolicy{}, Token: token}, nil
	}
	websocketHandler, err := hostcodex.NewHandler(hostcodex.HandlerConfig{Manager: manager, Authorizer: authorizer})
	if err != nil {
		t.Fatal(err)
	}
	managementHandler, err := hostcodex.NewManagementHandler(manager, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/codex-sessions/{session_id}/ws", websocketHandler)
	mux.Handle("POST /v1/codex-sessions/{session_id}", managementHandler)
	mux.Handle("POST /v1/codex-sessions/{session_id}/renew", managementHandler)
	mux.Handle("GET /v1/codex-sessions/{session_id}/directories", managementHandler)
	mux.Handle("DELETE /v1/codex-sessions/{session_id}", managementHandler)
	return func(ctx context.Context, connection net.Conn) error {
		return server.ServeHTTPConnection(ctx, connection, mux)
	}
}

func newTopologyFileTransferHandler(t *testing.T, ctx context.Context, stateRoot string) (*transfercrypto.KeyVault, *hostfiletransfer.Service, http.Handler) {
	t.Helper()
	vault, err := transfercrypto.NewKeyVault(clientconfig.FileSecretStore{Dir: filepath.Join(stateRoot, "transfer-keys")})
	if err != nil {
		t.Fatal(err)
	}
	durable, err := hoststore.Open(ctx, hoststore.Config{Root: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = durable.Close() })
	service, err := hostfiletransfer.New(hostfiletransfer.Config{Root: filepath.Join(stateRoot, "file-transfers"), LocalMachineID: "endpoint-host", Store: durable, PublishRoot: filepath.Join(stateRoot, "inbox")})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := operation.NewJournal(32)
	if err != nil {
		t.Fatal(err)
	}
	public := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{'i'}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	verifier := hostauth.Verifier{Keys: topologyCredentialKeys{public: public}, Clock: topologyClock{}, ClockSkew: time.Minute}
	authorizer := func(token string) (server.Authorizer, error) {
		return &server.CredentialAuthorizer{Verifier: verifier, Resolver: topologyTerminalPolicy{}, Token: token}, nil
	}
	handler, err := server.NewFileTransferHandler(server.FileTransferHandlerConfig{Service: service, Journal: journal, Authorizer: authorizer, TransferKeys: vault, AuthorizeCreate: func(authorization server.Authorization, request server.CreateFileTransferRequest) bool {
		return authorization.MachineID == "endpoint-host" && authorization.SourceMachineID == "endpoint-cli" && authorization.UserID == "account-topology" && request.SourceMachineID == "endpoint-cli" && request.DestinationMachineID == "endpoint-host" && request.InitiatingUserID == "account-topology"
	}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })
	mux.Handle("/v1/file-transfers", handler)
	mux.Handle("/v1/file-transfers/", handler)
	return vault, service, mux
}

func newTopologyPrivatePreviewServe(t *testing.T, _ context.Context) func(context.Context, net.Conn) error {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /http", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Paperboat-Preview", "private")
		_, _ = io.WriteString(w, "paperboat-private-preview-http")
	})
	mux.HandleFunc("GET /sse", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: paperboat-private-preview-sse\n\n")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	})
	mux.HandleFunc("GET /ws", func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer connection.Close(websocket.StatusNormalClosure, "complete")
		messageType, payload, err := connection.Read(r.Context())
		if err == nil {
			_ = connection.Write(r.Context(), messageType, append([]byte("paperboat-private-preview-host:"), payload...))
		}
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	done := make(chan error, 1)
	go func() { done <- httpServer.Serve(listener) }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		<-done
	})
	return func(serveCtx context.Context, connection net.Conn) error {
		return peerpreview.Serve(serveCtx, connection, (&net.Dialer{}).DialContext)
	}
}

func stageTopologyReverseFileTransfer(t *testing.T, ctx context.Context, vault *transfercrypto.KeyVault, service *hostfiletransfer.Service, role string) {
	t.Helper()
	transferID, batchID := topologyReverseTransferIDs(role)
	content := []byte("paperboat-reverse-file-canary")
	digest := sha256.Sum256(content)
	created, err := service.Create(ctx, hostfiletransfer.CreateRequest{BatchID: batchID, SourceMachineID: "endpoint-host", DestinationMachineID: "endpoint-cli", InitiatingUserID: "account-topology", SessionID: "session-topology", DeliveryClientID: "endpoint-cli", E2EETransferID: transferID, TransferGeneration: 1, Files: []hostfiletransfer.File{{ID: transferID + ".0", Basename: "reverse-canary.txt", Size: int64(len(content)), SHA256: fmt.Sprintf("%x", digest), Ordinal: 0}}})
	if err != nil || len(created) != 1 {
		t.Fatalf("create reverse transfer=%+v error=%v", created, err)
	}
	material, err := transfercrypto.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	defer material.Destroy()
	if err := vault.Save(transferID, 1, material, created[0].ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Append(ctx, created[0].ID, 0, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if completed, err := service.Complete(ctx, created[0].ID); err != nil || completed.State != "pending" {
		t.Fatalf("complete reverse transfer=%+v error=%v", completed, err)
	}
}

func topologyReverseTransferIDs(role string) (string, string) {
	suffix := "h3"
	if strings.Contains(role, "direct-quic") {
		suffix = "direct"
	} else if strings.Contains(role, "relay-h2") {
		suffix = "h2"
	}
	return "fb_topology_reverse_" + suffix, "batch_topology_reverse_" + suffix
}

func newTopologyTerminalServe(t *testing.T, ctx context.Context, stateRoot string, sshHost *managedssh.Host) func(net.Conn) error {
	t.Helper()
	workspace := filepath.Join(stateRoot, "workspace")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	shell := filepath.Join(stateRoot, "topology-shell")
	if err := os.WriteFile(shell, []byte("#!/bin/sh\nstty -echo\nread line\nprintf 'paperboat:%s\\n' \"$line\"\nif [ \"$line\" = hold ]; then sleep 30; fi\nexit 7\n"), 0o500); err != nil {
		t.Fatal(err)
	}
	adapter, err := pty.NewAdapter(workspace)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := session.NewManager(session.ManagerConfig{Launch: func(command pty.Command) (session.PTYProcess, error) { return adapter.Start(command) }, MaxSessions: 2, MaxAttachments: 2, MaxInputDecisions: 32})
	if err != nil {
		t.Fatal(err)
	}
	launcher, err := process.NewShellLauncher(shell, []string{"HOME=" + workspace, "PATH=/usr/bin:/bin", "SHELL=" + shell, "TERM=xterm-256color"}, sessions)
	if err != nil {
		t.Fatal(err)
	}
	executions, err := execprocess.New(execprocess.Config{WorkspaceRoot: workspace, BaseEnvironment: []string{"HOME=" + workspace, "PATH=/usr/bin:/bin", "LANG=C"}, MaximumActive: 2, MaximumOperations: 8, ReplayBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	if sshHost == nil {
		var closeSSH func()
		sshHost, closeSSH = newTopologySSHHost(t, ctx)
		t.Cleanup(closeSSH)
	}
	readiness := health.New("topology", []string{"terminal.v1", "health.v1", "exec.v1", "ssh.v1"}, nil)
	readiness.Set("terminal.v1", health.Ready, "", 0)
	readiness.Set("health.v1", health.Ready, "", 0)
	readiness.Set("exec.v1", health.Ready, "", 0)
	readiness.Set("ssh.v1", health.Ready, "", 0)
	dispatcher, err := server.NewDispatcher(server.DispatcherConfig{Sessions: sessions, Health: readiness, SessionLauncher: launcher, WorkspaceRoot: workspace, Random: rand.Reader, Exec: executions, SSH: sshHost})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := operation.NewJournal(32)
	if err != nil {
		t.Fatal(err)
	}
	protocolServer, err := server.New(server.Config{Negotiator: protocol.Negotiator{Profile: hostconfig.BYOD, Available: map[string]bool{"terminal.v1": true, "health.v1": true, "exec.v1": true, "ssh.v1": true}}, Journal: journal, Handler: dispatcher, MaxConcurrent: hostconfig.DefaultResources.MaxConcurrentOps, HeartbeatInterval: time.Hour, MutationDeadline: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocolServer.Start(ctx); err != nil {
		t.Fatal(err)
	}
	public := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{'i'}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	verifier := hostauth.Verifier{Keys: topologyCredentialKeys{public: public}, Clock: topologyClock{}, ClockSkew: time.Minute}
	authorizer := func(token string) (server.Authorizer, error) {
		if token == "" {
			return nil, server.ErrCredentialPolicy
		}
		return &server.CredentialAuthorizer{Verifier: verifier, Resolver: topologyTerminalPolicy{}, Token: token}, nil
	}
	limiter, err := server.NewConnectionLimiter(hostconfig.DefaultResources.MaxAttachments * hostconfig.DefaultResources.MaxSessions)
	if err != nil {
		t.Fatal(err)
	}
	native, err := server.NewNativeAssociationManager(server.NativeAssociationConfig{Server: protocolServer, Authorizer: authorizer, Limiter: limiter})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = protocolServer.Shutdown(shutdownCtx)
		_ = sessions.Shutdown(shutdownCtx)
	})
	return native.Serve
}

func newTopologySSHHost(t *testing.T, ctx context.Context) (*managedssh.Host, func()) {
	t.Helper()
	root := filepath.Join(os.TempDir(), "paperboat-system-sshd")
	if err := os.MkdirAll(filepath.Join(root, "run"), 0o700); err != nil {
		t.Fatal(err)
	}
	hostPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{92}, ed25519.SeedSize))
	hostPEM, err := ssh.MarshalPrivateKey(hostPrivate, "")
	if err != nil {
		t.Fatal(err)
	}
	hostKeyPath := filepath.Join(root, "ssh_host_ed25519_key")
	if err := os.WriteFile(hostKeyPath, pem.EncodeToMemory(hostPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	clientPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, ed25519.SeedSize))
	clientPublic, err := ssh.NewPublicKey(clientPrivate.Public())
	if err != nil {
		t.Fatal(err)
	}
	existingPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{90}, ed25519.SeedSize))
	existingPublic, err := ssh.NewPublicKey(existingPrivate.Public())
	if err != nil {
		t.Fatal(err)
	}
	authorizedKeysPath := filepath.Join(root, "authorized_keys")
	authorizedKeys := append(ssh.MarshalAuthorizedKey(clientPublic), ssh.MarshalAuthorizedKey(existingPublic)...)
	if err := os.WriteFile(authorizedKeysPath, authorizedKeys, 0o600); err != nil {
		t.Fatal(err)
	}
	clientPEM, err := ssh.MarshalPrivateKey(clientPrivate, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/authority/ssh-client-key", pem.EncodeToMemory(clientPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	existingPEM, err := ssh.MarshalPrivateKey(existingPrivate, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/authority/ssh-existing-client-key", pem.EncodeToMemory(existingPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	hostPublic, err := ssh.NewPublicKey(hostPrivate.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/authority/ssh-host-key.pub", ssh.MarshalAuthorizedKey(hostPublic), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/authority/ssh-known-hosts", append([]byte("paperboat "), ssh.MarshalAuthorizedKey(hostPublic)...), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "sshd_config")
	password := exec.Command("chpasswd")
	password.Stdin = strings.NewReader("root:paperboat-topology-password\n")
	if output, err := password.CombinedOutput(); err != nil {
		t.Fatalf("set topology SSH password: %v: %s", err, output)
	}
	config := "Port 18022\nListenAddress 127.0.0.1\nHostKey " + hostKeyPath + "\nAuthorizedKeysFile " + authorizedKeysPath + "\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\nPermitRootLogin yes\nStrictModes no\nUsePAM no\nPidFile " + filepath.Join(root, "sshd.pid") + "\nLogLevel ERROR\nSubsystem sftp internal-sftp\nAllowTcpForwarding yes\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("/run/sshd", 0o755); err != nil {
		t.Fatal(err)
	}
	forwardListener, err := net.Listen("tcp4", "127.0.0.1:18081")
	if err != nil {
		t.Fatal(err)
	}
	forwardServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "paperboat-ssh-forward-canary")
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = forwardServer.Serve(forwardListener) }()
	command := exec.CommandContext(ctx, "/usr/sbin/sshd", "-D", "-e", "-f", configPath)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	host, err := managedssh.NewHost(managedssh.HostConfig{MaxStreams: 32, ProbeTimeout: time.Second, DialTimeout: time.Second})
	if err != nil {
		_ = command.Process.Kill()
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := host.ReconcileTarget(ctx, 1, 18022); err == nil {
			break
		} else if time.Now().After(deadline) {
			_ = command.Process.Kill()
			t.Fatalf("system sshd did not become ready: %v: %s", err, stderr.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	return host, func() {
		_ = forwardServer.Close()
		_ = command.Process.Kill()
		err := <-done
		if err != nil && !strings.Contains(err.Error(), "signal: killed") && ctx.Err() == nil {
			t.Errorf("system sshd exit: %v: %s", err, stderr.String())
		}
	}
}

type topologyHostEnrollment struct {
	Generation     uint64 `json:"generation"`
	NoisePublicKey string `json:"noise_public_key"`
	QUICPublicKey  string `json:"quic_public_key"`
}

func topologyPingHostDescriptor(t *testing.T, ctx context.Context) (api.PeerAttemptDescriptor, string) {
	t.Helper()
	stateRoot := topologyPreparePingHostState(t)
	return topologyFinishPingHostDescriptor(t, ctx, stateRoot), stateRoot
}

func topologyPreparePingHostState(t *testing.T) string {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	stateRoot := filepath.Join(os.TempDir(), "paperboat-host-state")
	store, err := identitystore.Open(identitystore.Config{StateRoot: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	identityKey := store.Current()
	registration := identitystore.Registration{ServerURL: "https://api.paperboat.test", MachineID: "endpoint-host", EnvironmentID: "environment-topology", PublicKeyID: identityKey.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(identityKey.Public()), InboxPath: filepath.Join(stateRoot, "inbox"), InstallationGeneration: 1, SetupRoles: []string{"host"}, UpdatedAt: now}
	if err := store.SaveRegistration(registration); err != nil {
		t.Fatal(err)
	}
	local, err := store.PeerEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	noisePublic := local.NoisePublicKey()
	writeTopologyJSON(t, topologyHostEnrollmentPath(), topologyHostEnrollment{Generation: local.Generation, NoisePublicKey: base64.RawURLEncoding.EncodeToString(noisePublic[:]), QUICPublicKey: base64.RawURLEncoding.EncodeToString(local.QUICPublicKey())})
	return stateRoot
}

func topologyFinishPingHostDescriptor(t *testing.T, ctx context.Context, stateRoot string) api.PeerAttemptDescriptor {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	store, err := identitystore.Open(identitystore.Config{StateRoot: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	registration, err := store.Registration()
	if err != nil {
		t.Fatal(err)
	}
	descriptor := api.PeerAttemptDescriptor{}
	readTopologyJSON(t, ctx, topologyAuthorityPath(), &descriptor)
	var machineRaw []byte
	for _, certificate := range descriptor.EndpointCertificates {
		if certificate.EndpointID == registration.MachineID {
			decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(certificate.Certificate)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			machineRaw = decoded
			break
		}
	}
	var rootPublicEncoded string
	readTopologyJSON(t, ctx, topologyRootPath(), &rootPublicEncoded)
	rootPublicRaw, err := base64.RawURLEncoding.Strict().DecodeString(rootPublicEncoded)
	if err != nil || len(rootPublicRaw) != ed25519.PublicKeySize || len(machineRaw) == 0 {
		t.Fatal("topology host certificate authority is invalid")
	}
	if err := store.SavePeerEndpointCertificate(ed25519.PublicKey(rootPublicRaw), machineRaw, now); err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func writeTopologyJSON(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, path); err != nil {
		t.Fatal(err)
	}
}

func readTopologyJSON(t *testing.T, ctx context.Context, path string, value any) {
	t.Helper()
	for {
		encoded, err := os.ReadFile(path)
		if err == nil {
			if err := json.Unmarshal(encoded, value); err != nil {
				t.Fatal(err)
			}
			return
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-time.After(25 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func topologyHostServiceDescriptor(t *testing.T) (api.PeerAttemptDescriptor, string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	stateRoot := filepath.Join(os.TempDir(), "paperboat-host-state")
	store, err := identitystore.Open(identitystore.Config{StateRoot: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	identityKey := store.Current()
	registration := identitystore.Registration{ServerURL: "https://api.paperboat.test", MachineID: "endpoint-host", EnvironmentID: "environment-topology", PublicKeyID: identityKey.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(identityKey.Public()), InboxPath: filepath.Join(stateRoot, "inbox"), InstallationGeneration: 1, SetupRoles: []string{"host"}, UpdatedAt: now}
	if err := store.SaveRegistration(registration); err != nil {
		t.Fatal(err)
	}
	local, err := store.PeerEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	rootPrivate := topologyHostRootPrivate()
	initiatorPrivate := topologyHostInitiatorNoisePrivate(t)
	initiatorPublic := topologyNoisePublic(t, initiatorPrivate)
	initiatorQUICPublic := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{63}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	initiatorCertificate, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: "account-topology", Role: endpointidentity.RoleCLI, EndpointID: "endpoint-cli", NoisePublicKey: initiatorPublic, QUICPublicKey: initiatorQUICPublic, Generation: 1, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	responderCertificate, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: "account-topology", Role: endpointidentity.RoleMachine, EndpointID: registration.MachineID, NoisePublicKey: local.NoisePublicKey(), QUICPublicKey: local.QUICPublicKey(), Generation: 1, Serial: 2, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	initiatorRaw, err := initiatorCertificate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	responderRaw, err := responderCertificate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SavePeerEndpointCertificate(rootPrivate.Public().(ed25519.PublicKey), responderRaw, now); err != nil {
		t.Fatal(err)
	}
	descriptor := api.PeerAttemptDescriptor{Version: 1, AccountID: "account-topology", DeviceID: "endpoint-cli", OperationID: "operation-topology", IntentID: "intent-topology", EnvironmentID: registration.EnvironmentID, Purpose: "interactive", Consumer: "terminal", InitiatorEndpointID: "endpoint-cli", ResponderEndpointID: registration.MachineID, Role: "controlled", AttemptGeneration: 1, NetworkGeneration: 1, HostGeneration: 1, AuthorizationGeneration: 1, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), EndpointCertificates: []api.PeerAttemptCertificate{{EndpointID: "endpoint-cli", Certificate: base64.RawURLEncoding.EncodeToString(initiatorRaw)}, {EndpointID: registration.MachineID, Certificate: base64.RawURLEncoding.EncodeToString(responderRaw)}}}
	descriptor.Relays = []api.PeerAttemptRelay{{Region: "relay-topology", RouteGeneration: 1, WSSURL: os.Getenv("PAPERBOAT_TOPOLOGY_RELAY_URL"), RouteToken: "relay.payload.signature", ExpiresAt: descriptor.ExpiresAt}}
	descriptor.Policy.AllowedPaths = []string{"relay_wss"}
	descriptor.Policy.RelayDeadlineMS = 10_000
	return descriptor, stateRoot
}

func topologyHostRootPrivate() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize))
}

func topologyHostInitiatorNoisePrivate(t *testing.T) [32]byte {
	t.Helper()
	private, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{17}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var result [32]byte
	copy(result[:], private.Bytes())
	return result
}

func topologyNoisePublic(t *testing.T, private [32]byte) [32]byte {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		t.Fatal(err)
	}
	var result [32]byte
	copy(result[:], key.PublicKey().Bytes())
	return result
}

func topologyRelayTLS(t *testing.T) *tls.Config {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize))
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "relay.paperboat.test"}, NotBefore: time.Unix(1_577_836_800, 0), NotAfter: time.Unix(4_102_444_800, 0), DNSNames: []string{"relay.paperboat.test", "machine.paperboat.test"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "relay.paperboat.test"}
}

func waitTopologyExitGate(t *testing.T, ctx context.Context) {
	t.Helper()
	gate := os.Getenv("PAPERBOAT_TOPOLOGY_RELAY_EXIT_GATE")
	if gate == "" {
		return
	}
	for {
		if _, err := os.Stat(gate); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-time.After(25 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func topologyAuthorityPath() string      { return "/authority/descriptor.json" }
func topologyHostEnrollmentPath() string { return "/authority/host-enrollment.json" }
func topologyRootPath() string           { return "/authority/root-public.json" }
func topologyPingOKPath() string         { return "/authority/ping-ok.json" }
func topologyTerminalOKPath() string     { return "/authority/terminal-ok.json" }
