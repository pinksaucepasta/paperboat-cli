package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/inbox"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/connectionmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
	"github.com/pinksaucepasta/paperboat/internal/privatepreviewproxy"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
	"github.com/quic-go/quic-go/http3"
)

const topologyControlURL = "https://authority.paperboat.test:9445"

type topologyAuthSource struct{ credential config.Credential }

func (s topologyAuthSource) Credential() (config.Credential, error) { return s.credential, nil }

type topologyHostEnrollment struct {
	Generation     uint64 `json:"generation"`
	NoisePublicKey string `json:"noise_public_key"`
	QUICPublicKey  string `json:"quic_public_key"`
}

type topologyEndpointMaterial struct {
	RootPublic         string                          `json:"root_public"`
	LocalCertificate   string                          `json:"local_certificate"`
	MachineCertificate string                          `json:"machine_certificate"`
	LocalNoisePublic   string                          `json:"local_noise_public"`
	LocalQUICPublic    string                          `json:"local_quic_public"`
	MachineNoisePublic string                          `json:"machine_noise_public"`
	MachineQUICPublic  string                          `json:"machine_quic_public"`
	MachineDocument    api.EndpointCertificateDocument `json:"machine_document"`
}

type topologyTerminalCredential struct {
	Token string `json:"token"`
}

type topologyCodexCredential struct {
	ManageToken  string `json:"manage_token"`
	ConnectToken string `json:"connect_token"`
}

func TestTopologyPeerTerminalPingProcess(t *testing.T) {
	role := os.Getenv("PAPERBOAT_TOPOLOGY_TERMINAL_ROLE")
	if role != "terminal-ping-wss-initiator" && role != "terminal-ping-auto-initiator" && role != "terminal-ping-auto-fenced-initiator" && role != "terminal-wss-initiator" && role != "terminal-cancel-wss-initiator" && role != "terminal-relay-quic-initiator" && role != "terminal-cancel-relay-quic-initiator" && role != "terminal-direct-quic-initiator" && role != "terminal-cancel-direct-quic-initiator" && role != "exec-wss-initiator" && role != "exec-relay-quic-initiator" && role != "exec-direct-quic-initiator" && role != "ssh-wss-initiator" && role != "ssh-relay-quic-initiator" && role != "ssh-direct-quic-initiator" && role != "codex-wss-initiator" && role != "codex-relay-quic-initiator" && role != "codex-direct-quic-initiator" && role != "preview-wss-initiator" && role != "preview-relay-quic-initiator" && role != "preview-direct-quic-initiator" && role != "file-direct-quic-initiator" && role != "file-reverse-relay-h3-initiator" && role != "file-reverse-direct-quic-initiator" && role != "file-reverse-relay-h2-initiator" && role != "file-relay-h3-initiator" && role != "file-relay-h2-initiator" {
		t.Skip("topology peer terminal process mode is not configured")
	}
	processTimeout := 30 * time.Second
	if strings.HasPrefix(role, "ssh-") {
		processTimeout = 90 * time.Second
	} else if strings.HasPrefix(role, "preview-") {
		processTimeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), processTimeout)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Second)
	profileRoot := filepath.Join(os.TempDir(), "paperboat-cli-profile")
	store := config.ProfileStore{Path: profileRoot, Secrets: config.FileSecretStore{Dir: filepath.Join(profileRoot, "secrets")}}
	credential := config.Credential{AccessToken: "access.payload.signature", RefreshToken: "refresh.payload.signature", TokenType: "Bearer", ExpiresAt: now.Add(time.Hour)}
	if err := store.Save(config.Profile{Issuer: topologyControlURL, Account: config.Account{ID: "account-topology"}, CLIClientSessionID: "endpoint-cli", AccessExpiresAt: credential.ExpiresAt}, credential); err != nil {
		t.Fatal(err)
	}
	keys, err := store.PeerIdentityKeys(topologyControlURL, "account-topology", "endpoint-cli")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keys.RootPrivate)
	defer clear(keys.NoisePrivate[:])
	defer clear(keys.QUICPrivate)
	rootPublic := keys.RootPrivate.Public().(ed25519.PublicKey)
	writeTopologyJSON(t, topologyRootPath(), base64.RawURLEncoding.EncodeToString(rootPublic))
	var enrollment topologyHostEnrollment
	readTopologyJSON(t, ctx, topologyHostEnrollmentPath(), &enrollment)
	hostNoise, err := base64.RawURLEncoding.Strict().DecodeString(enrollment.NoisePublicKey)
	hostQUIC, errQUIC := base64.RawURLEncoding.Strict().DecodeString(enrollment.QUICPublicKey)
	if err != nil || errQUIC != nil || enrollment.Generation != 1 || len(hostNoise) != 32 || len(hostQUIC) != ed25519.PublicKeySize {
		t.Fatal("topology host enrollment is invalid")
	}
	var hostNoisePublic [32]byte
	copy(hostNoisePublic[:], hostNoise)
	localCertificate, err := endpointidentity.Sign(keys.RootPrivate, endpointidentity.Claims{AccountID: "account-topology", Role: endpointidentity.RoleCLI, EndpointID: "endpoint-cli", NoisePublicKey: keys.NoisePublic, QUICPublicKey: keys.QUICPrivate.Public().(ed25519.PublicKey), Generation: 1, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	machineCertificate, err := endpointidentity.Sign(keys.RootPrivate, endpointidentity.Claims{AccountID: "account-topology", Role: endpointidentity.RoleMachine, EndpointID: "endpoint-host", NoisePublicKey: hostNoisePublic, QUICPublicKey: ed25519.PublicKey(hostQUIC), Generation: 1, Serial: 2, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	localRaw, err := localCertificate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	machineRaw, err := machineCertificate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SavePeerCertificate(topologyControlURL, "endpoint-cli", localRaw); err != nil {
		t.Fatal(err)
	}
	machineDocument := topologyCertificateDocument(rootPublic, machineCertificate, machineRaw)
	writeTopologyJSON(t, topologyEndpointMaterialPath(), topologyEndpointMaterial{
		RootPublic:         base64.RawURLEncoding.EncodeToString(rootPublic),
		LocalCertificate:   base64.RawURLEncoding.EncodeToString(localRaw),
		MachineCertificate: base64.RawURLEncoding.EncodeToString(machineRaw),
		LocalNoisePublic:   base64.RawURLEncoding.EncodeToString(keys.NoisePublic[:]),
		LocalQUICPublic:    base64.RawURLEncoding.EncodeToString(keys.QUICPrivate.Public().(ed25519.PublicKey)),
		MachineNoisePublic: enrollment.NoisePublicKey,
		MachineQUICPublic:  enrollment.QUICPublicKey,
		MachineDocument:    machineDocument,
	})
	readTopologyJSON(t, ctx, topologyAuthorityReadyPath(), new(bool))
	peer := newTopologyPeerTunnel(t, role, store, credential)
	if strings.HasPrefix(role, "exec-") {
		runTopologyExec(t, ctx, peer)
		waitTopologyExitGate(t, ctx)
		return
	}
	if strings.HasPrefix(role, "ssh-") {
		runTopologySSH(t, ctx, peer)
		waitTopologyExitGate(t, ctx)
		return
	}
	if strings.HasPrefix(role, "codex-") {
		runTopologyCodex(t, ctx, peer)
		waitTopologyExitGate(t, ctx)
		return
	}
	if strings.HasPrefix(role, "preview-") {
		runTopologyPrivatePreview(t, ctx, peer)
		waitTopologyExitGate(t, ctx)
		return
	}
	if strings.HasPrefix(role, "file-") {
		runTopologyFileTransfer(t, ctx, peer, store, role)
		waitTopologyExitGate(t, ctx)
		return
	}
	if role != "terminal-ping-wss-initiator" && role != "terminal-ping-auto-initiator" && role != "terminal-ping-auto-fenced-initiator" {
		var terminalCredential topologyTerminalCredential
		readTopologyJSON(t, ctx, topologyTerminalCredentialPath(), &terminalCredential)
		if terminalCredential.Token == "" {
			t.Fatal("topology terminal credential is empty")
		}
		var sequence atomic.Int64
		target := &resolver.TerminalTarget{Protocol: "paperboat.peer.v1", EnvironmentID: "environment-topology", SessionID: "session-topology", Cols: 80, Rows: 24, Auth: resolver.AuthTarget{Method: "bearer", Token: terminalCredential.Token}, SequenceSink: func(value int) { sequence.Store(int64(value)) }}
		dialCtx := ctx
		cancelDial := func() {}
		cancelWorkflow := strings.Contains(role, "terminal-cancel-")
		if cancelWorkflow {
			dialCtx, cancelDial = context.WithCancel(ctx)
		}
		defer cancelDial()
		connection, dialErr := peer.Dial(dialCtx, resolver.ConnectInfo{TargetKind: "machine", ProjectID: "endpoint-host", Project: "host-topology", ProjectState: "running", MachineGeneration: 1, Terminal: target})
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		if err := connection.Resize(31, 101); err != nil {
			t.Fatal(err)
		}
		if cancelWorkflow {
			if written, err := connection.Write([]byte("hold\n")); err != nil || written != len("hold\n") {
				t.Fatalf("terminal write=%d error=%v", written, err)
			}
			observed := make(chan error, 1)
			go func() {
				buffer := make([]byte, 256)
				var output []byte
				for !bytes.Contains(output, []byte("paperboat:hold")) {
					n, readErr := connection.Read(buffer)
					output = append(output, buffer[:n]...)
					if readErr != nil {
						observed <- fmt.Errorf("terminal output %q: %w", output, readErr)
						return
					}
				}
				observed <- nil
			}()
			select {
			case err := <-observed:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			cancelDial()
			waited := make(chan error, 1)
			go func() {
				_, waitErr := connection.Wait()
				waited <- waitErr
			}()
			select {
			case waitErr := <-waited:
				if waitErr == nil {
					t.Fatal("canceled terminal returned a successful exit")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("canceled terminal did not unblock wait")
			}
			if err := connection.Close(); err != nil {
				t.Fatal(err)
			}
			writeTopologyJSON(t, topologyTerminalOKPath(), true)
			fmt.Println("PAPERBOAT_TOPOLOGY_PEER_TERMINAL_CANCEL_OK")
			waitTopologyExitGate(t, ctx)
			return
		}
		if written, err := connection.Write([]byte("hello\n")); err != nil || written != len("hello\n") {
			t.Fatalf("terminal write=%d error=%v", written, err)
		}
		output := make(chan struct {
			data []byte
			err  error
		}, 1)
		go func() {
			data, readErr := io.ReadAll(connection)
			output <- struct {
				data []byte
				err  error
			}{data, readErr}
		}()
		var terminalOutput struct {
			data []byte
			err  error
		}
		select {
		case terminalOutput = <-output:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if terminalOutput.err != nil || !strings.Contains(string(terminalOutput.data), "paperboat:hello") {
			t.Fatalf("terminal output=%q error=%v", terminalOutput.data, terminalOutput.err)
		}
		if exit, err := connection.Wait(); err != nil || exit != 7 {
			t.Fatalf("terminal exit=%d error=%v", exit, err)
		}
		if sequence.Load() <= 0 {
			t.Fatal("terminal output sequence was not committed")
		}
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
		writeTopologyJSON(t, topologyTerminalOKPath(), true)
		fmt.Println("PAPERBOAT_TOPOLOGY_PEER_TERMINAL_OK")
		waitTopologyExitGate(t, ctx)
		return
	}
	result, err := peer.PingOnce(ctx, resolver.ConnectInfo{TargetKind: "machine", ProjectID: "endpoint-host", Project: "host-topology", ProjectState: "running", MachineGeneration: 1, Terminal: &resolver.TerminalTarget{Protocol: "paperboat.peer.v1", EnvironmentID: "environment-topology"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.RTT <= 0 {
		t.Fatalf("ping result=%+v", result)
	}
	if role == "terminal-ping-wss-initiator" && (result.Path != connectionmanager.PathWSS || result.RelayRegion != "relay-topology") {
		t.Fatalf("ping result=%+v", result)
	}
	if (role == "terminal-ping-auto-initiator" || role == "terminal-ping-auto-fenced-initiator") && result.Path != connectionmanager.PathDirectQUIC && result.Path != connectionmanager.PathRelayQUIC && result.Path != connectionmanager.PathWSS {
		t.Fatalf("ping result=%+v", result)
	}
	if role == "terminal-ping-auto-fenced-initiator" && result.Path != connectionmanager.PathWSS {
		t.Fatalf("fenced auto ping did not fall back to WSS: %+v", result)
	}
	writeTopologyJSON(t, topologyPingOKPath(), true)
	fmt.Println("PAPERBOAT_TOPOLOGY_PEER_TERMINAL_PING_OK")
	waitTopologyExitGate(t, ctx)
}

func TestTopologySSHProxyProcess(t *testing.T) {
	operationID := os.Getenv("PAPERBOAT_TOPOLOGY_SSH_OPERATION_ID")
	role := os.Getenv("PAPERBOAT_TOPOLOGY_TERMINAL_ROLE")
	if operationID == "" || !strings.HasPrefix(role, "ssh-") {
		t.Skip("topology SSH proxy process mode is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	profileRoot := filepath.Join(os.TempDir(), "paperboat-cli-profile")
	store := config.ProfileStore{Path: profileRoot, Secrets: config.FileSecretStore{Dir: filepath.Join(profileRoot, "secrets")}}
	credential, err := store.CredentialFor(topologyControlURL)
	if err != nil {
		t.Fatal(err)
	}
	var credentials map[string]string
	readTopologyJSON(t, ctx, "/authority/ssh-credentials.json", &credentials)
	token := credentials[operationID]
	if token == "" {
		t.Fatalf("topology SSH credential is unavailable for %q", operationID)
	}
	peer := newTopologyPeerTunnel(t, role, store, credential)
	target := &resolver.TerminalTarget{Protocol: "paperboat.ssh.v1", EnvironmentID: "environment-topology", Auth: resolver.AuthTarget{Method: "bearer", Token: token}}
	connection, err := peer.DialSSH(ctx, resolver.ConnectInfo{TargetKind: "machine", ProjectID: "endpoint-host", Project: "host-topology", ProjectState: "running", MachineGeneration: 1, Terminal: target}, operationID)
	if err != nil {
		var uncertain *ExecStartUncertainError
		if errors.As(err, &uncertain) {
			t.Fatalf("dial SSH %s: %v (uncertain cause: %T %v)", operationID, err, uncertain.Cause, uncertain.Cause)
		}
		t.Fatalf("dial SSH %s: %v (cause: %T %v)", operationID, err, errors.Unwrap(err), errors.Unwrap(err))
	}
	defer connection.Close()
	halfCloser, ok := connection.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal(ErrInputEOFUnsupported)
	}
	inputDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(connection, os.Stdin)
		inputDone <- errors.Join(copyErr, halfCloser.CloseWrite())
	}()
	proxyOutput := os.NewFile(3, "paperboat-ssh-proxy-output")
	if proxyOutput == nil {
		t.Fatal("topology SSH proxy output descriptor is unavailable")
	}
	defer proxyOutput.Close()
	_, outputErr := io.Copy(proxyOutput, connection)
	if outputErr != nil && !errors.Is(outputErr, io.EOF) {
		t.Fatal(outputErr)
	}
	if inputErr := <-inputDone; inputErr != nil {
		t.Fatal(inputErr)
	}
}

func newTopologyPeerTunnel(t *testing.T, role string, store config.ProfileStore, credential config.Credential) *PeerTerminalTunnel {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: topologyControlTLS(t), Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	mode := connectionmanager.ModeWSS
	if strings.Contains(role, "ping-auto") {
		mode = connectionmanager.ModeAuto
	} else if strings.Contains(role, "relay-quic") {
		mode = connectionmanager.ModeRelayQUIC
	} else if strings.Contains(role, "direct-quic") {
		mode = connectionmanager.ModeDirectQUIC
	}
	peer, err := NewPeerTerminalTunnel(PeerTerminalConfig{Issuer: topologyControlURL, Store: store, Auth: topologyAuthSource{credential: credential}, TLS: topologyRelayTLS(t), HTTPClient: &http.Client{Transport: transport, Timeout: 15 * time.Second}, Mode: mode, Race: connectionmanager.Config{RelayDelay: 25 * time.Millisecond, WSSDelay: 50 * time.Millisecond, ConnectTimeout: 10 * time.Second}, Now: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	return peer
}

func runTopologyCodex(t *testing.T, ctx context.Context, peer *PeerTerminalTunnel) {
	t.Helper()
	var credential topologyCodexCredential
	readTopologyJSON(t, ctx, "/authority/codex-credential.json", &credential)
	if credential.ManageToken == "" || credential.ConnectToken == "" {
		t.Fatal("topology Codex credentials are empty")
	}
	info := resolver.ConnectInfo{TargetKind: "machine", ProjectID: "endpoint-host", Project: "host-topology", ProjectState: "running", MachineGeneration: 1, Terminal: &resolver.TerminalTarget{Protocol: "paperboat.peer.v1", EnvironmentID: "environment-topology"}}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, ResponseHeaderTimeout: 10 * time.Second}
	transport.DialTLSContext = func(dialCtx context.Context, _, _ string) (net.Conn, error) {
		return peer.DialCodexHTTP(dialCtx, info)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	lease := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://machine.paperboat.invalid/v1/codex-sessions/cdx_topology", strings.NewReader(`{"path":"/workspace","lease_expires_at":"`+lease+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+credential.ManageToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"codex_version":"0.146.0"`)) {
		t.Fatalf("Codex prepare status=%s body=%q error=%v", response.Status, body, readErr)
	}
	ws, _, err := websocket.Dial(ctx, "wss://machine.paperboat.invalid/v1/codex-sessions/cdx_topology/ws", &websocket.DialOptions{HTTPClient: &http.Client{Transport: transport}, HTTPHeader: http.Header{"Authorization": []string{"Bearer " + credential.ConnectToken}}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		t.Fatal(err)
	}
	const canary = "paperboat-codex-client-canary"
	if err := ws.Write(ctx, websocket.MessageText, []byte(canary)); err != nil {
		t.Fatal(err)
	}
	messageType, payload, err := ws.Read(ctx)
	if err != nil || messageType != websocket.MessageText || string(payload) != "paperboat-codex-host:"+canary {
		t.Fatalf("Codex websocket type=%d payload=%q error=%v", messageType, payload, err)
	}
	_ = ws.Close(websocket.StatusNormalClosure, "complete")
	writeTopologyJSON(t, "/authority/codex-ok.json", true)
	fmt.Println("PAPERBOAT_TOPOLOGY_PEER_CODEX_OK")
}

func runTopologyPrivatePreview(t *testing.T, ctx context.Context, peer *PeerTerminalTunnel) {
	t.Helper()
	target := resolver.ConnectInfo{TargetKind: "machine", ProjectID: "endpoint-host", Project: "host-topology", ProjectState: "running", MachineGeneration: 1, Terminal: &resolver.TerminalTarget{Protocol: "paperboat.private-preview.v1", EnvironmentID: "environment-topology"}}
	proxy, err := privatepreviewproxy.Start(ctx, privatepreviewproxy.Config{Dial: func(dialCtx context.Context) (io.ReadWriteCloser, error) {
		return peer.DialPrivatePreview(dialCtx, target, 18080)
	}, MaximumConnections: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(proxy.URL + "/http")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK || response.Header.Get("X-Paperboat-Preview") != "private" || string(body) != "paperboat-private-preview-http" {
		t.Fatalf("private preview HTTP status=%d header=%q body=%q error=%v", response.StatusCode, response.Header.Get("X-Paperboat-Preview"), body, readErr)
	}
	response, err = client.Get(proxy.URL + "/sse")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" || string(body) != "data: paperboat-private-preview-sse\n\n" {
		t.Fatalf("private preview SSE status=%d type=%q body=%q error=%v", response.StatusCode, response.Header.Get("Content-Type"), body, readErr)
	}
	websocketURL := "ws" + strings.TrimPrefix(proxy.URL, "http") + "/ws"
	connection, _, err := websocket.Dial(ctx, websocketURL, &websocket.DialOptions{HTTPClient: client, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		t.Fatal(err)
	}
	const canary = "paperboat-private-preview-websocket"
	if err := connection.Write(ctx, websocket.MessageText, []byte(canary)); err != nil {
		t.Fatal(err)
	}
	messageType, payload, err := connection.Read(ctx)
	if err != nil || messageType != websocket.MessageText || string(payload) != "paperboat-private-preview-host:"+canary {
		t.Fatalf("private preview websocket type=%d payload=%q error=%v", messageType, payload, err)
	}
	_ = connection.Close(websocket.StatusNormalClosure, "complete")
	writeTopologyJSON(t, "/authority/preview-ok.json", true)
	fmt.Println("PAPERBOAT_TOPOLOGY_PEER_PREVIEW_OK")
}

type topologyRoundTripFunc func(*http.Request) (*http.Response, error)

func (f topologyRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func runTopologyFileTransfer(t *testing.T, ctx context.Context, peer *PeerTerminalTunnel, store config.ProfileStore, role string) {
	t.Helper()
	var credential topologyTerminalCredential
	readTopologyJSON(t, ctx, topologyFileCredentialPath(), &credential)
	if credential.Token == "" {
		t.Fatal("topology file credential is empty")
	}
	vault, err := transfercrypto.NewKeyVault(store.Secrets)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := filetransfer.NewKeyCoordinator(vault, peer)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(role, "file-reverse-") {
		runTopologyReverseFileTransfer(t, ctx, peer, keys, vault, credential.Token, role)
		return
	}
	batchID := "fb_topology_" + strings.TrimSuffix(strings.TrimPrefix(role, "file-"), "-initiator")
	binding := transfercrypto.KeyControlBinding{OperationID: filetransfer.KeyOperationID(batchID), TransferID: batchID, Generation: 1, ExpiresAt: time.Now().UTC().Truncate(time.Second).Add(5 * time.Minute)}
	target := resolver.ConnectInfo{TargetKind: "machine", ProjectID: "endpoint-host", Project: "host-topology", ProjectState: "running", MachineGeneration: 1, Terminal: &resolver.TerminalTarget{Protocol: "paperboat.peer.v1", EnvironmentID: "environment-topology"}}
	prepared, err := keys.Prepare(ctx, target, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	defer prepared.Material.Destroy()
	if role == "file-direct-quic-initiator" && prepared.Direct == nil {
		t.Fatal("strict direct file transfer did not retain a direct data transport")
	}
	if role != "file-direct-quic-initiator" && prepared.Direct != nil {
		t.Fatal("relay file transfer unexpectedly retained a direct data transport")
	}
	var relayCalls atomic.Int64
	var relay http.RoundTripper = topologyRoundTripFunc(func(*http.Request) (*http.Response, error) {
		relayCalls.Add(1)
		return nil, errors.New("relay HTTP is forbidden in strict direct topology")
	})
	endpoint := "https://machine.paperboat.test/v1/file-transfers"
	if role != "file-direct-quic-initiator" {
		port := "9443"
		if role == "file-relay-h2-initiator" {
			port = "9442"
		}
		endpoint = "https://machine.paperboat.test:" + port + "/v1/file-transfers"
		tlsConfig := topologyRelayTLS(t)
		tlsConfig.ServerName = "machine.paperboat.test"
		h3 := &http3.Transport{TLSClientConfig: tlsConfig.Clone()}
		h2 := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: tlsConfig.Clone(), Proxy: nil}
		t.Cleanup(func() { _ = h3.Close(); h2.CloseIdleConnections() })
		selector, selectErr := filetransfer.NewTransportSelector(filetransfer.TransportSelectorConfig{H3: h3, H2: h2, Stagger: 25 * time.Millisecond, ProbeTimeout: 2 * time.Second})
		if selectErr != nil {
			t.Fatal(selectErr)
		}
		relay = selector
	}
	client := filetransfer.NewClient(endpoint, filetransfer.Auth{Token: credential.Token, ExpiresAt: time.Now().Add(5 * time.Minute)}, filetransfer.Binding{SourceMachineID: "endpoint-cli", DestinationMachineID: "endpoint-host", InitiatingUserID: "account-topology"}, &http.Client{Transport: relay, Timeout: 10 * time.Second})
	content := []byte("paperboat-file-canary")
	digest := sha256.Sum256(content)
	batch, err := client.SendEncryptedBatch(ctx, batchID, "", []filetransfer.Source{{Basename: "file-canary.txt", Size: int64(len(content)), SHA256: digest, Reader: bytes.NewReader(content)}}, 1, prepared)
	if err != nil {
		var transferErr *filetransfer.Error
		if errors.As(err, &transferErr) {
			t.Fatalf("file transfer status=%d code=%s retryable=%t request=%s: %v", transferErr.StatusCode, transferErr.Code, transferErr.Retryable, transferErr.RequestID, err)
		}
		t.Fatal(err)
	}
	if relayCalls.Load() != 0 || len(batch.Transfers) != 1 || batch.Transfers[0].State != "delivered" || batch.Transfers[0].CommittedOffset != int64(len(content)) || batch.Paths[0] != "Paperboat Inbox/file-canary.txt" {
		t.Fatalf("batch=%+v relay_calls=%d", batch, relayCalls.Load())
	}
	if err := keys.Erase(batchID); err != nil {
		t.Fatal(err)
	}
	writeTopologyJSON(t, topologyTerminalOKPath(), true)
	writeTopologyJSON(t, topologyFileOKPath(), true)
	marker := "PAPERBOAT_TOPOLOGY_PEER_FILE_DIRECT_OK"
	if role == "file-relay-h3-initiator" {
		marker = "PAPERBOAT_TOPOLOGY_PEER_FILE_H3_OK"
	} else if role == "file-relay-h2-initiator" {
		marker = "PAPERBOAT_TOPOLOGY_PEER_FILE_H2_OK"
	}
	fmt.Println(marker)
}

func runTopologyReverseFileTransfer(t *testing.T, ctx context.Context, peer *PeerTerminalTunnel, keys *filetransfer.KeyCoordinator, vault *transfercrypto.KeyVault, token, role string) {
	t.Helper()
	tlsConfig := topologyRelayTLS(t)
	tlsConfig.ServerName = "machine.paperboat.test"
	h3 := &http3.Transport{TLSClientConfig: tlsConfig.Clone()}
	h2 := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: tlsConfig.Clone(), Proxy: nil}
	t.Cleanup(func() { _ = h3.Close(); h2.CloseIdleConnections() })
	selector, err := filetransfer.NewTransportSelector(filetransfer.TransportSelectorConfig{H3: h3, H2: h2, Stagger: 25 * time.Millisecond, ProbeTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	port := "9443"
	transferID := "fb_topology_reverse_h3"
	marker := "PAPERBOAT_TOPOLOGY_PEER_FILE_REVERSE_H3_OK"
	if role == "file-reverse-relay-h2-initiator" {
		port = "9442"
		transferID = "fb_topology_reverse_h2"
		marker = "PAPERBOAT_TOPOLOGY_PEER_FILE_REVERSE_H2_OK"
	} else if role == "file-reverse-direct-quic-initiator" {
		transferID = "fb_topology_reverse_direct"
		marker = "PAPERBOAT_TOPOLOGY_PEER_FILE_REVERSE_DIRECT_OK"
	}
	client := filetransfer.NewClient("https://machine.paperboat.test:"+port+"/v1/file-transfers", filetransfer.Auth{Token: token, ExpiresAt: time.Now().Add(5 * time.Minute)}, filetransfer.Binding{SourceMachineID: "endpoint-cli", DestinationMachineID: "endpoint-host", InitiatingUserID: "account-topology"}, &http.Client{Transport: selector, Timeout: 10 * time.Second})
	batches, err := client.PendingEncrypted(ctx, "session-topology", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 1 || batches[0].TransferID != transferID || len(batches[0].Resources) != 1 {
		t.Fatalf("reverse pending batches=%+v", batches)
	}
	target := resolver.ConnectInfo{TargetKind: "machine", ProjectID: "endpoint-host", Project: "host-topology", ProjectState: "running", MachineGeneration: 1, Terminal: &resolver.TerminalTarget{Protocol: "paperboat.peer.v1", EnvironmentID: "environment-topology"}}
	destination := filepath.Join(t.TempDir(), "Paperboat Inbox")
	receiver, err := inbox.New(inbox.Config{Client: client, Encrypted: client, Keys: keys, Target: target, MachineID: "endpoint-host", SessionID: "session-topology", Path: destination})
	if err != nil {
		t.Fatal(err)
	}
	paths, err := receiver.DeliverEncrypted(ctx, batches[0])
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(destination, "reverse-canary.txt"))
	if err != nil || string(content) != "paperboat-reverse-file-canary" || len(paths) != 1 || paths[0] != "Paperboat Inbox/reverse-canary.txt" {
		t.Fatalf("reverse paths=%v content=%q error=%v", paths, content, err)
	}
	if material, err := vault.Load(batches[0].TransferID, batches[0].TransferGeneration); !errors.Is(err, transfercrypto.ErrKeyUnavailable) {
		material.Destroy()
		t.Fatalf("recipient transfer key remains after receipt: %v", err)
	}
	writeTopologyJSON(t, topologyTerminalOKPath(), true)
	writeTopologyJSON(t, topologyFileOKPath(), true)
	fmt.Println(marker)
}

func runTopologyExec(t *testing.T, ctx context.Context, peer *PeerTerminalTunnel) {
	t.Helper()
	var credential topologyTerminalCredential
	readTopologyJSON(t, ctx, topologyExecCredentialPath(), &credential)
	if credential.Token == "" {
		t.Fatal("topology exec credential is empty")
	}
	const operationID = "operation-exec-topology"
	target := &resolver.TerminalTarget{Protocol: "paperboat.peer.v1", EnvironmentID: "environment-topology", Auth: resolver.AuthTarget{Method: "bearer", Token: credential.Token}}
	connection, err := peer.DialExec(ctx, resolver.ConnectInfo{TargetKind: "machine", ProjectID: "endpoint-host", Project: "host-topology", ProjectState: "running", MachineGeneration: 1, Terminal: target}, ExecRequest{
		OperationID: operationID,
		Argv:        []string{"/bin/sh", "-c", "printf paperboat-exec-stdout; printf paperboat-exec-stderr >&2; exit 23"},
		CWD:         "/tmp/paperboat-host-state/workspace",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var stdout, stderr strings.Builder
	var lastEvent uint64
	for event := range connection.Events() {
		if event.OperationID != operationID || event.EventSequence < lastEvent {
			t.Fatalf("invalid exec event operation=%q sequence=%d after=%d", event.OperationID, event.EventSequence, lastEvent)
		}
		lastEvent = event.EventSequence
		switch event.Stream {
		case "stdout":
			stdout.Write(event.Data)
		case "stderr":
			stderr.Write(event.Data)
		}
	}
	exit, err := connection.Wait()
	if err != nil || exit != 23 || stdout.String() != "paperboat-exec-stdout" || stderr.String() != "paperboat-exec-stderr" {
		t.Fatalf("exec exit=%d error=%v stdout=%q stderr=%q", exit, err, stdout.String(), stderr.String())
	}
	writeTopologyJSON(t, topologyTerminalOKPath(), true)
	writeTopologyJSON(t, topologyExecOKPath(), true)
	fmt.Println("PAPERBOAT_TOPOLOGY_PEER_EXEC_OK")
}

func runTopologySSH(t *testing.T, ctx context.Context, peer *PeerTerminalTunnel) {
	t.Helper()
	_ = peer // OpenSSH reaches Paperboat through a fresh ProxyCommand process per connection.
	for _, path := range []string{"/authority/ssh-client-key", "/authority/ssh-known-hosts"} {
		deadline := time.Now().Add(10 * time.Second)
		for {
			if info, err := os.Stat(path); err == nil && info.Size() > 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("topology SSH material %s was not published", path)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	baseCommon := []string{"-F", "/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/authority/ssh-known-hosts", "-o", "ConnectTimeout=10"}
	common := append(append([]string{}, baseCommon...), "-i", "/authority/ssh-client-key", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes")
	proxy := func(operationID string) string {
		path := filepath.Join(t.TempDir(), "proxy-"+operationID)
		script := "#!/bin/sh\nPAPERBOAT_TOPOLOGY_SSH_OPERATION_ID=" + operationID + " exec " + executable + " -test.run '^TestTopologySSHProxyProcess$' 3>&1 1>&2\n"
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	run := func(name string, input []byte, arguments ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, name, arguments...)
		command.Stdin = bytes.NewReader(input)
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		if err := command.Run(); err != nil {
			t.Fatalf("%s %v failed: %v: stdout=%q stderr=%q", name, arguments, err, stdout.String(), stderr.String())
		}
		// The remote peer attempt closes asynchronously after ProxyCommand exits.
		// Keep independent tool proofs from becoming a teardown stress test.
		time.Sleep(150 * time.Millisecond)
		return stdout.Bytes()
	}
	sshArguments := append(append([]string{}, common...), "-o", "ProxyCommand="+proxy("operation-ssh-command"), "root@paperboat", "set -eu; printf paperboat-openssh-command; printf paperboat-scp-download >/tmp/paperboat-scp-download; rm -rf /tmp/paperboat.git; git init --bare -q /tmp/paperboat.git; blob=$(printf paperboat-git-canary | git --git-dir=/tmp/paperboat.git hash-object -w --stdin); tree=$(printf '100644 blob %s\\tcanary.txt\\n' \"$blob\" | git --git-dir=/tmp/paperboat.git mktree); commit=$(printf topology | git --git-dir=/tmp/paperboat.git -c user.name=Paperboat -c user.email=topology@paperboat.test commit-tree \"$tree\"); git --git-dir=/tmp/paperboat.git update-ref refs/heads/main \"$commit\"; git --git-dir=/tmp/paperboat.git symbolic-ref HEAD refs/heads/main")
	if output := run("ssh", nil, sshArguments...); string(output) != "paperboat-openssh-command" {
		t.Fatalf("OpenSSH command output=%q", output)
	}
	if role := os.Getenv("PAPERBOAT_TOPOLOGY_TERMINAL_ROLE"); role != "ssh-wss-initiator" {
		writeTopologyJSON(t, topologyTerminalOKPath(), true)
		writeTopologyJSON(t, "/authority/ssh-ok.json", true)
		fmt.Println("PAPERBOAT_TOPOLOGY_PEER_SSH_OK")
		return
	}
	forwardCtx, cancelForward := context.WithCancel(ctx)
	forwardArguments := append(append([]string{}, common...), "-o", "ProxyCommand="+proxy("operation-ssh-forward"), "-o", "ExitOnForwardFailure=yes", "-N", "-L", "127.0.0.1:18081:127.0.0.1:18081", "root@paperboat")
	forward := exec.CommandContext(forwardCtx, "ssh", forwardArguments...)
	var forwardOutput bytes.Buffer
	forward.Stdout, forward.Stderr = &forwardOutput, &forwardOutput
	if err := forward.Start(); err != nil {
		cancelForward()
		t.Fatal(err)
	}
	forwardReady := false
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, requestErr := client.Get("http://127.0.0.1:18081/forward")
		if requestErr == nil {
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK && string(body) == "paperboat-ssh-forward-canary" {
				forwardReady = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancelForward()
	_ = forward.Wait()
	if !forwardReady {
		t.Fatalf("OpenSSH forwarding failed: %s", forwardOutput.String())
	}
	time.Sleep(150 * time.Millisecond)
	reverseListener, err := net.Listen("tcp4", "127.0.0.1:18082")
	if err != nil {
		t.Fatal(err)
	}
	reverseServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "paperboat-ssh-reverse-forward-canary")
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = reverseServer.Serve(reverseListener) }()
	reverseArguments := append(append([]string{}, common...), "-o", "ProxyCommand="+proxy("operation-ssh-reverse-forward"), "-o", "ExitOnForwardFailure=yes", "-R", "127.0.0.1:18082:127.0.0.1:18082", "root@paperboat", "curl -fsS http://127.0.0.1:18082/reverse")
	if output := run("ssh", nil, reverseArguments...); string(output) != "paperboat-ssh-reverse-forward-canary" {
		t.Fatalf("OpenSSH reverse forwarding output=%q", output)
	}
	if err := reverseServer.Close(); err != nil {
		t.Fatal(err)
	}
	dynamicCtx, cancelDynamic := context.WithCancel(ctx)
	dynamicArguments := append(append([]string{}, common...), "-o", "ProxyCommand="+proxy("operation-ssh-dynamic-forward"), "-o", "ExitOnForwardFailure=yes", "-N", "-D", "127.0.0.1:18083", "root@paperboat")
	dynamic := exec.CommandContext(dynamicCtx, "ssh", dynamicArguments...)
	var dynamicOutput bytes.Buffer
	dynamic.Stdout, dynamic.Stderr = &dynamicOutput, &dynamicOutput
	if err := dynamic.Start(); err != nil {
		cancelDynamic()
		t.Fatal(err)
	}
	dynamicReady := false
	dynamicDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(dynamicDeadline) {
		probe := exec.CommandContext(ctx, "curl", "-fsS", "--max-time", "1", "--socks5-hostname", "127.0.0.1:18083", "http://127.0.0.1:18081/dynamic")
		if output, probeErr := probe.Output(); probeErr == nil && string(output) == "paperboat-ssh-forward-canary" {
			dynamicReady = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancelDynamic()
	_ = dynamic.Wait()
	if !dynamicReady {
		t.Fatalf("OpenSSH dynamic forwarding failed: %s", dynamicOutput.String())
	}
	time.Sleep(150 * time.Millisecond)
	upload := filepath.Join(t.TempDir(), "scp-upload.txt")
	if err := os.WriteFile(upload, []byte("paperboat-scp-upload"), 0o600); err != nil {
		t.Fatal(err)
	}
	scpUploadArguments := append(append([]string{}, common...), "-o", "ProxyCommand="+proxy("operation-ssh-scp-upload"), upload, "root@paperboat:/tmp/paperboat-scp-upload")
	run("scp", nil, scpUploadArguments...)
	download := filepath.Join(t.TempDir(), "scp-download.txt")
	scpDownloadArguments := append(append([]string{}, common...), "-o", "ProxyCommand="+proxy("operation-ssh-scp-download"), "root@paperboat:/tmp/paperboat-scp-download", download)
	run("scp", nil, scpDownloadArguments...)
	if content, err := os.ReadFile(download); err != nil || string(content) != "paperboat-scp-download" {
		t.Fatalf("SCP download content=%q error=%v", content, err)
	}
	sftpSource := filepath.Join(t.TempDir(), "sftp-source.txt")
	sftpDownload := filepath.Join(t.TempDir(), "sftp-download.txt")
	if err := os.WriteFile(sftpSource, []byte("paperboat-sftp-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	batch := []byte("put " + sftpSource + " /tmp/paperboat-sftp-upload\nget /tmp/paperboat-scp-upload " + sftpDownload + "\n")
	sftpArguments := append(append([]string{}, common...), "-o", "ProxyCommand="+proxy("operation-ssh-sftp"), "-b", "-", "root@paperboat")
	run("sftp", batch, sftpArguments...)
	if content, err := os.ReadFile(sftpDownload); err != nil || string(content) != "paperboat-scp-upload" {
		t.Fatalf("SFTP download content=%q error=%v", content, err)
	}
	clone := filepath.Join(t.TempDir(), "git-clone")
	gitSSH := strings.Join(append(append([]string{"ssh"}, common...), "-o", "ProxyCommand="+proxy("operation-ssh-git")), " ")
	git := exec.CommandContext(ctx, "git", "clone", "-q", "root@paperboat:/tmp/paperboat.git", clone)
	git.Env = append(os.Environ(), "GIT_SSH_COMMAND="+gitSSH)
	var gitOutput bytes.Buffer
	git.Stdout, git.Stderr = &gitOutput, &gitOutput
	if err := git.Run(); err != nil {
		t.Fatalf("git clone failed: %v: %s", err, gitOutput.String())
	}
	if content, err := os.ReadFile(filepath.Join(clone, "canary.txt")); err != nil || string(content) != "paperboat-git-canary" {
		t.Fatalf("Git-over-SSH content=%q error=%v", content, err)
	}
	rsyncSource := filepath.Join(t.TempDir(), "rsync-source.txt")
	if err := os.WriteFile(rsyncSource, []byte("paperboat-rsync-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	rsyncSSH := func(operationID string) string {
		return strings.Join(append(append([]string{"ssh"}, common...), "-o", "ProxyCommand="+proxy(operationID)), " ")
	}
	run("rsync", nil, "-a", "-e", rsyncSSH("operation-ssh-rsync-upload"), rsyncSource, "root@paperboat:/tmp/paperboat-rsync-upload")
	rsyncDownload := filepath.Join(t.TempDir(), "rsync-download.txt")
	run("rsync", nil, "-a", "-e", rsyncSSH("operation-ssh-rsync-download"), "root@paperboat:/tmp/paperboat-rsync-upload", rsyncDownload)
	if content, err := os.ReadFile(rsyncDownload); err != nil || string(content) != "paperboat-rsync-canary" {
		t.Fatalf("rsync-over-SSH content=%q error=%v", content, err)
	}
	existingKeyArguments := append(append([]string{}, baseCommon...), "-i", "/authority/ssh-existing-client-key", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ProxyCommand="+proxy("operation-ssh-existing-key"), "root@paperboat", "printf paperboat-existing-key-auth")
	if output := run("ssh", nil, existingKeyArguments...); string(output) != "paperboat-existing-key-auth" {
		t.Fatalf("existing-key OpenSSH output=%q", output)
	}
	askpass := filepath.Join(t.TempDir(), "ssh-askpass")
	if err := os.WriteFile(askpass, []byte("#!/bin/sh\nprintf '%s\\n' paperboat-topology-password\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	passwordArguments := append(append([]string{}, baseCommon...), "-o", "BatchMode=no", "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1", "-o", "ProxyCommand="+proxy("operation-ssh-password"), "root@paperboat", "printf paperboat-password-auth")
	passwordCommand := exec.CommandContext(ctx, "ssh", passwordArguments...)
	passwordCommand.Env = append(os.Environ(), "SSH_ASKPASS="+askpass, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=paperboat-topology:0")
	var passwordOutput, passwordError bytes.Buffer
	passwordCommand.Stdout, passwordCommand.Stderr = &passwordOutput, &passwordError
	if err := passwordCommand.Run(); err != nil {
		t.Fatalf("password OpenSSH failed: %v: stdout=%q stderr=%q", err, passwordOutput.String(), passwordError.String())
	}
	if passwordOutput.String() != "paperboat-password-auth" {
		t.Fatalf("password OpenSSH output=%q", passwordOutput.String())
	}
	agentSocket := filepath.Join(t.TempDir(), "agent.sock")
	agentCtx, cancelAgent := context.WithCancel(ctx)
	agentProcess := exec.CommandContext(agentCtx, "ssh-agent", "-D", "-a", agentSocket)
	var agentError bytes.Buffer
	agentProcess.Stderr = &agentError
	if err := agentProcess.Start(); err != nil {
		cancelAgent()
		t.Fatal(err)
	}
	agentDeadline := time.Now().Add(5 * time.Second)
	for {
		if info, statErr := os.Stat(agentSocket); statErr == nil && info.Mode()&os.ModeSocket != 0 {
			break
		}
		if time.Now().After(agentDeadline) {
			cancelAgent()
			_ = agentProcess.Wait()
			t.Fatalf("ssh-agent socket was not ready: %s", agentError.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	agentEnvironment := append(os.Environ(), "SSH_AUTH_SOCK="+agentSocket)
	add := exec.CommandContext(ctx, "ssh-add", "/authority/ssh-existing-client-key")
	add.Env = agentEnvironment
	if output, err := add.CombinedOutput(); err != nil {
		cancelAgent()
		_ = agentProcess.Wait()
		t.Fatalf("load forwarded SSH key: %v: %s", err, output)
	}
	public := exec.CommandContext(ctx, "ssh-keygen", "-y", "-f", "/authority/ssh-existing-client-key")
	expectedPublic, err := public.Output()
	if err != nil {
		cancelAgent()
		_ = agentProcess.Wait()
		t.Fatal(err)
	}
	agentArguments := append(append([]string{}, common...), "-A", "-o", "ProxyCommand="+proxy("operation-ssh-agent-forward"), "root@paperboat", "ssh-add -L")
	agentCommand := exec.CommandContext(ctx, "ssh", agentArguments...)
	agentCommand.Env = agentEnvironment
	forwardedPublic, err := agentCommand.Output()
	cancelAgent()
	_ = agentProcess.Wait()
	if err != nil {
		t.Fatalf("OpenSSH agent forwarding failed: %v: %s", err, forwardedPublic)
	}
	expectedFields, forwardedFields := strings.Fields(string(expectedPublic)), strings.Fields(string(forwardedPublic))
	if len(expectedFields) < 2 || len(forwardedFields) < 2 || expectedFields[0] != forwardedFields[0] || expectedFields[1] != forwardedFields[1] {
		t.Fatalf("forwarded SSH identity mismatch: expected=%q actual=%q", expectedPublic, forwardedPublic)
	}
	writeTopologyJSON(t, topologyTerminalOKPath(), true)
	writeTopologyJSON(t, "/authority/ssh-ok.json", true)
	fmt.Println("PAPERBOAT_TOPOLOGY_PEER_SSH_OK")
}

func topologyCertificateDocument(root ed25519.PublicKey, certificate endpointidentity.Certificate, raw []byte) api.EndpointCertificateDocument {
	rootFingerprint := sha256.Sum256(root)
	certificateFingerprint := sha256.Sum256(raw)
	return api.EndpointCertificateDocument{Version: 1, AccountID: certificate.Claims.AccountID, RootFingerprint: hex.EncodeToString(rootFingerprint[:]), EndpointID: certificate.Claims.EndpointID, Role: "machine", Generation: certificate.Claims.Generation, Serial: certificate.Claims.Serial, IssuedAt: certificate.Claims.IssuedAt.Format(time.RFC3339), ExpiresAt: certificate.Claims.ExpiresAt.Format(time.RFC3339), Certificate: base64.RawURLEncoding.EncodeToString(raw), CertificateFingerprint: hex.EncodeToString(certificateFingerprint[:])}
}

func topologyControlTLS(t *testing.T) *tls.Config {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{73}, ed25519.SeedSize))
	template := &x509.Certificate{SerialNumber: big.NewInt(73), Subject: pkix.Name{CommonName: "authority.paperboat.test"}, NotBefore: time.Unix(1_577_836_800, 0), NotAfter: time.Unix(4_102_444_800, 0), DNSNames: []string{"authority.paperboat.test"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
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
	relayPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize))
	relayTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "relay.paperboat.test"}, NotBefore: time.Unix(1_577_836_800, 0), NotAfter: time.Unix(4_102_444_800, 0), DNSNames: []string{"relay.paperboat.test", "machine.paperboat.test"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	relayDER, err := x509.CreateCertificate(rand.Reader, relayTemplate, relayTemplate, relayPrivate.Public(), relayPrivate)
	if err != nil {
		t.Fatal(err)
	}
	relayCertificate, err := x509.ParseCertificate(relayDER)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(relayCertificate)
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
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

func writeTopologyJSON(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".tmp", encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
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

func waitTopologyExitGate(t *testing.T, ctx context.Context) {
	t.Helper()
	for {
		if _, err := os.Stat("/tmp/paperboat-relay-exit"); err == nil {
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

func topologyEndpointMaterialPath() string   { return "/authority/endpoint-material.json" }
func topologyAuthorityReadyPath() string     { return "/authority/authority-ready.json" }
func topologyTerminalCredentialPath() string { return "/authority/terminal-credential.json" }
func topologyFileCredentialPath() string     { return "/authority/file-credential.json" }
func topologyFileOKPath() string             { return "/authority/file-ok.json" }
func topologyExecCredentialPath() string     { return "/authority/exec-credential.json" }
func topologyTerminalOKPath() string         { return "/authority/terminal-ok.json" }
func topologyExecOKPath() string             { return "/authority/exec-ok.json" }
func topologyHostEnrollmentPath() string     { return "/authority/host-enrollment.json" }
func topologyRootPath() string               { return "/authority/root-public.json" }
func topologyPingOKPath() string             { return "/authority/ping-ok.json" }
