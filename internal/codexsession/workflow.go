package codexsession

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/processlaunch"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat/internal/api"
	"golang.org/x/term"
)

var ErrCanceled = errors.New("Codex session canceled")

type Backend interface {
	CreateCodexSession(context.Context, string, string) (api.CodexSession, error)
	CodexSessionDescriptor(context.Context, string) (api.CodexDescriptor, error)
	RenewCodexSession(context.Context, string) (api.CodexSession, error)
	DeleteCodexSession(context.Context, string) error
}
type Options struct {
	Backend       Backend
	EnvironmentID string
	Path          string
	Args          []string
	Stdin         *os.File
	Stdout        io.Writer
	Stderr        io.Writer
	CodexPath     string
	PeerDial      func(context.Context, api.CodexDescriptor) (net.Conn, error)
	Now           func() time.Time
}
type runtimeDescriptor struct {
	ID             string    `json:"id"`
	Path           string    `json:"path"`
	CodexVersion   string    `json:"codex_version"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
}
type directoryPage struct {
	Path        string   `json:"path"`
	Directories []string `json:"directories"`
	NextCursor  string   `json:"next_cursor"`
}

func Run(ctx context.Context, o Options) error {
	if o.Backend == nil || o.EnvironmentID == "" || o.Stdin == nil || o.PeerDial == nil {
		return errors.New("invalid Codex session configuration")
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.CodexPath == "" {
		o.CodexPath = "codex"
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if err := ValidateForwardedArgs(o.Args); err != nil {
		return err
	}
	localVersion, err := version(ctx, o.CodexPath)
	if err != nil {
		return fmt.Errorf("local Codex is unavailable: %w", err)
	}
	idempotency, err := randomToken(24)
	if err != nil {
		return err
	}
	session, err := o.Backend.CreateCodexSession(ctx, o.EnvironmentID, "pb-codex-"+idempotency)
	if err != nil {
		return err
	}
	var descriptor api.CodexDescriptor
	var client *http.Client
	var transport *http.Transport
	defer func() {
		cleanupCodexSession(o, descriptor, client, session.ID)
	}()
	descriptor, err = o.Backend.CodexSessionDescriptor(ctx, session.ID)
	if err != nil {
		return err
	}
	client, transport = newPeerHTTPClient(func(dialCtx context.Context) (net.Conn, error) { return o.PeerDial(dialCtx, descriptor) })
	defer transport.CloseIdleConnections()
	websocketClient := &http.Client{Transport: transport}
	path := strings.TrimSpace(o.Path)
	if path == "" {
		if !term.IsTerminal(int(o.Stdin.Fd())) {
			return errors.New("pb codex requires --path when stdin is not a terminal")
		}
		path, err = pickDirectory(ctx, o, descriptor, client)
		if err != nil {
			return err
		}
	}
	prepared, err := prepare(ctx, client, descriptor, path, session.LeaseExpiresAt)
	if err != nil {
		return err
	}
	if err = compatible(localVersion, prepared.CodexVersion, o.Stderr); err != nil {
		return err
	}
	bridgeToken, err := randomToken(32)
	if err != nil {
		return err
	}
	pathNamespace, err := randomToken(18)
	if err != nil {
		return err
	}
	pathCodecConfig, err := newCodexPathCodecConfig(runtime.GOOS, localVersion, prepared.CodexVersion, prepared.Path, pathNamespace)
	if err != nil {
		return err
	}
	localWorkingDirectory := prepared.Path
	if pathCodecConfig != nil {
		localWorkingDirectory = pathCodecConfig.remoteToLocal(prepared.Path)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	bridge := newBridge(listener, bridgeToken, descriptor.WebSocketURL, descriptor.ConnectCredential, websocketClient, pathCodecConfig)
	bridgeCtx, bridgeCancel := context.WithCancel(ctx)
	defer bridgeCancel()
	go bridge.serve(bridgeCtx)
	renewCtx, renewCancel := context.WithCancel(ctx)
	defer renewCancel()
	go renewLoop(renewCtx, o, client, session.ID)
	args := codexLaunchArgs(listener.Addr().String(), localWorkingDirectory, o.Args)
	command := exec.CommandContext(ctx, o.CodexPath, args...)
	command.Stdin = o.Stdin
	command.Stdout = o.Stdout
	command.Stderr = o.Stderr
	command.Env = append(os.Environ(), "PAPERBOAT_CODEX_BRIDGE_TOKEN="+bridgeToken)
	err = command.Run()
	return finishCodexRun(ctx, err, bridge, bridgeCancel, codexBridgeHandlerWait)
}

func cleanupCodexSession(o Options, descriptor api.CodexDescriptor, client *http.Client, sessionID string) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if descriptor.ManagementURL != "" && client != nil {
		if err := stopRemote(cleanupCtx, client, descriptor); err != nil {
			fmt.Fprintf(o.Stderr, "Paperboat could not confirm runtime Codex cleanup: %v\n", err)
		}
	}
	if err := o.Backend.DeleteCodexSession(cleanupCtx, sessionID); err != nil {
		fmt.Fprintf(o.Stderr, "Paperboat could not confirm remote Codex cleanup: %v\n", err)
	}
}

func codexLaunchArgs(address, workingDirectory string, forwarded []string) []string {
	args := []string{"--remote", "ws://" + address, "--remote-auth-token-env", "PAPERBOAT_CODEX_BRIDGE_TOKEN", "-C", workingDirectory}
	return append(args, forwarded...)
}

func newPeerHTTPClient(dial func(context.Context) (net.Conn, error)) (*http.Client, *http.Transport) {
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	transport.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) }
	return &http.Client{Transport: transport, Timeout: 20 * time.Second}, transport
}

func stopRemote(ctx context.Context, client *http.Client, d api.CodexDescriptor) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, d.ManagementURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.ManageCredential)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("runtime cleanup returned %s", resp.Status)
	}
	return nil
}

func prepare(ctx context.Context, client *http.Client, d api.CodexDescriptor, path string, lease time.Time) (runtimeDescriptor, error) {
	body, _ := json.Marshal(map[string]any{"path": path, "lease_expires_at": lease})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.ManagementURL, strings.NewReader(string(body)))
	if err != nil {
		return runtimeDescriptor{}, err
	}
	req.Header.Set("Authorization", "Bearer "+d.ManageCredential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return runtimeDescriptor{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return runtimeDescriptor{}, fmt.Errorf("remote Codex preparation failed (%s)", resp.Status)
	}
	var out runtimeDescriptor
	err = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out)
	return out, err
}
func directories(ctx context.Context, client *http.Client, d api.CodexDescriptor, path, cursor string) (directoryPage, error) {
	endpoint, err := url.Parse(d.ManagementURL + "/directories")
	if err != nil {
		return directoryPage{}, err
	}
	q := endpoint.Query()
	q.Set("path", path)
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	endpoint.RawQuery = q.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	req.Header.Set("Authorization", "Bearer "+d.ManageCredential)
	resp, err := client.Do(req)
	if err != nil {
		return directoryPage{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return directoryPage{}, fmt.Errorf("remote directory listing failed (%s)", resp.Status)
	}
	var page directoryPage
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&page)
	return page, err
}
func ValidateForwardedArgs(args []string) error {
	for _, arg := range args {
		if arg == "--remote" || strings.HasPrefix(arg, "--remote=") || arg == "--remote-auth-token-env" || strings.HasPrefix(arg, "--remote-auth-token-env=") || arg == "-C" || strings.HasPrefix(arg, "-C=") || arg == "--cd" || strings.HasPrefix(arg, "--cd=") {
			return fmt.Errorf("%s is managed by Paperboat and cannot be forwarded", arg)
		}
	}
	return nil
}
func version(ctx context.Context, path string) (string, error) {
	command := exec.CommandContext(ctx, path, "--version")
	processlaunch.ConfigureBackground(command)
	body, err := command.Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(body))
	if len(fields) != 2 {
		return "", errors.New("Codex returned a malformed version")
	}
	return fields[1], nil
}
func compatible(local, remote string, w io.Writer) error {
	l, err := majorMinorPatch(local)
	if err != nil {
		return fmt.Errorf("local Codex version %q is malformed", local)
	}
	r, err := majorMinorPatch(remote)
	if err != nil {
		return fmt.Errorf("remote Codex version %q is malformed", remote)
	}
	if l[0] != r[0] || l[1] != r[1] {
		return fmt.Errorf("local Codex %s is incompatible with remote Codex %s; major and minor versions must match", local, remote)
	}
	if l[2] != r[2] {
		fmt.Fprintf(w, "Warning: local Codex %s and remote Codex %s differ by patch version.\n", local, remote)
	}
	return nil
}
func majorMinorPatch(value string) ([3]int, error) {
	var out [3]int
	// Codex prerelease versions use dotted identifiers (for example
	// 0.148.0-alpha.21). Split only the numeric version components, then
	// discard the optional prerelease/build suffix from the patch component.
	parts := strings.SplitN(strings.TrimPrefix(value, "v"), ".", 3)
	if len(parts) != 3 {
		return out, errors.New("invalid semantic version")
	}
	patch := parts[2]
	if suffix := strings.IndexAny(patch, "-+"); suffix >= 0 {
		patch = patch[:suffix]
	}
	parts[2] = patch
	for i, p := range parts {
		n, err := strconv.Atoi(strings.SplitN(p, "-", 2)[0])
		if err != nil {
			return out, err
		}
		out[i] = n
	}
	return out, nil
}
func randomToken(size int) (string, error) {
	body := make([]byte, size)
	if _, err := rand.Read(body); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(body), nil
}
func childError(err error) error {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return fmt.Errorf("Codex exited with status %d", exit.ExitCode())
	}
	return err
}
func renewLoop(ctx context.Context, o Options, client *http.Client, id string) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			renewCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			renewed, err := o.Backend.RenewCodexSession(renewCtx, id)
			if err == nil {
				var descriptor api.CodexDescriptor
				descriptor, err = o.Backend.CodexSessionDescriptor(renewCtx, id)
				if err == nil {
					err = renewRuntime(renewCtx, client, descriptor, renewed.LeaseExpiresAt)
				}
			}
			cancel()
			if err != nil {
				fmt.Fprintf(o.Stderr, "Warning: remote Codex lease renewal failed: %v\n", err)
			}
		}
	}
}

func renewRuntime(ctx context.Context, client *http.Client, d api.CodexDescriptor, lease time.Time) error {
	body, _ := json.Marshal(map[string]any{"lease_expires_at": lease})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.ManagementURL+"/renew", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.ManageCredential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("runtime renewal returned %s", resp.Status)
	}
	return nil
}

type bridge struct {
	listener                      net.Listener
	token, remoteURL, remoteToken string
	httpClient                    *http.Client
	pathCodecConfig               *codexPathCodecConfig
	mu                            sync.Mutex
	server                        *http.Server
	serveErr                      error
	activeHandlers                int
	connections                   map[net.Conn]struct{}
	stateChanged                  chan struct{}
	serveDone                     chan struct{}
	stopOnce                      sync.Once
}

const (
	codexBridgeHandlerWait       = 2 * time.Second
	codexBridgeGracefulCloseWait = 250 * time.Millisecond
)

const codexDiagnosticMethodUnavailable = "unavailable"

func newBridge(l net.Listener, token, remoteURL, remoteToken string, httpClient *http.Client, pathCodecConfig *codexPathCodecConfig) *bridge {
	return &bridge{
		listener: l, token: token, remoteURL: remoteURL, remoteToken: remoteToken,
		httpClient: httpClient, pathCodecConfig: pathCodecConfig,
		connections: make(map[net.Conn]struct{}), stateChanged: make(chan struct{}), serveDone: make(chan struct{}),
	}
}
func (b *bridge) serve(ctx context.Context) {
	defer close(b.serveDone)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { b.handle(ctx, w, r) })
	server := &http.Server{
		Handler: mux, ReadHeaderTimeout: 5 * time.Second, ConnState: b.connectionStateChanged,
		ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
			return context.WithValue(ctx, bridgeConnectionContextKey{}, connection)
		},
	}
	b.mu.Lock()
	b.server = server
	b.signalStateChangedLocked()
	b.mu.Unlock()
	stop := context.AfterFunc(ctx, b.stopAccepting)
	defer stop()
	if err := server.Serve(b.listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		b.recordTermination(newBridgeTermination("bridge", "serve", codexDiagnosticMethodUnavailable, 0, "serve_failed", err))
	}
}
func (b *bridge) err() error { b.mu.Lock(); defer b.mu.Unlock(); return b.serveErr }
func (b *bridge) stopAccepting() {
	b.stopOnce.Do(func() {
		b.mu.Lock()
		server := b.server
		listener := b.listener
		b.mu.Unlock()
		if server != nil {
			_ = server.Close()
		} else if listener != nil {
			_ = listener.Close()
		}
	})
}
func (b *bridge) handle(parent context.Context, w http.ResponseWriter, r *http.Request) {
	b.handlerStarted()
	defer b.handlerFinished()
	if r.Header.Get("Authorization") != "Bearer "+b.token {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	local, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	localRaw, _ := r.Context().Value(bridgeConnectionContextKey{}).(net.Conn)
	local.SetReadLimit(128 << 20)
	handlerCtx, handlerCancel := context.WithCancel(parent)
	stopRequest := context.AfterFunc(r.Context(), handlerCancel)
	defer func() {
		stopRequest()
		handlerCancel()
	}()
	var remoteRaw net.Conn
	dialCtx := httptrace.WithClientTrace(handlerCtx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { remoteRaw = info.Conn }})
	remote, _, err := websocket.Dial(dialCtx, b.remoteURL, &websocket.DialOptions{HTTPClient: b.httpClient, HTTPHeader: http.Header{"Authorization": []string{"Bearer " + b.remoteToken}}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		if bridgeDialWasCanceled(handlerCtx, err) {
			_ = local.CloseNow()
			return
		}
		b.recordTermination(newBridgeTermination("server_to_client", "remote_dial", codexDiagnosticMethodUnavailable, 0, "dial_failed", err))
		_ = local.CloseNow()
		return
	}
	remote.SetReadLimit(128 << 20)
	if proxyErr := proxy(handlerCtx, newWebSocketBridgeConnection(local, localRaw), newWebSocketBridgeConnection(remote, remoteRaw), b.pathCodecConfig.newCodec()); proxyErr != nil {
		b.recordTermination(proxyErr)
	}
}

func bridgeDialWasCanceled(ctx context.Context, err error) bool {
	ctxErr := ctx.Err()
	return ctxErr != nil && errors.Is(err, ctxErr)
}

type bridgeConnectionContextKey struct{}

func (b *bridge) handlerStarted() {
	b.mu.Lock()
	b.activeHandlers++
	b.signalStateChangedLocked()
	b.mu.Unlock()
}

func (b *bridge) handlerFinished() {
	b.mu.Lock()
	if b.activeHandlers > 0 {
		b.activeHandlers--
	}
	b.signalStateChangedLocked()
	b.mu.Unlock()
}

func (b *bridge) connectionStateChanged(connection net.Conn, state http.ConnState) {
	b.mu.Lock()
	switch state {
	case http.StateNew:
		b.connections[connection] = struct{}{}
	case http.StateHijacked, http.StateClosed:
		delete(b.connections, connection)
	default:
		b.mu.Unlock()
		return
	}
	b.signalStateChangedLocked()
	b.mu.Unlock()
}

func (b *bridge) recordTermination(err error) {
	if err == nil {
		return
	}
	b.mu.Lock()
	if b.serveErr == nil {
		b.serveErr = err
		b.signalStateChangedLocked()
	}
	b.mu.Unlock()
}

func (b *bridge) signalStateChangedLocked() {
	close(b.stateChanged)
	b.stateChanged = make(chan struct{})
}

func (b *bridge) waitForHandlers(timeout time.Duration) error {
	if timeout <= 0 {
		return b.err()
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-b.serveDone:
	case <-timer.C:
		return b.recordShutdownTimeout()
	}
	for {
		b.mu.Lock()
		active := b.activeHandlers
		connections := len(b.connections)
		changed := b.stateChanged
		b.mu.Unlock()
		if active == 0 && connections == 0 {
			return b.err()
		}
		select {
		case <-changed:
		case <-timer.C:
			return b.recordShutdownTimeout()
		}
	}
}

func (b *bridge) recordShutdownTimeout() error {
	b.recordTermination(newBridgeTermination("bridge", "shutdown", codexDiagnosticMethodUnavailable, 0, "shutdown_timeout", nil))
	return b.err()
}

func finishCodexRun(ctx context.Context, childErr error, bridge *bridge, cancelBridge context.CancelFunc, wait time.Duration) error {
	bridge.stopAccepting()
	cancelBridge()
	bridgeErr := bridge.waitForHandlers(wait)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if bridgeErr != nil {
		return fmt.Errorf("Codex connection was interrupted: %w", bridgeErr)
	}
	if childErr != nil {
		return childError(childErr)
	}
	return nil
}

type bridgeWebSocket interface {
	Read(context.Context) (websocket.MessageType, []byte, error)
	Write(context.Context, websocket.MessageType, []byte) error
	CloseNow() error
}

type boundedGracefulBridgeWebSocket interface {
	closeGracefullyWithin(websocket.StatusCode, string, time.Duration) error
}

type webSocketBridgeConnection struct {
	connection *websocket.Conn
	raw        net.Conn
}

func newWebSocketBridgeConnection(connection *websocket.Conn, raw net.Conn) *webSocketBridgeConnection {
	return &webSocketBridgeConnection{connection: connection, raw: raw}
}

func (c *webSocketBridgeConnection) Read(ctx context.Context) (websocket.MessageType, []byte, error) {
	return c.connection.Read(ctx)
}

func (c *webSocketBridgeConnection) Write(ctx context.Context, typ websocket.MessageType, data []byte) error {
	return c.connection.Write(ctx, typ, data)
}

func (c *webSocketBridgeConnection) CloseNow() error { return c.connection.CloseNow() }

func (c *webSocketBridgeConnection) closeGracefullyWithin(code websocket.StatusCode, reason string, timeout time.Duration) error {
	if c.raw == nil || timeout <= 0 {
		return errors.New("bounded WebSocket close is unavailable")
	}
	if err := c.raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	return c.connection.Close(code, reason)
}

type bridgeTermination struct {
	direction    string
	stage        string
	method       string
	frameLength  int
	cause        string
	codecClass   string
	closeCode    int
	closeReason  string
	clean        bool
	sourceClosed bool
}

func (e *bridgeTermination) Error() string {
	return fmt.Sprintf("direction=%s stage=%s method=%s frame_length=%d cause=%s codec_class=%s close_code=%d close_reason=%s", e.direction, e.stage, e.method, e.frameLength, e.cause, e.codecClass, e.closeCode, e.closeReason)
}

func newBridgeTermination(direction, stage, method string, frameLength int, cause string, err error) *bridgeTermination {
	if method == "" {
		method = codexDiagnosticMethodUnavailable
	}
	termination := &bridgeTermination{direction: direction, stage: stage, method: method, frameLength: frameLength, cause: cause, codecClass: "none", closeReason: "none"}
	if errors.Is(err, context.Canceled) {
		termination.clean = true
		termination.cause = "canceled"
	}
	var closeErr websocket.CloseError
	if errors.As(err, &closeErr) {
		termination.closeCode = int(closeErr.Code)
		termination.closeReason = sanitizeCodexCloseReason(closeErr.Reason)
		termination.clean = closeErr.Code == websocket.StatusNormalClosure || closeErr.Code == websocket.StatusGoingAway
		termination.sourceClosed = true
		termination.cause = "websocket_close"
	}
	return termination
}

func newCodecBridgeTermination(direction, method string, frameLength int, err error) *bridgeTermination {
	termination := newBridgeTermination(direction, "codec", method, frameLength, "codec_rejected", nil)
	termination.codecClass = codexCodecFailureClassOf(err)
	return termination
}

func sanitizeCodexCloseReason(reason string) string {
	switch strings.TrimSpace(reason) {
	case "":
		return "none"
	case "closed", "normal", "going_away", "remote_unavailable":
		return strings.TrimSpace(reason)
	default:
		return "redacted"
	}
}

func proxy(parent context.Context, a, b bridgeWebSocket, pathCodec *codexPathCodec) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	first := make(chan *bridgeTermination, 1)
	done := make(chan struct{}, 2)
	var firstOnce sync.Once
	report := func(termination *bridgeTermination) {
		firstOnce.Do(func() { first <- termination })
		done <- struct{}{}
	}
	copyFrames := func(direction string, pathDirection codexPathDirection, dst, src bridgeWebSocket) {
		for {
			typ, data, err := src.Read(ctx)
			if err != nil {
				method := codexDiagnosticMethodUnavailable
				if pathCodec != nil {
					method = pathCodec.pendingDiagnosticMethod(pathDirection)
				}
				termination := newBridgeTermination(direction, "read", method, 0, "read_failed", err)
				if termination.sourceClosed && termination.clean && method != codexDiagnosticMethodUnavailable {
					termination.clean = false
				}
				report(termination)
				return
			}
			method := codexDiagnosticMethodUnavailable
			if pathCodec != nil {
				if typ != websocket.MessageText {
					report(newBridgeTermination(direction, "frame_type", pathCodec.pendingDiagnosticMethod(pathDirection), len(data), "non_text_frame", nil))
					return
				}
				frameLength := len(data)
				data, method, err = pathCodec.transformDiagnosticFrame(data, pathDirection)
				if err != nil {
					report(newCodecBridgeTermination(direction, method, frameLength, err))
					return
				}
			}
			if err = dst.Write(ctx, typ, data); err != nil {
				report(newBridgeTermination(direction, "write", method, len(data), "write_failed", err))
				return
			}
		}
	}
	go copyFrames("server_to_client", codexPathsToClient, a, b)
	go copyFrames("client_to_server", codexPathsToServer, b, a)
	termination := <-first
	if termination.clean && termination.sourceClosed {
		// Keep the opposite read alive while the bounded close handshake is
		// propagated. Canceling it first would turn a clean peer close into EOF.
		closeBridgeWebSockets(a, b, termination)
		cancel()
	} else {
		cancel()
		closeBridgeWebSockets(a, b, termination)
	}
	<-done
	<-done
	if termination.clean {
		return nil
	}
	return termination
}

func closeBridgeWebSockets(a, b bridgeWebSocket, termination *bridgeTermination) {
	// coder/websocket completes the close handshake and closes the source socket
	// before Read returns a CloseError. Close only the opposite socket in that
	// case. Starting Conn.Close here would add an uninterruptible five-second
	// handshake, which is longer than the bounded bridge shutdown.
	if termination.sourceClosed {
		var opposite bridgeWebSocket
		if termination.direction == "server_to_client" {
			opposite = a
		} else {
			opposite = b
		}
		if termination.clean {
			if closer, ok := opposite.(boundedGracefulBridgeWebSocket); ok {
				reason := "normal"
				if websocket.StatusCode(termination.closeCode) == websocket.StatusGoingAway {
					reason = "going_away"
				}
				if err := closer.closeGracefullyWithin(websocket.StatusCode(termination.closeCode), reason, codexBridgeGracefulCloseWait); err == nil {
					return
				}
			}
		}
		_ = opposite.CloseNow()
		return
	}
	_ = a.CloseNow()
	_ = b.CloseNow()
}
