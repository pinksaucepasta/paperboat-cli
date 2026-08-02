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
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

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
	HTTPClient    *http.Client
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
	if o.Backend == nil || o.EnvironmentID == "" || o.Stdin == nil {
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
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 20 * time.Second}
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
	cleanup := true
	var descriptor api.CodexDescriptor
	defer func() {
		if cleanup {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if descriptor.ManagementURL != "" {
				if cleanupErr := stopRemote(cleanupCtx, o, descriptor); cleanupErr != nil {
					fmt.Fprintf(o.Stderr, "Paperboat could not confirm runtime Codex cleanup: %v\n", cleanupErr)
				}
			}
			if cleanupErr := o.Backend.DeleteCodexSession(cleanupCtx, session.ID); cleanupErr != nil {
				fmt.Fprintf(o.Stderr, "Paperboat could not confirm remote Codex cleanup: %v\n", cleanupErr)
			}
		}
	}()
	descriptor, err = o.Backend.CodexSessionDescriptor(ctx, session.ID)
	if err != nil {
		return err
	}
	path := strings.TrimSpace(o.Path)
	if path == "" {
		if !term.IsTerminal(int(o.Stdin.Fd())) {
			return errors.New("pb codex requires --path when stdin is not a terminal")
		}
		path, err = pickDirectory(ctx, o, descriptor)
		if err != nil {
			return err
		}
	}
	prepared, err := prepare(ctx, o, descriptor, path, session.LeaseExpiresAt)
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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	bridge := newBridge(listener, bridgeToken, descriptor.WebSocketURL, descriptor.ConnectCredential)
	bridgeCtx, bridgeCancel := context.WithCancel(ctx)
	defer bridgeCancel()
	go bridge.serve(bridgeCtx)
	renewCtx, renewCancel := context.WithCancel(ctx)
	defer renewCancel()
	go renewLoop(renewCtx, o, session.ID)
	args := []string{"--remote", "ws://" + listener.Addr().String(), "--remote-auth-token-env", "PAPERBOAT_CODEX_BRIDGE_TOKEN", "-C", prepared.Path}
	args = append(args, o.Args...)
	command := exec.CommandContext(ctx, o.CodexPath, args...)
	command.Stdin = o.Stdin
	command.Stdout = o.Stdout
	command.Stderr = o.Stderr
	command.Env = append(os.Environ(), "PAPERBOAT_CODEX_BRIDGE_TOKEN="+bridgeToken)
	err = command.Run()
	if bridgeErr := bridge.err(); bridgeErr != nil {
		cleanup = false
		return fmt.Errorf("Codex connection was interrupted: %w", bridgeErr)
	}
	if err != nil {
		return childError(err)
	}
	cleanup = true
	return nil
}

func stopRemote(ctx context.Context, o Options, d api.CodexDescriptor) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, d.ManagementURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.ManageCredential)
	resp, err := o.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("runtime cleanup returned %s", resp.Status)
	}
	return nil
}

func prepare(ctx context.Context, o Options, d api.CodexDescriptor, path string, lease time.Time) (runtimeDescriptor, error) {
	body, _ := json.Marshal(map[string]any{"path": path, "lease_expires_at": lease})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.ManagementURL, strings.NewReader(string(body)))
	if err != nil {
		return runtimeDescriptor{}, err
	}
	req.Header.Set("Authorization", "Bearer "+d.ManageCredential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.HTTPClient.Do(req)
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
func directories(ctx context.Context, o Options, d api.CodexDescriptor, path, cursor string) (directoryPage, error) {
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
	resp, err := o.HTTPClient.Do(req)
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
	parts := strings.Split(strings.TrimPrefix(value, "v"), ".")
	if len(parts) != 3 {
		return out, errors.New("invalid semantic version")
	}
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
func renewLoop(ctx context.Context, o Options, id string) {
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
					err = renewRuntime(renewCtx, o, descriptor, renewed.LeaseExpiresAt)
				}
			}
			cancel()
			if err != nil {
				fmt.Fprintf(o.Stderr, "Warning: remote Codex lease renewal failed: %v\n", err)
			}
		}
	}
}

func renewRuntime(ctx context.Context, o Options, d api.CodexDescriptor, lease time.Time) error {
	body, _ := json.Marshal(map[string]any{"lease_expires_at": lease})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.ManagementURL+"/renew", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.ManageCredential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.HTTPClient.Do(req)
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
	mu                            sync.Mutex
	serveErr                      error
	server                        *http.Server
}

func newBridge(l net.Listener, token, remoteURL, remoteToken string) *bridge {
	return &bridge{listener: l, token: token, remoteURL: remoteURL, remoteToken: remoteToken}
}
func (b *bridge) serve(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", b.handle)
	b.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	context.AfterFunc(ctx, func() { _ = b.server.Close() })
	if err := b.server.Serve(b.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		b.mu.Lock()
		b.serveErr = err
		b.mu.Unlock()
	}
}
func (b *bridge) err() error { b.mu.Lock(); defer b.mu.Unlock(); return b.serveErr }
func (b *bridge) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+b.token {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	local, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	local.SetReadLimit(128 << 20)
	remote, _, err := websocket.Dial(r.Context(), b.remoteURL, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + b.remoteToken}}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		b.mu.Lock()
		b.serveErr = err
		b.mu.Unlock()
		_ = local.Close(websocket.StatusInternalError, "remote_unavailable")
		return
	}
	remote.SetReadLimit(128 << 20)
	if proxyErr := proxy(r.Context(), local, remote); proxyErr != nil && websocket.CloseStatus(proxyErr) != websocket.StatusNormalClosure {
		b.mu.Lock()
		b.serveErr = proxyErr
		b.mu.Unlock()
	}
}
func proxy(parent context.Context, a, b *websocket.Conn) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	errs := make(chan error, 2)
	copyFrames := func(dst, src *websocket.Conn) {
		for {
			typ, data, err := src.Read(ctx)
			if err != nil {
				errs <- err
				return
			}
			if err = dst.Write(ctx, typ, data); err != nil {
				errs <- err
				return
			}
		}
	}
	go copyFrames(a, b)
	go copyFrames(b, a)
	err := <-errs
	status := websocket.CloseStatus(err)
	if status < 1000 {
		status = websocket.StatusGoingAway
	}
	_ = a.Close(status, "closed")
	_ = b.Close(status, "closed")
	return err
}
