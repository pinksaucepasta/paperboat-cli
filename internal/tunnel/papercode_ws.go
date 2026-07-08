package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
	"github.com/pujan-modha/paperboat-cli/internal/resolver"
)

const (
	rpcTerminalAttach = "terminal.attach"
	rpcTerminalWrite  = "terminal.write"
	rpcTerminalResize = "terminal.resize"
	rpcTerminalClose  = "terminal.close"
)

// PapercodeWSTunnel attaches to the VM-local papercode terminal RPC over the
// agentunnel-provided WebSocket route.
type PapercodeWSTunnel struct {
	Dialer *websocket.Dialer
}

func NewPapercodeWSTunnel() *PapercodeWSTunnel {
	return &PapercodeWSTunnel{Dialer: websocket.DefaultDialer}
}

func (t *PapercodeWSTunnel) Check(ctx context.Context, target *resolver.TerminalTarget) error {
	wsURL, headers, err := papercodeWebSocketRequest(target)
	if err != nil {
		return err
	}
	dialer := t.Dialer
	if dialer == nil {
		dialer = websocket.DefaultDialer
	}
	ws, resp, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("dial papercode websocket: %w (status %d)", err, resp.StatusCode)
		}
		return fmt.Errorf("dial papercode websocket: %w", err)
	}
	return ws.Close()
}

func (t *PapercodeWSTunnel) Dial(ctx context.Context, info resolver.ConnectInfo) (Conn, error) {
	if info.Terminal == nil {
		return nil, errors.New("missing papercode terminal descriptor")
	}
	target := info.Terminal
	wsURL, headers, err := papercodeWebSocketRequest(target)
	if err != nil {
		return nil, err
	}
	dialer := t.Dialer
	if dialer == nil {
		dialer = websocket.DefaultDialer
	}
	ws, resp, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("dial papercode websocket: %w (status %d)", err, resp.StatusCode)
		}
		return nil, fmt.Errorf("dial papercode websocket: %w", err)
	}
	c := newPapercodeWSConn(ws, target)
	c.sessionEnv = sessionEnv(info)
	if err := c.attach(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func papercodeWebSocketRequest(target *resolver.TerminalTarget) (string, http.Header, error) {
	base := strings.TrimRight(target.WebSocketBaseURL, "/")
	if base == "" {
		return "", nil, errors.New("missing papercode websocket base URL")
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", nil, fmt.Errorf("parse papercode websocket URL: %w", err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return "", nil, fmt.Errorf("papercode websocket URL must use ws or wss, got %q", u.Scheme)
	}
	if !strings.HasSuffix(u.Path, "/ws") {
		u.Path = strings.TrimRight(u.Path, "/") + "/ws"
	}
	headers := make(http.Header)
	switch target.Auth.Method {
	case "websocket_ticket":
		if target.Auth.Ticket == "" {
			return "", nil, errors.New("missing papercode websocket ticket")
		}
		q := u.Query()
		q.Set("wsTicket", target.Auth.Ticket)
		u.RawQuery = q.Encode()
	case "bearer":
		if target.Auth.Token == "" {
			return "", nil, errors.New("missing papercode bearer token")
		}
		headers.Set("Authorization", "Bearer "+target.Auth.Token)
	default:
		return "", nil, fmt.Errorf("unsupported papercode websocket auth method %q", target.Auth.Method)
	}
	return u.String(), headers, nil
}

type papercodeWSConn struct {
	ws     *websocket.Conn
	target *resolver.TerminalTarget

	writeMu sync.Mutex
	readMu  sync.Mutex
	pending []byte
	out     chan []byte
	done    chan struct{}
	closed  chan struct{}

	exitOnce sync.Once
	exitCode int
	exitErr  error

	sessionEnv map[string]string
	nextID     int
	closing    atomic.Bool
}

func newPapercodeWSConn(ws *websocket.Conn, target *resolver.TerminalTarget) *papercodeWSConn {
	c := &papercodeWSConn{
		ws:       ws,
		target:   target,
		out:      make(chan []byte, 64),
		done:     make(chan struct{}),
		closed:   make(chan struct{}),
		exitCode: 0,
		nextID:   1,
	}
	go c.readLoop()
	return c
}

func (c *papercodeWSConn) attach(ctx context.Context) error {
	payload := map[string]any{
		"threadId":            c.target.ThreadID,
		"terminalId":          c.target.TerminalID,
		"restartIfNotRunning": true,
	}
	if c.target.CWD != "" {
		payload["cwd"] = c.target.CWD
	}
	if len(c.sessionEnv) > 0 {
		payload["env"] = c.sessionEnv
	}
	return c.call(ctx, rpcTerminalAttach, payload)
}

func sessionEnv(info resolver.ConnectInfo) map[string]string {
	env := make(map[string]string, 2)
	if info.Agent != "" {
		env["PAPERBOAT_AGENT"] = info.Agent
	}
	if info.Size != "" {
		env["PAPERBOAT_MACHINE_SIZE"] = info.Size
	}
	if len(env) == 0 {
		return nil
	}
	return env
}

func (c *papercodeWSConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	b, ok := <-c.out
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, b)
	if n < len(b) {
		c.pending = append(c.pending, b[n:]...)
	}
	return n, nil
}

func (c *papercodeWSConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	payload := map[string]any{
		"threadId":   c.target.ThreadID,
		"terminalId": c.target.TerminalID,
		"data":       string(p),
	}
	if err := c.call(context.Background(), rpcTerminalWrite, payload); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *papercodeWSConn) Resize(rows, cols uint16) error {
	if rows == 0 || cols == 0 {
		return nil
	}
	payload := map[string]any{
		"threadId":   c.target.ThreadID,
		"terminalId": c.target.TerminalID,
		"rows":       rows,
		"cols":       cols,
	}
	return c.call(context.Background(), rpcTerminalResize, payload)
}

func (c *papercodeWSConn) Close() error {
	select {
	case <-c.closed:
		return nil
	default:
	}
	c.closing.Store(true)
	_ = c.call(context.Background(), rpcTerminalClose, map[string]any{
		"threadId":   c.target.ThreadID,
		"terminalId": c.target.TerminalID,
	})
	return c.ws.Close()
}

func (c *papercodeWSConn) Wait() (int, error) {
	<-c.done
	return c.exitCode, c.exitErr
}

func (c *papercodeWSConn) call(ctx context.Context, method string, payload any) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	id := c.nextID
	c.nextID++
	msg := rpcRequest{Type: "Request", Tag: method, ID: fmt.Sprintf("%d", id), Payload: payload, Headers: [][2]string{}}
	return c.ws.WriteJSON(msg)
}

func (c *papercodeWSConn) readLoop() {
	defer close(c.closed)
	defer close(c.out)
	for {
		_, data, err := c.ws.ReadMessage()
		if err != nil {
			if c.isClosing() {
				c.finish(0, nil)
			} else {
				c.finish(1, fmt.Errorf("papercode websocket read failed: %w", err))
			}
			return
		}
		var frames []rpcFrame
		if len(data) > 0 && data[0] == '[' {
			if err := json.Unmarshal(data, &frames); err != nil {
				c.finish(1, err)
				return
			}
		} else {
			var frame rpcFrame
			if err := json.Unmarshal(data, &frame); err != nil {
				c.finish(1, err)
				return
			}
			frames = []rpcFrame{frame}
		}
		for _, frame := range frames {
			if err := c.handleFrame(frame); err != nil {
				c.finish(1, err)
				return
			}
		}
	}
}

func (c *papercodeWSConn) isClosing() bool {
	return c.closing.Load()
}

func (c *papercodeWSConn) handleFrame(frame rpcFrame) error {
	switch frame.Tag {
	case "Chunk":
		for _, raw := range frame.Values {
			var ev terminalEvent
			if err := json.Unmarshal(raw, &ev); err != nil {
				return err
			}
			c.handleTerminalEvent(ev)
		}
	case "Exit":
		if frame.Exit.Tag == "Failure" {
			return errors.New(effectFailureMessage(frame.Exit.Cause))
		}
	case "ClientProtocolError", "Defect":
		return errors.New("papercode websocket protocol error")
	}
	return nil
}

func (c *papercodeWSConn) handleTerminalEvent(ev terminalEvent) {
	switch ev.Type {
	case "snapshot", "restarted":
		if ev.Snapshot.History != "" {
			c.out <- []byte(ev.Snapshot.History)
		}
		c.finishFromStatus(ev.Snapshot.Status, ev.Snapshot.ExitCode, ev.Snapshot.ExitSignal, "")
	case "output":
		if ev.Data != "" {
			c.out <- []byte(ev.Data)
		}
	case "exited":
		c.finish(exitStatus(ev.ExitCode, ev.ExitSignal), nil)
	case "closed":
		c.finish(0, nil)
	case "error":
		c.finish(1, errors.New(ev.Message))
	}
}

func (c *papercodeWSConn) finishFromStatus(status string, exitCode, exitSignal *int, errMsg string) {
	switch status {
	case "exited":
		c.finish(exitStatus(exitCode, exitSignal), nil)
	case "error":
		if errMsg == "" {
			errMsg = "terminal is in error state"
		}
		c.finish(1, errors.New(errMsg))
	}
}

func exitStatus(exitCode, exitSignal *int) int {
	if exitCode != nil {
		return *exitCode
	}
	if exitSignal != nil {
		return 128 + *exitSignal
	}
	return 0
}

func (c *papercodeWSConn) finish(code int, err error) {
	c.exitOnce.Do(func() {
		c.exitCode = code
		c.exitErr = err
		close(c.done)
	})
}

type rpcRequest struct {
	Tag     string      `json:"tag"`
	ID      string      `json:"id"`
	Payload any         `json:"payload"`
	Headers [][2]string `json:"headers"`
	Type    string      `json:"_tag"`
}

type rpcFrame struct {
	Tag       string            `json:"_tag"`
	RequestID string            `json:"requestId"`
	Values    []json.RawMessage `json:"values"`
	Exit      effectExit        `json:"exit"`
}

type effectExit struct {
	Tag   string        `json:"_tag"`
	Cause []effectCause `json:"cause"`
}

type effectCause struct {
	Tag    string          `json:"_tag"`
	Error  json.RawMessage `json:"error"`
	Defect json.RawMessage `json:"defect"`
}

func effectFailureMessage(causes []effectCause) string {
	for _, cause := range causes {
		if cause.Tag == "Fail" && len(cause.Error) > 0 {
			var msg struct {
				Message string `json:"message"`
			}
			if json.Unmarshal(cause.Error, &msg) == nil && msg.Message != "" {
				return msg.Message
			}
			return string(cause.Error)
		}
	}
	return "papercode rpc failed"
}

type terminalEvent struct {
	Type       string           `json:"type"`
	Data       string           `json:"data"`
	Message    string           `json:"message"`
	ExitCode   *int             `json:"exitCode"`
	ExitSignal *int             `json:"exitSignal"`
	Snapshot   terminalSnapshot `json:"snapshot"`
}

type terminalSnapshot struct {
	Status     string `json:"status"`
	History    string `json:"history"`
	ExitCode   *int   `json:"exitCode"`
	ExitSignal *int   `json:"exitSignal"`
}

var _ Tunnel = (*PapercodeWSTunnel)(nil)
var _ Conn = (*papercodeWSConn)(nil)
