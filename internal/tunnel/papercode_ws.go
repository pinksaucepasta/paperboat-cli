package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pujan-modha/paperboat-cli/internal/resolver"
)

const (
	papercodeTerminalProtocol     = "paperboat-terminal-rpc/v1"
	papercodeWebSocketPath        = "/ws"
	papercodeTicketQueryParameter = "wsTicket"
	rpcRequestTagValue            = "Request"
	rpcAckTagValue                = "Ack"
	rpcChunkTag                   = "Chunk"
	rpcExitTag                    = "Exit"
	rpcClientProtocolErrorTag     = "ClientProtocolError"
	rpcDefectTag                  = "Defect"
	rpcTerminalAttach             = "terminal.attach"
	rpcTerminalWrite              = "terminal.write"
	rpcTerminalResize             = "terminal.resize"
	rpcTerminalClose              = "terminal.close"
	rpcSubscribeTerminalMetadata  = "subscribeTerminalMetadata"
	rpcFieldThreadID              = "threadId"
	rpcFieldTerminalID            = "terminalId"
	rpcFieldRestartIfNotRunning   = "restartIfNotRunning"
	rpcFieldCWD                   = "cwd"
	rpcFieldEnv                   = "env"
	rpcFieldAfterSequence         = "afterSequence"
	rpcFieldData                  = "data"
	rpcFieldRows                  = "rows"
	rpcFieldCols                  = "cols"
	terminalEventSnapshot         = "snapshot"
	terminalEventOutput           = "output"
	terminalEventExited           = "exited"
	terminalEventClosed           = "closed"
	terminalEventError            = "error"
	terminalEventCleared          = "cleared"
	terminalEventRestarted        = "restarted"
	terminalEventActivity         = "activity"
	websocketKeepaliveInterval    = 30 * time.Second
	websocketKeepaliveTimeout     = 10 * time.Second
	websocketWriteTimeout         = 10 * time.Second
	terminalOutputQueueChunks     = 256
)

var papercodeAttachEventTypes = []string{
	terminalEventSnapshot,
	terminalEventOutput,
	terminalEventExited,
	terminalEventClosed,
	terminalEventError,
	terminalEventCleared,
	terminalEventRestarted,
	terminalEventActivity,
}

// PapercodeWSTunnel attaches to the VM-local papercode terminal RPC over the
// agentunnel-provided WebSocket route.
type PapercodeWSTunnel struct {
	Dialer            *websocket.Dialer
	OutputQueueChunks int
}

func NewPapercodeWSTunnel() *PapercodeWSTunnel {
	return &PapercodeWSTunnel{Dialer: websocket.DefaultDialer, OutputQueueChunks: terminalOutputQueueChunks}
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
	c := newPapercodeWSConn(ws, target, t.outputQueueChunks())
	defer c.Close()
	if err := c.call(ctx, rpcSubscribeTerminalMetadata, map[string]any{}); err != nil {
		return err
	}
	return c.waitProtocol(ctx)
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
	c := newPapercodeWSConn(ws, target, t.outputQueueChunks())
	if err := c.attach(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}
	if err := c.waitProtocol(ctx); err != nil {
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
	if !strings.HasSuffix(u.Path, papercodeWebSocketPath) {
		u.Path = strings.TrimRight(u.Path, "/") + papercodeWebSocketPath
	}
	headers := make(http.Header)
	switch target.Auth.Method {
	case "websocket_ticket":
		if target.Auth.Ticket == "" {
			return "", nil, errors.New("missing papercode websocket ticket")
		}
		q := u.Query()
		q.Set(papercodeTicketQueryParameter, target.Auth.Ticket)
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

	nextID        int
	closing       atomic.Bool
	protocolReady chan struct{}
	protocolOnce  sync.Once
	keepaliveStop chan struct{}
	keepaliveOnce sync.Once
}

func (t *PapercodeWSTunnel) outputQueueChunks() int {
	if t.OutputQueueChunks > 0 {
		return t.OutputQueueChunks
	}
	return terminalOutputQueueChunks
}

func newPapercodeWSConn(ws *websocket.Conn, target *resolver.TerminalTarget, configuredQueueChunks ...int) *papercodeWSConn {
	outputQueueChunks := terminalOutputQueueChunks
	if len(configuredQueueChunks) > 0 && configuredQueueChunks[0] > 0 {
		outputQueueChunks = configuredQueueChunks[0]
	}
	c := &papercodeWSConn{
		ws:            ws,
		target:        target,
		out:           make(chan []byte, outputQueueChunks),
		done:          make(chan struct{}),
		closed:        make(chan struct{}),
		exitCode:      0,
		nextID:        1,
		protocolReady: make(chan struct{}),
		keepaliveStop: make(chan struct{}),
	}
	go c.readLoop()
	go c.keepaliveLoop()
	return c
}

func (c *papercodeWSConn) waitProtocol(ctx context.Context) error {
	select {
	case <-c.protocolReady:
		return nil
	case <-c.done:
		if c.exitErr != nil {
			return c.exitErr
		}
		return errors.New("papercode terminal attach ended before a protocol frame")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *papercodeWSConn) attach(ctx context.Context) error {
	payload := map[string]any{
		rpcFieldThreadID:            c.target.ThreadID,
		rpcFieldTerminalID:          c.target.TerminalID,
		rpcFieldRestartIfNotRunning: true,
	}
	if c.target.CWD != "" {
		payload[rpcFieldCWD] = c.target.CWD
	}
	if c.target.AfterSequence > 0 {
		payload[rpcFieldAfterSequence] = c.target.AfterSequence
	}
	return c.call(ctx, rpcTerminalAttach, payload)
}

func (c *papercodeWSConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	// Animated TUIs emit many small PTY updates. Drain output that is already
	// available so one local write can render a burst without dropping bytes.
	return readBufferedChunks(p, &c.pending, c.out)
}

func (c *papercodeWSConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	payload := map[string]any{
		rpcFieldThreadID:   c.target.ThreadID,
		rpcFieldTerminalID: c.target.TerminalID,
		rpcFieldData:       string(p),
	}
	ctx, cancel := context.WithTimeout(context.Background(), websocketWriteTimeout)
	defer cancel()
	if err := c.call(ctx, rpcTerminalWrite, payload); err != nil {
		return 0, err
	}
	return len(p), nil
}

// CloseWrite reports the protocol limitation instead of pretending EOF was
// delivered and leaving a non-interactive remote process waiting forever.
func (c *papercodeWSConn) CloseWrite() error {
	return ErrInputEOFUnsupported
}

func (c *papercodeWSConn) Resize(rows, cols uint16) error {
	if rows == 0 || cols == 0 {
		return nil
	}
	payload := map[string]any{
		rpcFieldThreadID:   c.target.ThreadID,
		rpcFieldTerminalID: c.target.TerminalID,
		rpcFieldRows:       rows,
		rpcFieldCols:       cols,
	}
	ctx, cancel := context.WithTimeout(context.Background(), websocketWriteTimeout)
	defer cancel()
	return c.call(ctx, rpcTerminalResize, payload)
}

func (c *papercodeWSConn) Close() error {
	select {
	case <-c.closed:
		return nil
	default:
	}
	c.closing.Store(true)
	c.stopKeepalive()
	// Closing the client detaches the transport. terminal.close is destructive:
	// it stops and unregisters the remote PTY, which would break reconnect and
	// make `pb doctor` terminate a user's session.
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
	msg := rpcRequest{Type: rpcRequestTagValue, Tag: method, ID: fmt.Sprintf("%d", id), Payload: payload, Headers: [][2]string{}}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.ws.SetWriteDeadline(deadline)
		defer c.ws.SetWriteDeadline(time.Time{})
	}
	return c.ws.WriteJSON(msg)
}

func (c *papercodeWSConn) keepaliveLoop() {
	_ = c.ws.SetReadDeadline(time.Now().Add(websocketKeepaliveInterval + websocketKeepaliveTimeout))
	c.ws.SetPongHandler(func(string) error {
		return c.ws.SetReadDeadline(time.Now().Add(websocketKeepaliveInterval + websocketKeepaliveTimeout))
	})
	ticker := time.NewTicker(websocketKeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.writeMu.Lock()
			_ = c.ws.SetWriteDeadline(time.Now().Add(websocketKeepaliveTimeout))
			err := c.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(websocketKeepaliveTimeout))
			_ = c.ws.SetWriteDeadline(time.Time{})
			c.writeMu.Unlock()
			if err != nil {
				c.finish(1, errors.Join(ErrTransportLost, err))
				_ = c.ws.Close()
				return
			}
		case <-c.keepaliveStop:
			return
		}
	}
}

func (c *papercodeWSConn) stopKeepalive() {
	c.keepaliveOnce.Do(func() { close(c.keepaliveStop) })
}

func (c *papercodeWSConn) readLoop() {
	defer c.stopKeepalive()
	defer close(c.closed)
	defer close(c.out)
	for {
		_, data, err := c.ws.ReadMessage()
		if err != nil {
			if c.isClosing() {
				c.finish(0, nil)
			} else {
				c.finish(1, errors.Join(ErrTransportLost, fmt.Errorf("papercode websocket read failed: %w", err)))
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

// MarkTransportLost terminates the socket as an unexpected transport failure,
// allowing the reconnect supervisor to distinguish it from an intentional close.
func (c *papercodeWSConn) MarkTransportLost(err error) {
	if err == nil {
		err = ErrTransportLost
	}
	c.finish(1, errors.Join(ErrTransportLost, err))
	_ = c.ws.Close()
}

func (c *papercodeWSConn) handleFrame(frame rpcFrame) error {
	switch frame.Tag {
	case rpcChunkTag:
		for _, raw := range frame.Values {
			var ev terminalEvent
			if err := json.Unmarshal(raw, &ev); err != nil {
				return err
			}
			if err := c.handleTerminalEvent(ev); err != nil {
				return err
			}
		}
		if err := c.acknowledgeChunk(frame.RequestID); err != nil {
			return err
		}
		c.protocolOnce.Do(func() {
			if c.protocolReady != nil {
				close(c.protocolReady)
			}
		})
	case rpcExitTag:
		if frame.Exit.Tag == "Failure" {
			return errors.New(effectFailureMessage(frame.Exit.Cause))
		}
	case rpcClientProtocolErrorTag, rpcDefectTag:
		return errors.New("papercode websocket protocol error")
	}
	return nil
}

func (c *papercodeWSConn) acknowledgeChunk(requestID string) error {
	if requestID == "" {
		return errors.New("papercode websocket chunk is missing requestId")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	defer c.ws.SetWriteDeadline(time.Time{})
	return c.ws.WriteJSON(rpcAcknowledgement{Type: rpcAckTagValue, RequestID: requestID})
}

func (c *papercodeWSConn) handleTerminalEvent(ev terminalEvent) error {
	commitSequence := func(sequence *int) {
		if sequence != nil && c.target != nil && c.target.SequenceSink != nil {
			c.target.SequenceSink(*sequence)
		}
	}
	pushOutput := func(data []byte) error {
		if len(data) == 0 {
			return nil
		}
		timer := time.NewTimer(websocketWriteTimeout)
		defer timer.Stop()
		select {
		case c.out <- data:
			return nil
		case <-c.keepaliveStop:
			return ErrTransportLost
		case <-timer.C:
			return errors.Join(ErrTransportLost, errors.New("papercode terminal output queue stalled"))
		}
	}
	switch ev.Type {
	case terminalEventSnapshot, terminalEventRestarted:
		replayHistory := ev.Type == terminalEventRestarted || c.target == nil || c.target.ReplayHistory
		if ev.Snapshot.History != "" && replayHistory {
			if ev.Type == terminalEventRestarted && c.target != nil && !c.target.ReplayHistory {
				if err := pushOutput([]byte("\x1b[2J\x1b[H")); err != nil {
					return err
				}
			}
			if err := pushOutput([]byte(ev.Snapshot.History)); err != nil {
				return err
			}
		}
		if replayHistory {
			commitSequence(ev.Snapshot.Sequence)
		}
		if replayHistory {
			c.finishFromStatus(ev.Snapshot.Status, ev.Snapshot.ExitCode, ev.Snapshot.ExitSignal, "")
		}
	case terminalEventOutput:
		if ev.Data != "" {
			if err := pushOutput([]byte(ev.Data)); err != nil {
				return err
			}
		}
		commitSequence(ev.Sequence)
	case terminalEventExited:
		commitSequence(ev.Sequence)
		c.finish(exitStatus(ev.ExitCode, ev.ExitSignal), nil)
	case terminalEventClosed:
		commitSequence(ev.Sequence)
		c.finish(0, nil)
	case terminalEventError:
		commitSequence(ev.Sequence)
		c.finish(1, errors.New(ev.Message))
	case terminalEventCleared:
		if err := pushOutput([]byte("\x1b[2J\x1b[H")); err != nil {
			return err
		}
		commitSequence(ev.Sequence)
	case terminalEventActivity:
		commitSequence(ev.Sequence)
	}
	return nil
}

func (c *papercodeWSConn) finishFromStatus(status string, exitCode, exitSignal *int, errMsg string) {
	switch status {
	case terminalEventExited:
		c.finish(exitStatus(exitCode, exitSignal), nil)
	case terminalEventError:
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

type rpcAcknowledgement struct {
	Type      string `json:"_tag"`
	RequestID string `json:"requestId"`
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
	Sequence   *int             `json:"sequence"`
	Data       string           `json:"data"`
	Message    string           `json:"message"`
	ExitCode   *int             `json:"exitCode"`
	ExitSignal *int             `json:"exitSignal"`
	Snapshot   terminalSnapshot `json:"snapshot"`
}

type terminalSnapshot struct {
	Status     string `json:"status"`
	History    string `json:"history"`
	Sequence   *int   `json:"sequence"`
	ExitCode   *int   `json:"exitCode"`
	ExitSignal *int   `json:"exitSignal"`
}

var _ Tunnel = (*PapercodeWSTunnel)(nil)
var _ Conn = (*papercodeWSConn)(nil)
