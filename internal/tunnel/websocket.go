package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

const (
	websocketWriteTimeout      = 10 * time.Second
	terminalOutputQueueChunks  = 256
	helperWebSocketSubprotocol = "paperboat.terminal.v1"
)

// WebSocketTunnel attaches to the helper terminal RPC over the server-assigned
// WebSocket route.
type WebSocketTunnel struct {
	Dialer            *websocket.Dialer
	OutputQueueChunks int
	sessionCache      tls.ClientSessionCache
	sessionCacheOnce  sync.Once
}

func NewWebSocketTunnel() *WebSocketTunnel {
	dialer := *websocket.DefaultDialer
	dialer.TLSClientConfig = &tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(64)}
	return &WebSocketTunnel{Dialer: &dialer, OutputQueueChunks: terminalOutputQueueChunks}
}

func (t *WebSocketTunnel) outputQueueChunks() int {
	if t.OutputQueueChunks > 0 {
		return t.OutputQueueChunks
	}
	return terminalOutputQueueChunks
}

type preparedWebSocketTerminal struct {
	connection net.Conn
	dialer     *websocket.Dialer
	url        string
	headers    http.Header
	target     *resolver.TerminalTarget
	queue      int
	tls        bool
	proxy      bool
	once       sync.Once
}

func (p *preparedWebSocketTerminal) Attach(ctx context.Context) (Conn, error) {
	var result Conn
	var resultErr error
	p.once.Do(func() {
		dialer := *p.dialer
		if !p.proxy {
			dialer.Proxy = nil
		}
		used := false
		preparedDial := func(context.Context, string, string) (net.Conn, error) {
			if used {
				return nil, errors.New("prepared WebSocket transport already used")
			}
			used = true
			return p.connection, nil
		}
		if p.tls {
			dialer.NetDialTLSContext = preparedDial
		} else {
			dialer.NetDialContext = preparedDial
		}
		ws, response, err := dialer.DialContext(ctx, p.url, p.headers)
		if err != nil {
			_ = p.connection.Close()
			resultErr = classifyWebSocketUpgradeError(ctx, err, response)
			return
		}
		message := &helperWebSocketConnection{ws: ws}
		if _, err := helperHandshake(ctx, message); err != nil {
			_ = ws.Close()
			resultErr = err
			return
		}
		connection := newHelperTerminalConn(message, p.target, p.queue)
		if err := connection.initialize(ctx); err != nil {
			_ = ws.Close()
			resultErr = err
			return
		}
		result = connection
	})
	if result == nil && resultErr == nil {
		return nil, errors.New("prepared terminal already consumed")
	}
	return result, resultErr
}

func (p *preparedWebSocketTerminal) Close() error { return p.connection.Close() }

func (t *WebSocketTunnel) Check(ctx context.Context, target *resolver.TerminalTarget) error {
	wsURL, headers, err := terminalWebSocketRequest(target)
	if err != nil {
		return err
	}
	dialer := helperDialer(t.Dialer)
	ws, resp, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		return classifyWebSocketUpgradeError(ctx, err, resp)
	}
	defer ws.Close()
	message := &helperWebSocketConnection{ws: ws}
	if _, err := helperHandshake(ctx, message); err != nil {
		return err
	}
	return helperCheck(ctx, message)
}

func (t *WebSocketTunnel) Dial(ctx context.Context, info resolver.ConnectInfo) (Conn, error) {
	prepared, err := t.Establish(ctx, info)
	if err != nil {
		return nil, err
	}
	return prepared.Attach(ctx)
}

func (t *WebSocketTunnel) Establish(ctx context.Context, info resolver.ConnectInfo) (preparedTerminal, error) {
	if info.Terminal == nil || info.Terminal.Protocol != "paperboat.terminal.v1" {
		return nil, errors.New("WSS requires terminal protocol v1")
	}
	wsURL, headers, err := terminalWebSocketRequest(info.Terminal)
	if err != nil {
		return nil, err
	}
	dialer := helperDialer(t.Dialer)
	connection, secure, proxy, err := t.dialTransport(ctx, dialer, wsURL)
	if err != nil {
		return nil, err
	}
	return &preparedWebSocketTerminal{connection: connection, dialer: dialer, url: wsURL, headers: headers, target: info.Terminal, queue: t.outputQueueChunks(), tls: secure, proxy: proxy}, nil
}

func (t *WebSocketTunnel) dialTransport(ctx context.Context, dialer *websocket.Dialer, target string) (net.Conn, bool, bool, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, false, false, err
	}
	secure := u.Scheme == "wss"
	port := u.Port()
	if port == "" {
		if secure {
			port = "443"
		} else {
			port = "80"
		}
	}
	address := net.JoinHostPort(u.Hostname(), port)
	request := &http.Request{URL: u}
	var proxyURL *url.URL
	if dialer.Proxy != nil {
		proxyURL, err = dialer.Proxy(request)
		proxyErr := err
		if proxyErr != nil {
			return nil, secure, false, proxyErr
		}
	}
	dialAddress := address
	if proxyURL != nil {
		if proxyURL.Scheme != "http" || proxyURL.Hostname() == "" {
			return nil, secure, false, errors.New("terminal transport requires an HTTP proxy")
		}
		proxyPort := proxyURL.Port()
		if proxyPort == "" {
			proxyPort = "80"
		}
		dialAddress = net.JoinHostPort(proxyURL.Hostname(), proxyPort)
	}
	if secure && proxyURL == nil && dialer.NetDialTLSContext != nil {
		connection, err := dialer.NetDialTLSContext(ctx, "tcp", dialAddress)
		return connection, secure, false, classifyWebSocketTransportError(ctx, err)
	}
	var connection net.Conn
	if dialer.NetDialContext != nil {
		connection, err = dialer.NetDialContext(ctx, "tcp", dialAddress)
	} else if dialer.NetDial != nil {
		connection, err = dialer.NetDial("tcp", dialAddress)
	} else {
		connection, err = (&net.Dialer{}).DialContext(ctx, "tcp", dialAddress)
	}
	if err != nil {
		return nil, secure, false, classifyWebSocketTransportError(ctx, err)
	}
	if proxyURL != nil && !secure {
		return connection, false, true, nil
	}
	if proxyURL != nil {
		if err := connectWebSocketProxy(ctx, connection, address, proxyURL); err != nil {
			_ = connection.Close()
			return nil, true, false, classifyWebSocketTransportError(ctx, err)
		}
	}
	if !secure {
		return connection, false, false, nil
	}
	tlsConfig := &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12, ClientSessionCache: t.clientSessionCache()}
	if dialer.TLSClientConfig != nil {
		tlsConfig = dialer.TLSClientConfig.Clone()
		tlsConfig.ServerName = u.Hostname()
		if tlsConfig.ClientSessionCache == nil {
			tlsConfig.ClientSessionCache = t.clientSessionCache()
		}
	}
	tlsConnection := tls.Client(connection, tlsConfig)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		_ = connection.Close()
		return nil, true, false, classifyWebSocketTransportError(ctx, err)
	}
	return tlsConnection, true, false, nil
}

func connectWebSocketProxy(ctx context.Context, connection net.Conn, target string, proxy *url.URL) error {
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	if proxy.User != nil {
		password, _ := proxy.User.Password()
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(proxy.User.Username()+":"+password)))
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	if err := request.Write(connection); err != nil {
		stop()
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if !stop() && ctx.Err() != nil {
		return ctx.Err()
	}
	_ = connection.SetDeadline(time.Time{})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP proxy CONNECT returned status %d", response.StatusCode)
	}
	return nil
}

func (t *WebSocketTunnel) clientSessionCache() tls.ClientSessionCache {
	t.sessionCacheOnce.Do(func() { t.sessionCache = tls.NewLRUClientSessionCache(64) })
	return t.sessionCache
}

func classifyWebSocketTransportError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	return classifyWebSocketDialError(ctx, err)
}

func classifyWebSocketDialError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if certificateError(err) {
		return fmt.Errorf("verify WSS terminal certificate: %w", err)
	}
	return &terminalTransportError{transport: "WSS", cause: err}
}

func classifyWebSocketUpgradeError(ctx context.Context, err error, response *http.Response) error {
	if response == nil {
		return classifyWebSocketDialError(ctx, err)
	}
	cause := fmt.Errorf("dial terminal websocket: %w (status %d)", err, response.StatusCode)
	switch response.StatusCode {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return &terminalTransportError{transport: "WSS", cause: cause}
	default:
		return cause
	}
}

func helperDialer(input *websocket.Dialer) *websocket.Dialer {
	if input == nil {
		input = websocket.DefaultDialer
	}
	dialer := *input
	dialer.Subprotocols = []string{helperWebSocketSubprotocol}
	return &dialer
}

func terminalWebSocketRequest(target *resolver.TerminalTarget) (string, http.Header, error) {
	base := strings.TrimRight(target.WSSEndpoint, "/")
	if base == "" {
		return "", nil, errors.New("missing terminal websocket base URL")
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", nil, fmt.Errorf("parse terminal websocket URL: %w", err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return "", nil, fmt.Errorf("terminal websocket URL must use ws or wss, got %q", u.Scheme)
	}
	headers := make(http.Header)
	if target.Auth.Method != "bearer" || target.Auth.Token == "" {
		return "", nil, errors.New("terminal WebSocket requires a bearer credential")
	}
	headers.Set("Authorization", "Bearer "+target.Auth.Token)
	return u.String(), headers, nil
}

var _ Tunnel = (*WebSocketTunnel)(nil)
