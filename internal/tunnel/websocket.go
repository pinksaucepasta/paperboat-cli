package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat/internal/httptransport"
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
	transportConfig   httptransport.Config
	OutputQueueChunks int
	sessionCache      tls.ClientSessionCache
	sessionCacheOnce  sync.Once
}

func NewWebSocketTunnel() *WebSocketTunnel {
	config := httptransport.DevelopmentConfig()
	config.ForceAttemptHTTP2 = false
	config.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ClientSessionCache: tls.NewLRUClientSessionCache(64)}
	return &WebSocketTunnel{transportConfig: config, OutputQueueChunks: terminalOutputQueueChunks}
}

func (t *WebSocketTunnel) outputQueueChunks() int {
	if t.OutputQueueChunks > 0 {
		return t.OutputQueueChunks
	}
	return terminalOutputQueueChunks
}

type preparedWebSocketTerminal struct {
	connection      net.Conn
	transportConfig httptransport.Config
	url             string
	headers         http.Header
	target          *resolver.TerminalTarget
	queue           int
	tls             bool
	proxy           bool
	once            sync.Once
}

func (p *preparedWebSocketTerminal) Attach(ctx context.Context) (Conn, error) {
	var result Conn
	var resultErr error
	p.once.Do(func() {
		config := p.transportConfig
		if !p.proxy {
			config.ProxySource = httptransport.StaticProxySource{}
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
			config.DialTLSContext = preparedDial
		} else {
			config.DialContext = preparedDial
		}
		ws, response, err := dialWebSocket(ctx, config, p.url, p.headers)
		if err != nil {
			_ = p.connection.Close()
			resultErr = classifyWebSocketUpgradeError(ctx, err, response)
			return
		}
		message := &helperWebSocketConnection{ws: ws}
		if _, err := helperHandshake(ctx, message); err != nil {
			_ = ws.Close(websocket.StatusInternalError, "handshake_failed")
			resultErr = err
			return
		}
		connection, err := newInitializedHelperTerminalConn(ctx, message, p.target, p.queue)
		if err != nil {
			_ = ws.Close(websocket.StatusInternalError, "initialize_failed")
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
	ws, resp, err := dialWebSocket(ctx, t.transportConfig, wsURL, headers)
	if err != nil {
		return classifyWebSocketUpgradeError(ctx, err, resp)
	}
	defer ws.Close(websocket.StatusNormalClosure, "")
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
	connection, secure, proxy, snapshot, err := t.dialTransport(ctx, t.transportConfig, wsURL)
	if err != nil {
		return nil, err
	}
	config := t.transportConfig
	config.ProxySource = httptransport.StaticProxySource{Value: snapshot}
	return &preparedWebSocketTerminal{connection: connection, transportConfig: config, url: wsURL, headers: headers, target: info.Terminal, queue: t.outputQueueChunks(), tls: secure, proxy: proxy}, nil
}

func (t *WebSocketTunnel) dialTransport(ctx context.Context, config httptransport.Config, target string) (net.Conn, bool, bool, httptransport.ProxySnapshot, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, false, false, httptransport.ProxySnapshot{}, err
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
	snapshot, proxyURL, err := httptransport.ResolveProxy(ctx, config.ProxySource, request.URL)
	if err != nil {
		return nil, secure, false, httptransport.ProxySnapshot{}, err
	}
	dialAddress := address
	if proxyURL != nil {
		if proxyURL.Scheme != "http" || proxyURL.Hostname() == "" {
			return nil, secure, false, snapshot, errors.New("terminal transport requires an HTTP proxy")
		}
		proxyPort := proxyURL.Port()
		if proxyPort == "" {
			proxyPort = "80"
		}
		dialAddress = net.JoinHostPort(proxyURL.Hostname(), proxyPort)
	}
	if secure && proxyURL == nil && config.DialTLSContext != nil {
		connection, err := config.DialTLSContext(ctx, "tcp", dialAddress)
		return connection, secure, false, snapshot, classifyWebSocketTransportError(ctx, err)
	}
	var connection net.Conn
	if config.DialContext != nil {
		connection, err = config.DialContext(ctx, "tcp", dialAddress)
	} else {
		connection, err = (&net.Dialer{}).DialContext(ctx, "tcp", dialAddress)
	}
	if err != nil {
		return nil, secure, false, snapshot, classifyWebSocketTransportError(ctx, err)
	}
	if proxyURL != nil && !secure {
		return connection, false, true, snapshot, nil
	}
	if proxyURL != nil {
		if err := connectWebSocketProxy(ctx, connection, address, proxyURL); err != nil {
			_ = connection.Close()
			return nil, true, false, snapshot, classifyWebSocketTransportError(ctx, err)
		}
	}
	if !secure {
		return connection, false, false, snapshot, nil
	}
	tlsConfig := &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12, ClientSessionCache: t.clientSessionCache()}
	if config.TLSConfig != nil {
		tlsConfig = config.TLSConfig.Clone()
		tlsConfig.ServerName = u.Hostname()
		if tlsConfig.ClientSessionCache == nil {
			tlsConfig.ClientSessionCache = t.clientSessionCache()
		}
	}
	tlsConnection := tls.Client(connection, tlsConfig)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		_ = connection.Close()
		return nil, true, false, snapshot, classifyWebSocketTransportError(ctx, err)
	}
	return tlsConnection, true, false, snapshot, nil
}

func connectWebSocketProxy(ctx context.Context, connection net.Conn, target string, proxy *url.URL) error {
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
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
	if response.StatusCode == http.StatusProxyAuthRequired {
		return &httptransport.ProxyError{Failure: httptransport.ProxyAuthenticationRequired}
	}
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

func dialWebSocket(ctx context.Context, config httptransport.Config, target string, headers http.Header) (*websocket.Conn, *http.Response, error) {
	transport, err := httptransport.New(config)
	if err != nil {
		return nil, nil, err
	}
	client := &http.Client{Transport: transport}
	connection, response, err := websocket.Dial(ctx, target, &websocket.DialOptions{HTTPClient: client, HTTPHeader: headers, Subprotocols: []string{helperWebSocketSubprotocol}, CompressionMode: websocket.CompressionDisabled})
	transport.CloseIdleConnections()
	return connection, response, err
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
