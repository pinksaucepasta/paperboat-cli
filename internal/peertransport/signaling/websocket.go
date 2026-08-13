package signaling

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/pinksaucepasta/paperboat/internal/diagnosticlog"
)

const WebSocketSubprotocol = "paperboat.peer-signaling.v1"

var (
	ErrTransportInvalid        = errors.New("invalid peer signaling transport")
	ErrTransportProtocol       = errors.New("peer signaling transport protocol violation")
	ErrTransportAuthentication = errors.New("peer signaling authentication failed")
	ErrTransportCertificate    = errors.New("peer signaling certificate verification failed")
	ErrTransportUnavailable    = errors.New("peer signaling transport unavailable")
)

type WebSocketConfig struct {
	URL        string
	Credential string
	TLS        *tls.Config
}

type WebSocketTransport struct {
	connection *websocket.Conn
	lifetime   context.Context
	cancel     context.CancelFunc
	sendMu     sync.Mutex
	receiveMu  sync.Mutex
	closeOnce  sync.Once
	closeErr   error
}

func DialWebSocket(ctx context.Context, config WebSocketConfig) (*WebSocketTransport, error) {
	if ctx == nil {
		return nil, ErrTransportInvalid
	}
	if err := ValidateWebSocketConfig(config); err != nil {
		return nil, err
	}
	target, _ := url.Parse(config.URL)
	started := time.Now()
	timing := map[string]int64{}
	var timingMu sync.Mutex
	mark := func(name string) {
		timingMu.Lock()
		timing[name] = time.Since(started).Milliseconds()
		timingMu.Unlock()
	}
	defer func() {
		timingMu.Lock()
		snapshot := make(map[string]int64, len(timing))
		for name, elapsed := range timing {
			snapshot[name] = elapsed
		}
		timingMu.Unlock()
		diagnosticlog.TryInfo("peer signaling dial timing", "milestones_ms", snapshot, "elapsed_ms", time.Since(started).Milliseconds())
	}()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if config.TLS != nil {
		tlsConfig = config.TLS.Clone()
		if tlsConfig.InsecureSkipVerify || tlsConfig.MaxVersion != 0 && tlsConfig.MaxVersion < tls.VersionTLS13 {
			return nil, ErrTransportInvalid
		}
		if tlsConfig.MinVersion < tls.VersionTLS13 {
			tlsConfig.MinVersion = tls.VersionTLS13
		}
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true, TLSClientConfig: tlsConfig},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("peer signaling redirects are forbidden")
		},
	}
	headers := http.Header{"Authorization": []string{"Bearer " + config.Credential}}
	trace := &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { mark("dns_start") },
		DNSDone:              func(httptrace.DNSDoneInfo) { mark("dns_done") },
		ConnectStart:         func(_, _ string) { mark("connect_start") },
		ConnectDone:          func(_, _ string, _ error) { mark("connect_done") },
		TLSHandshakeStart:    func() { mark("tls_start") },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { mark("tls_done") },
		WroteRequest:         func(httptrace.WroteRequestInfo) { mark("request_written") },
		GotFirstResponseByte: func() { mark("response_first_byte") },
	}
	dialCtx := httptrace.WithClientTrace(ctx, trace)
	connection, response, err := websocket.Dial(dialCtx, target.String(), &websocket.DialOptions{HTTPClient: client, HTTPHeader: headers, Subprotocols: []string{WebSocketSubprotocol}, CompressionMode: websocket.CompressionDisabled})
	mark("websocket_ready")
	if err != nil {
		status := 0
		if response != nil && response.Body != nil {
			status = response.StatusCode
			_ = response.Body.Close()
		}
		return nil, classifyWebSocketDialError(ctx, status, err)
	}
	if connection.Subprotocol() != WebSocketSubprotocol {
		_ = connection.CloseNow()
		return nil, ErrTransportProtocol
	}
	connection.SetReadLimit(MaximumMessage)
	lifetime, cancel := context.WithCancel(ctx)
	return &WebSocketTransport{connection: connection, lifetime: lifetime, cancel: cancel}, nil
}

func ValidateWebSocketConfig(config WebSocketConfig) error {
	if !validWebSocketCredential(config.Credential) {
		return ErrTransportInvalid
	}
	target, err := url.Parse(config.URL)
	if err != nil || target.Scheme != "wss" || target.Host == "" || target.User != nil || target.Fragment != "" || target.RawQuery != "" || target.Opaque != "" {
		return ErrTransportInvalid
	}
	if config.TLS != nil && (config.TLS.InsecureSkipVerify || config.TLS.MaxVersion != 0 && config.TLS.MaxVersion < tls.VersionTLS13) {
		return ErrTransportInvalid
	}
	return nil
}

func classifyWebSocketDialError(ctx context.Context, status int, cause error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(cause, &unknownAuthority) || errors.As(cause, &hostname) || errors.As(cause, &invalid) {
		return fmt.Errorf("%w: %v", ErrTransportCertificate, cause)
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: admission status %d", ErrTransportAuthentication, status)
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return fmt.Errorf("%w: admission status %d", ErrTransportUnavailable, status)
	default:
		if status >= 500 {
			return fmt.Errorf("%w: admission status %d", ErrTransportUnavailable, status)
		}
		return fmt.Errorf("%w: %v", ErrTransportProtocol, cause)
	}
}

func validWebSocketCredential(value string) bool {
	if len(value) == 0 || len(value) > 8<<10 || strings.Count(value, ".") != 2 {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if part == "" {
			return false
		}
		for _, character := range part {
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
				continue
			}
			return false
		}
	}
	return true
}

func (t *WebSocketTransport) Send(ctx context.Context, raw []byte) error {
	if t == nil || t.connection == nil || ctx == nil || len(raw) == 0 || len(raw) > MaximumMessage {
		return ErrTransportInvalid
	}
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	opCtx, cancel := t.operationContext(ctx)
	defer cancel()
	if err := t.connection.Write(opCtx, websocket.MessageBinary, raw); err != nil {
		return fmt.Errorf("write peer signaling message: %w", err)
	}
	return nil
}

func (t *WebSocketTransport) Receive(ctx context.Context) ([]byte, error) {
	if t == nil || t.connection == nil || ctx == nil {
		return nil, ErrTransportInvalid
	}
	t.receiveMu.Lock()
	defer t.receiveMu.Unlock()
	opCtx, cancel := t.operationContext(ctx)
	defer cancel()
	messageType, raw, err := t.connection.Read(opCtx)
	if err != nil {
		return nil, fmt.Errorf("read peer signaling message: %w", err)
	}
	if messageType != websocket.MessageBinary || len(raw) == 0 || len(raw) > MaximumMessage {
		return nil, ErrTransportProtocol
	}
	return append([]byte(nil), raw...), nil
}

func (t *WebSocketTransport) Close() error {
	if t == nil || t.connection == nil {
		return nil
	}
	t.closeOnce.Do(func() {
		t.cancel()
		t.closeErr = t.connection.Close(websocket.StatusNormalClosure, "signaling complete")
		if errors.Is(t.closeErr, io.EOF) {
			t.closeErr = nil
		}
	})
	return t.closeErr
}

func (t *WebSocketTransport) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	opCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(t.lifetime, cancel)
	return opCtx, func() {
		stop()
		cancel()
	}
}
