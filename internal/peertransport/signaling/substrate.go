package signaling

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

const substrateMaximumChannels = 256

const (
	substrateKeepaliveInterval = 20 * time.Second
	substrateKeepaliveTimeout  = 5 * time.Second
	substrateReconnectMinimum  = time.Second
	substrateReconnectMaximum  = 30 * time.Second
)

// Substrate owns one daemon-lifetime physical signaling connection and opens
// independently authorized logical attempt channels over it.
type Substrate struct {
	config WebSocketConfig

	mu          sync.Mutex
	connection  *websocket.Conn
	lifetime    context.Context
	cancel      context.CancelFunc
	channels    map[uint64]*substrateChannel
	next        atomic.Uint64
	dialing     chan struct{}
	maintaining bool
	closed      bool
	writeMu     sync.Mutex
}

type substrateChannel struct {
	ready chan error
	inbox chan []byte
	done  chan struct{}
	once  sync.Once
}

type SubstrateTransport struct {
	owner   *Substrate
	id      uint64
	channel *substrateChannel
	once    sync.Once
}

func NewSubstrate(config WebSocketConfig) (*Substrate, error) {
	if config.URL == "" || config.TLS != nil && (config.TLS.InsecureSkipVerify || config.TLS.MaxVersion != 0 && config.TLS.MaxVersion < tls.VersionTLS13) {
		return nil, ErrTransportInvalid
	}
	target, err := url.Parse(config.URL)
	if err != nil || target.Scheme != "wss" || target.Host == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return nil, ErrTransportInvalid
	}
	config.Credential = ""
	lifetime, cancel := context.WithCancel(context.Background())
	return &Substrate{config: config, lifetime: lifetime, cancel: cancel, channels: make(map[uint64]*substrateChannel)}, nil
}

func (s *Substrate) Warm(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrTransportInvalid
	}
	s.startMaintenance()
	return s.ensureConnected(ctx)
}

func (s *Substrate) Open(ctx context.Context, credential string) (*SubstrateTransport, error) {
	if s == nil || ctx == nil || !validWebSocketCredential(credential) {
		return nil, ErrTransportInvalid
	}
	s.startMaintenance()
	if err := s.ensureConnected(ctx); err != nil {
		return nil, err
	}
	id := s.next.Add(1)
	if id == 0 {
		return nil, ErrTransportUnavailable
	}
	channel := &substrateChannel{ready: make(chan error, 1), inbox: make(chan []byte, 128), done: make(chan struct{})}
	s.mu.Lock()
	if s.closed || s.connection == nil || len(s.channels) >= substrateMaximumChannels {
		s.mu.Unlock()
		return nil, ErrTransportUnavailable
	}
	s.channels[id] = channel
	s.mu.Unlock()
	if err := s.write(ctx, substrateFrame{kind: substrateAttach, channel: id, body: []byte(credential)}); err != nil {
		s.remove(id, err)
		return nil, err
	}
	select {
	case err := <-channel.ready:
		if err != nil {
			s.remove(id, err)
			return nil, err
		}
		return &SubstrateTransport{owner: s, id: id, channel: channel}, nil
	case <-ctx.Done():
		s.remove(id, ctx.Err())
		_ = s.write(context.Background(), substrateFrame{kind: substrateAbort, channel: id})
		return nil, ctx.Err()
	case <-channel.done:
		return nil, ErrTransportUnavailable
	}
}

func (s *Substrate) startMaintenance() {
	s.mu.Lock()
	if s.closed || s.maintaining {
		s.mu.Unlock()
		return
	}
	s.maintaining = true
	s.mu.Unlock()
	go s.maintain()
}

func (s *Substrate) maintain() {
	backoff := substrateReconnectMinimum
	for {
		select {
		case <-s.lifetime.Done():
			return
		default:
		}
		connectCtx, cancel := context.WithTimeout(s.lifetime, substrateKeepaliveTimeout)
		err := s.ensureConnected(connectCtx)
		cancel()
		if err != nil {
			timer := time.NewTimer(backoff)
			select {
			case <-timer.C:
			case <-s.lifetime.Done():
				timer.Stop()
				return
			}
			backoff *= 2
			if backoff > substrateReconnectMaximum {
				backoff = substrateReconnectMaximum
			}
			continue
		}
		backoff = substrateReconnectMinimum
		timer := time.NewTimer(substrateKeepaliveInterval)
		select {
		case <-timer.C:
		case <-s.lifetime.Done():
			timer.Stop()
			return
		}
		s.mu.Lock()
		connection := s.connection
		s.mu.Unlock()
		if connection == nil {
			continue
		}
		pingCtx, pingCancel := context.WithTimeout(s.lifetime, substrateKeepaliveTimeout)
		s.writeMu.Lock()
		err = connection.Ping(pingCtx)
		s.writeMu.Unlock()
		pingCancel()
		if err != nil {
			s.failConnection(connection, err)
		}
	}
}

func (s *Substrate) ensureConnected(ctx context.Context) error {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return errSubstrateClosed
		}
		if s.connection != nil {
			s.mu.Unlock()
			return nil
		}
		if s.dialing != nil {
			waiting := s.dialing
			s.mu.Unlock()
			select {
			case <-waiting:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		waiting := make(chan struct{})
		s.dialing = waiting
		s.mu.Unlock()
		connection, err := s.dial(ctx)
		s.mu.Lock()
		if err == nil && !s.closed {
			s.connection = connection
			go s.readLoop(connection)
		} else if connection != nil {
			_ = connection.CloseNow()
		}
		s.dialing = nil
		close(waiting)
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return errSubstrateClosed
		}
		return err
	}
}

func (s *Substrate) dial(ctx context.Context) (*websocket.Conn, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if s.config.TLS != nil {
		tlsConfig = s.config.TLS.Clone()
		if tlsConfig.MinVersion < tls.VersionTLS13 {
			tlsConfig.MinVersion = tls.VersionTLS13
		}
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true, TLSClientConfig: tlsConfig}, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrTransportProtocol }}
	connection, response, err := websocket.Dial(ctx, s.config.URL, &websocket.DialOptions{HTTPClient: client, Subprotocols: []string{SubstrateSubprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		status := 0
		if response != nil && response.Body != nil {
			status = response.StatusCode
			_ = response.Body.Close()
		}
		return nil, classifyWebSocketDialError(ctx, status, err)
	}
	if connection.Subprotocol() != SubstrateSubprotocol {
		_ = connection.CloseNow()
		return nil, ErrTransportProtocol
	}
	connection.SetReadLimit(substrateHeaderSize + substrateMaximumBody)
	return connection, nil
}

func (s *Substrate) readLoop(connection *websocket.Conn) {
	for {
		messageType, raw, err := connection.Read(s.lifetime)
		if err != nil || messageType != websocket.MessageBinary {
			if err == nil {
				err = ErrTransportProtocol
			}
			s.failConnection(connection, err)
			return
		}
		frame, err := decodeSubstrateFrame(raw)
		if err != nil {
			s.failConnection(connection, err)
			return
		}
		s.mu.Lock()
		channel := s.channels[frame.channel]
		s.mu.Unlock()
		if channel == nil {
			continue
		}
		switch frame.kind {
		case substrateReady:
			select {
			case channel.ready <- nil:
			default:
			}
		case substrateRejected:
			select {
			case channel.ready <- ErrTransportAuthentication:
			default:
			}
		case substrateData:
			select {
			case channel.inbox <- frame.body:
			case <-channel.done:
			default:
				s.remove(frame.channel, ErrTransportProtocol)
				_ = s.write(context.Background(), substrateFrame{kind: substrateAbort, channel: frame.channel})
			}
		case substrateComplete, substrateAbort:
			s.remove(frame.channel, io.EOF)
		default:
			s.failConnection(connection, ErrTransportProtocol)
			return
		}
	}
}

func (s *Substrate) write(ctx context.Context, frame substrateFrame) error {
	raw, err := encodeSubstrateFrame(frame)
	if err != nil {
		return err
	}
	s.mu.Lock()
	connection := s.connection
	s.mu.Unlock()
	if connection == nil {
		return ErrTransportUnavailable
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := connection.Write(ctx, websocket.MessageBinary, raw); err != nil {
		s.failConnection(connection, err)
		return ErrTransportUnavailable
	}
	return nil
}

func (s *Substrate) failConnection(connection *websocket.Conn, cause error) {
	s.mu.Lock()
	if s.connection != connection {
		s.mu.Unlock()
		return
	}
	s.connection = nil
	channels := s.channels
	s.channels = make(map[uint64]*substrateChannel)
	s.mu.Unlock()
	_ = connection.CloseNow()
	for _, channel := range channels {
		channel.once.Do(func() { close(channel.done) })
		select {
		case channel.ready <- errors.Join(ErrTransportUnavailable, cause):
		default:
		}
	}
}

func (s *Substrate) remove(id uint64, _ error) {
	s.mu.Lock()
	channel := s.channels[id]
	delete(s.channels, id)
	s.mu.Unlock()
	if channel != nil {
		channel.once.Do(func() { close(channel.done) })
	}
}

func (s *Substrate) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	connection := s.connection
	s.connection = nil
	channels := s.channels
	s.channels = make(map[uint64]*substrateChannel)
	s.mu.Unlock()
	s.cancel()
	for _, channel := range channels {
		channel.once.Do(func() { close(channel.done) })
	}
	if connection != nil {
		return connection.Close(websocket.StatusNormalClosure, "daemon shutdown")
	}
	return nil
}

func (t *SubstrateTransport) Send(ctx context.Context, raw []byte) error {
	if t == nil || t.owner == nil || ctx == nil || len(raw) == 0 || len(raw) > MaximumMessage {
		return ErrTransportInvalid
	}
	select {
	case <-t.channel.done:
		return ErrTransportUnavailable
	default:
	}
	return t.owner.write(ctx, substrateFrame{kind: substrateData, channel: t.id, body: raw})
}

func (t *SubstrateTransport) Receive(ctx context.Context) ([]byte, error) {
	if t == nil || t.owner == nil || ctx == nil {
		return nil, ErrTransportInvalid
	}
	select {
	case raw := <-t.channel.inbox:
		return append([]byte(nil), raw...), nil
	case <-t.channel.done:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *SubstrateTransport) Close() error {
	if t == nil || t.owner == nil {
		return nil
	}
	t.once.Do(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = t.owner.write(closeCtx, substrateFrame{kind: substrateComplete, channel: t.id})
		cancel()
		t.owner.remove(t.id, io.EOF)
	})
	return nil
}
