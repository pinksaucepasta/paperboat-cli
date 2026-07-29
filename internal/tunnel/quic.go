package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-cli/internal/resolver"
	"github.com/quic-go/quic-go"
)

const (
	nativeALPN             = "paperboat-terminal/1"
	nativeVersion     byte = 1
	nativeRoleControl byte = 1
	nativeRoleInput   byte = 2
	nativeRoleOutput  byte = 3
	nativeBindingSize      = 32
	nativeMaxRecord        = 1 << 20
	nativeStructured  byte = 1
	nativeBinary      byte = 2
)

var nativeMagic = [4]byte{'P', 'B', 'T', '1'}

type QUICTunnel struct {
	OutputQueueChunks int
	TLSConfig         *tls.Config
	QUICConfig        *quic.Config
	DialQUIC          func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error)
}

func NewQUICTunnel() *QUICTunnel {
	return &QUICTunnel{OutputQueueChunks: terminalOutputQueueChunks, TLSConfig: &tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(64)}}
}

type preparedNativeTerminal struct {
	connection *quic.Conn
	target     *resolver.TerminalTarget
	queue      int
	once       sync.Once
}

func (p *preparedNativeTerminal) Attach(ctx context.Context) (Conn, error) {
	var result Conn
	var resultErr error
	p.once.Do(func() {
		message, err := authenticateNativeConnection(ctx, p.connection, p.target)
		if err != nil {
			_ = p.connection.CloseWithError(1, "authentication_failed")
			resultErr = err
			return
		}
		connection := newHelperTerminalConn(message, p.target, p.queue)
		resultErr = connection.initialize(ctx)
		if resultErr != nil {
			_ = message.Close()
			return
		}
		result = connection
	})
	if result == nil && resultErr == nil {
		return nil, errors.New("prepared terminal already consumed")
	}
	return result, resultErr
}

func (p *preparedNativeTerminal) Close() error {
	return p.connection.CloseWithError(0, "closed")
}

type terminalTransportError struct {
	transport string
	cause     error
}

func (e *terminalTransportError) Error() string {
	return fmt.Sprintf("%s terminal transport unavailable: %v", e.transport, e.cause)
}
func (e *terminalTransportError) Unwrap() error { return e.cause }
func FallbackEligible(err error) bool {
	var target *terminalTransportError
	return errors.As(err, &target)
}

func (t *QUICTunnel) Dial(ctx context.Context, info resolver.ConnectInfo) (Conn, error) {
	prepared, err := t.Establish(ctx, info)
	if err != nil {
		return nil, err
	}
	return prepared.Attach(ctx)
}

func (t *QUICTunnel) Establish(ctx context.Context, info resolver.ConnectInfo) (preparedTerminal, error) {
	if info.Terminal == nil || info.Terminal.Protocol != "paperboat.terminal.v2" {
		return nil, errors.New("native QUIC requires terminal protocol v2")
	}
	connection, err := t.dialTransport(ctx, info.Terminal)
	if err != nil {
		return nil, err
	}
	return &preparedNativeTerminal{connection: connection, target: info.Terminal, queue: t.outputQueueChunks()}, nil
}

func (t *QUICTunnel) Check(ctx context.Context, target *resolver.TerminalTarget) error {
	message, err := t.dialMessage(ctx, target)
	if err != nil {
		return err
	}
	defer message.Close()
	return helperCheck(ctx, message)
}

func (t *QUICTunnel) outputQueueChunks() int {
	if t.OutputQueueChunks > 0 {
		return t.OutputQueueChunks
	}
	return terminalOutputQueueChunks
}

func (t *QUICTunnel) dialMessage(ctx context.Context, target *resolver.TerminalTarget) (*nativeMessageConnection, error) {
	connection, err := t.dialTransport(ctx, target)
	if err != nil {
		return nil, err
	}
	message, err := authenticateNativeConnection(ctx, connection, target)
	if err != nil {
		_ = connection.CloseWithError(1, "authentication_failed")
		return nil, err
	}
	return message, nil
}

func (t *QUICTunnel) dialTransport(ctx context.Context, target *resolver.TerminalTarget) (*quic.Conn, error) {
	address, serverName, err := nativeEndpoint(target)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, NextProtos: []string{nativeALPN}}
	if t.TLSConfig != nil {
		tlsConfig = t.TLSConfig.Clone()
		tlsConfig.ServerName = serverName
		tlsConfig.NextProtos = []string{nativeALPN}
	}
	quicConfig := &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 2 * time.Minute, KeepAlivePeriod: 15 * time.Second, MaxIncomingStreams: 0, MaxIncomingUniStreams: 0, EnableDatagrams: false}
	if t.QUICConfig != nil {
		quicConfig = t.QUICConfig.Clone()
	}
	dial := t.DialQUIC
	if dial == nil {
		dial = quic.DialAddr
	}
	connection, err := dial(ctx, address, tlsConfig, quicConfig)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if certificateError(err) {
			return nil, fmt.Errorf("verify native QUIC terminal certificate: %w", err)
		}
		return nil, &terminalTransportError{transport: "QUIC", cause: fmt.Errorf("dial %s: %w", address, err)}
	}
	return connection, nil
}

func authenticateNativeConnection(ctx context.Context, connection *quic.Conn, target *resolver.TerminalTarget) (*nativeMessageConnection, error) {
	var id [16]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		_ = connection.CloseWithError(1, "random_failed")
		return nil, err
	}
	control, err := connection.OpenStreamSync(ctx)
	if err != nil {
		_ = connection.CloseWithError(1, "control_failed")
		return nil, &terminalTransportError{transport: "QUIC", cause: err}
	}
	if err := writeNativePreface(control, nativeRoleControl, id, nil, target.Auth.Token); err != nil {
		_ = connection.CloseWithError(1, "preface_failed")
		return nil, err
	}
	message := newNativeMessageConnection(connection, control)
	binding, err := nativeHandshake(ctx, message)
	if err != nil {
		_ = message.Close()
		return nil, err
	}
	input, err := connection.OpenStreamSync(ctx)
	if err == nil {
		err = writeNativePreface(input, nativeRoleInput, id, binding, "")
	}
	if err != nil {
		_ = message.Close()
		return nil, &terminalTransportError{transport: "QUIC", cause: err}
	}
	output, err := connection.OpenStreamSync(ctx)
	if err == nil {
		err = writeNativePreface(output, nativeRoleOutput, id, binding, "")
	}
	if err != nil {
		_ = message.Close()
		return nil, &terminalTransportError{transport: "QUIC", cause: err}
	}
	message.attach(input, output)
	return message, nil
}

func nativeEndpoint(target *resolver.TerminalTarget) (string, string, error) {
	if target == nil || target.Auth.Method != "bearer" || target.Auth.Token == "" {
		return "", "", errors.New("missing terminal bearer credential")
	}
	u, err := url.Parse(target.QUICEndpoint)
	if err != nil || u.Scheme != "quic" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", errors.New("invalid native QUIC endpoint")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port), u.Hostname(), nil
}

func certificateError(err error) bool {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid)
}

func nativeHandshake(ctx context.Context, message helperMessageConnection) ([]byte, error) {
	payload, _ := json.Marshal(map[string]any{"min_version": helperProtocolVersion, "max_version": helperProtocolVersion, "capabilities": []string{"terminal.v2", "health.v1"}})
	id := helperID("req_")
	if err := writeHelperFrame(ctx, message, helperFrame{Type: "hello", RequestID: id, Version: helperProtocolVersion, Payload: payload}); err != nil {
		return nil, err
	}
	frame, err := readHelperStructured(ctx, message)
	if err != nil {
		return nil, err
	}
	if frame.Type == "error" {
		return nil, decodeHelperError(frame)
	}
	var welcome struct {
		Version      string   `json:"version"`
		Capabilities []string `json:"capabilities"`
		Binding      []byte   `json:"binding_secret"`
	}
	if frame.Type != "welcome" || frame.RequestID != id || json.Unmarshal(frame.Payload, &welcome) != nil || welcome.Version != helperProtocolVersion || len(welcome.Binding) != nativeBindingSize || !containsString(welcome.Capabilities, "terminal.v2") || !containsString(welcome.Capabilities, "health.v1") {
		return nil, errors.New("helper returned an invalid native protocol welcome")
	}
	return welcome.Binding, nil
}

type nativeMessageConnection struct {
	connection *quic.Conn
	control    *quic.Stream
	input      *quic.Stream
	output     *quic.Stream
	ctx        context.Context
	cancel     context.CancelFunc
	reads      chan nativeMessage
	writeMu    sync.Mutex
	closeOnce  sync.Once
}
type nativeMessage struct {
	kind helperMessageType
	data []byte
	err  error
}

func newNativeMessageConnection(connection *quic.Conn, control *quic.Stream) *nativeMessageConnection {
	ctx, cancel := context.WithCancel(context.Background())
	c := &nativeMessageConnection{connection: connection, control: control, ctx: ctx, cancel: cancel, reads: make(chan nativeMessage, 2)}
	go c.read(control, true)
	return c
}
func (c *nativeMessageConnection) attach(input, output *quic.Stream) {
	c.input, c.output = input, output
	go c.read(output, false)
}
func (c *nativeMessageConnection) read(stream io.Reader, typed bool) {
	for {
		kind, data, err := readNativeRecord(stream, typed)
		messageKind := helperBinaryMessage
		if kind == nativeStructured {
			messageKind = helperStructuredMessage
		}
		select {
		case c.reads <- nativeMessage{messageKind, data, err}:
		case <-c.ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}
func (c *nativeMessageConnection) ReadMessage(ctx context.Context) (helperMessageType, []byte, error) {
	select {
	case result := <-c.reads:
		return result.kind, result.data, result.err
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	case <-c.ctx.Done():
		return 0, nil, io.EOF
	}
}
func (c *nativeMessageConnection) WriteMessage(ctx context.Context, kind helperMessageType, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	stream := c.control
	typed := true
	recordKind := nativeStructured
	if kind == helperBinaryMessage {
		recordKind = nativeBinary
		if len(data) > 0 && data[0] == 1 {
			if c.input == nil {
				return errors.New("native input stream unavailable")
			}
			stream = c.input
			typed = false
		}
	} else if kind != helperStructuredMessage {
		return errors.New("invalid helper message type")
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetWriteDeadline(deadline)
	}
	cancelDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = stream.SetWriteDeadline(time.Now()); close(cancelDone) })
	err := writeNativeRecord(stream, recordKind, data, typed)
	if !stop() {
		<-cancelDone
	}
	_ = stream.SetWriteDeadline(time.Time{})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if c.ctx.Err() != nil {
		return io.EOF
	}
	return err
}
func (c *nativeMessageConnection) Close() error {
	c.closeOnce.Do(func() { c.cancel(); _ = c.connection.CloseWithError(0, "closed") })
	return nil
}

func writeNativePreface(w io.Writer, role byte, id [16]byte, binding []byte, token string) error {
	buffer := make([]byte, 26+len(binding)+len(token))
	copy(buffer, nativeMagic[:])
	buffer[4], buffer[5] = nativeVersion, role
	copy(buffer[6:22], id[:])
	binary.BigEndian.PutUint16(buffer[22:24], uint16(len(binding)))
	binary.BigEndian.PutUint16(buffer[24:26], uint16(len(token)))
	copy(buffer[26:], binding)
	copy(buffer[26+len(binding):], token)
	return writeNativeFull(w, buffer)
}
func readNativeRecord(r io.Reader, typed bool) (byte, []byte, error) {
	size := 4
	if typed {
		size = 5
	}
	header := make([]byte, size)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	kind := nativeBinary
	offset := 0
	if typed {
		kind = header[0]
		offset = 1
		if kind != nativeStructured && kind != nativeBinary {
			return 0, nil, errors.New("invalid native record kind")
		}
	}
	length := binary.BigEndian.Uint32(header[offset:])
	if length == 0 || length > nativeMaxRecord {
		return 0, nil, errors.New("invalid native record length")
	}
	data := make([]byte, length)
	_, err := io.ReadFull(r, data)
	return kind, data, err
}
func writeNativeRecord(w io.Writer, kind byte, data []byte, typed bool) error {
	if len(data) == 0 || len(data) > nativeMaxRecord || typed && kind != nativeStructured && kind != nativeBinary {
		return errors.New("invalid native record length")
	}
	size := 4
	if typed {
		size = 5
	}
	record := make([]byte, size+len(data))
	if typed {
		record[0] = kind
	}
	binary.BigEndian.PutUint32(record[size-4:size], uint32(len(data)))
	copy(record[size:], data)
	return writeNativeFull(w, record)
}
func writeNativeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
