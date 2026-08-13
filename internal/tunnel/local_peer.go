package tunnel

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const localPeerMaximumFrame = 1 << 20

const (
	localPeerData byte = iota + 1
	localPeerResize
	localPeerCloseWrite
	localPeerWait
	localPeerClose
	localPeerResult
	localPeerFailure
	localPeerExecEvent
	localPeerExecCancel
	localPeerExecSignal
	localPeerExecDetach
	localPeerClosed
)

type localPeerWriter struct {
	writer io.Writer
	mu     sync.Mutex
}

func (w *localPeerWriter) write(kind byte, payload []byte) error {
	if w == nil || w.writer == nil || len(payload) > localPeerMaximumFrame {
		return ErrPeerTerminalInvalid
	}
	header := [5]byte{kind}
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := writeNativeFull(w.writer, header[:]); err != nil {
		return err
	}
	return writeNativeFull(w.writer, payload)
}

func readLocalPeerFrame(reader io.Reader) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(header[1:])
	if size > localPeerMaximumFrame || header[0] < localPeerData || header[0] > localPeerClosed {
		return 0, nil, ErrPeerTerminalInvalid
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	return header[0], payload, nil
}

// ServeLocalPeerConn projects the terminal connection contract over one
// authenticated local Unix stream. The remote carrier remains daemon-owned.
func ServeLocalPeerConn(ctx context.Context, local net.Conn, remote Conn) error {
	if ctx == nil || local == nil || remote == nil {
		return ErrPeerTerminalInvalid
	}
	defer local.Close()
	defer remote.Close()
	writer := &localPeerWriter{writer: local}
	remoteExec, isExec := remote.(ExecConn)
	done := make(chan error, 3)
	outputDone := make(chan struct{})
	waitStarted := false
	if isExec {
		go func() {
			defer close(outputDone)
			terminal := false
			for event := range remoteExec.Events() {
				if event.Stream == "" && event.State != "" && event.State != "started" {
					terminal = true
				}
				encoded, err := json.Marshal(event)
				if err != nil || len(encoded) > localPeerMaximumFrame {
					done <- ErrPeerTerminalInvalid
					return
				}
				if err := writer.write(localPeerExecEvent, encoded); err != nil {
					done <- err
					return
				}
			}
			// An exec event stream can close normally only after its terminal
			// event. Without one, the remote operation outcome is unknown and
			// Wait may never unblock after a carrier or host failure.
			if !terminal {
				done <- ErrTransportLost
			}
		}()
	} else {
		go func() {
			defer close(outputDone)
			buffer := make([]byte, 32<<10)
			for {
				count, err := remote.Read(buffer)
				if count > 0 {
					if writeErr := writer.write(localPeerData, buffer[:count]); writeErr != nil {
						done <- writeErr
						return
					}
				}
				if err != nil {
					if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
						done <- err
					}
					return
				}
			}
		}()
	}
	go func() {
		for {
			kind, payload, err := readLocalPeerFrame(local)
			if err != nil {
				done <- err
				return
			}
			switch kind {
			case localPeerData:
				if _, err := remote.Write(payload); err != nil {
					done <- err
					return
				}
			case localPeerResize:
				if len(payload) != 4 {
					done <- ErrPeerTerminalInvalid
					return
				}
				rows, cols := binary.BigEndian.Uint16(payload[:2]), binary.BigEndian.Uint16(payload[2:])
				if resizeErr := remote.Resize(rows, cols); resizeErr != nil {
					done <- ErrPeerTerminalInvalid
					return
				}
			case localPeerCloseWrite:
				closer, ok := remote.(InputHalfCloser)
				if !ok || closer.CloseWrite() != nil {
					done <- ErrInputEOFUnsupported
					return
				}
			case localPeerWait:
				if waitStarted {
					done <- ErrPeerTerminalInvalid
					return
				}
				waitStarted = true
				go func() {
					code, waitErr := remote.Wait()
					if !isExec {
						<-outputDone
					}
					result := make([]byte, 4)
					binary.BigEndian.PutUint32(result, uint32(int32(code)))
					kind := localPeerResult
					if waitErr != nil {
						kind, result = localPeerFailure, nil
					}
					if err := writer.write(kind, result); err != nil {
						done <- err
					}
				}()
			case localPeerClose:
				closeErr := remote.Close()
				ackErr := writer.write(localPeerClosed, nil)
				done <- errors.Join(closeErr, ackErr)
				return
			case localPeerExecCancel:
				if !isExec || remoteExec.Cancel() != nil {
					done <- ErrPeerTerminalInvalid
					return
				}
			case localPeerExecSignal:
				if !isExec || len(payload) == 0 || len(payload) > 64 || remoteExec.Signal(string(payload)) != nil {
					done <- ErrPeerTerminalInvalid
					return
				}
			case localPeerExecDetach:
				if !isExec || remoteExec.Detach() != nil {
					done <- ErrPeerTerminalInvalid
					return
				}
			default:
				done <- ErrPeerTerminalInvalid
				return
			}
		}
	}()
	select {
	case err := <-done:
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

type localPeerConn struct {
	connection net.Conn
	writer     *localPeerWriter
	data       chan []byte
	result     chan localPeerWaitResult
	done       chan struct{}
	closed     chan struct{}
	events     chan ExecEvent
	exec       bool
	mu         sync.Mutex
	pending    []byte
	once       sync.Once
}

type localPeerWaitResult struct {
	code int
	err  error
}

func NewLocalPeerConn(connection net.Conn) (Conn, error) {
	value, err := newLocalPeerConn(connection, false)
	if err != nil {
		return nil, err
	}
	return &localBasicPeerConn{inner: value.(*localPeerConn)}, nil
}

type localBasicPeerConn struct{ inner *localPeerConn }

func (c *localBasicPeerConn) Read(v []byte) (int, error)     { return c.inner.Read(v) }
func (c *localBasicPeerConn) Write(v []byte) (int, error)    { return c.inner.Write(v) }
func (c *localBasicPeerConn) Close() error                   { return c.inner.Close() }
func (c *localBasicPeerConn) Resize(rows, cols uint16) error { return c.inner.Resize(rows, cols) }
func (c *localBasicPeerConn) Wait() (int, error)             { return c.inner.Wait() }
func (c *localBasicPeerConn) CloseWrite() error              { return c.inner.CloseWrite() }

func NewLocalExecPeerConn(connection net.Conn) (ExecConn, error) {
	value, err := newLocalPeerConn(connection, true)
	if err != nil {
		return nil, err
	}
	return value.(*localPeerConn), nil
}

func newLocalPeerConn(connection net.Conn, exec bool) (Conn, error) {
	if connection == nil {
		return nil, ErrPeerTerminalInvalid
	}
	value := &localPeerConn{connection: connection, writer: &localPeerWriter{writer: connection}, data: make(chan []byte, 16), result: make(chan localPeerWaitResult, 1), done: make(chan struct{}), closed: make(chan struct{}), events: make(chan ExecEvent, 256), exec: exec}
	go value.readLoop()
	return value, nil
}

func (c *localPeerConn) readLoop() {
	defer close(c.done)
	defer close(c.data)
	defer close(c.events)
	for {
		kind, payload, err := readLocalPeerFrame(c.connection)
		if err != nil {
			if !errors.Is(err, ErrPeerTerminalInvalid) {
				err = errors.Join(ErrTransportLost, err)
			}
			select {
			case c.result <- localPeerWaitResult{err: err}:
			default:
			}
			return
		}
		switch kind {
		case localPeerData:
			c.data <- payload
		case localPeerResult:
			if len(payload) != 4 {
				c.result <- localPeerWaitResult{err: ErrPeerTerminalInvalid}
				return
			}
			c.result <- localPeerWaitResult{code: int(int32(binary.BigEndian.Uint32(payload)))}
		case localPeerFailure:
			c.result <- localPeerWaitResult{err: ErrTransportLost}
		case localPeerExecEvent:
			if !c.exec {
				c.result <- localPeerWaitResult{err: ErrPeerTerminalInvalid}
				return
			}
			var event ExecEvent
			if json.Unmarshal(payload, &event) != nil || event.OperationID == "" {
				c.result <- localPeerWaitResult{err: ErrPeerTerminalInvalid}
				return
			}
			c.events <- event
			if event.Stream == "" && event.State != "" && event.State != "started" {
				result := localPeerWaitResult{}
				if event.Result != nil {
					result.code = event.Result.Code
					if result.code == 0 && event.Result.Signal != "" {
						result.code = signalExitCode(event.Result.Signal)
					}
				}
				if event.State == "failed" || event.State == "canceled" {
					result.err = &RemoteExecError{Code: firstNonEmptyExec(event.ErrorCode, event.State)}
				}
				select {
				case c.result <- result:
				default:
				}
			}
		case localPeerClosed:
			close(c.closed)
			return
		default:
			c.result <- localPeerWaitResult{err: ErrPeerTerminalInvalid}
			return
		}
	}
}

func (c *localPeerConn) Read(value []byte) (int, error) {
	c.mu.Lock()
	if len(c.pending) > 0 {
		count := copy(value, c.pending)
		c.pending = c.pending[count:]
		c.mu.Unlock()
		return count, nil
	}
	c.mu.Unlock()
	payload, ok := <-c.data
	if !ok {
		return 0, io.EOF
	}
	count := copy(value, payload)
	if count < len(payload) {
		c.mu.Lock()
		c.pending = append(c.pending, payload[count:]...)
		c.mu.Unlock()
	}
	return count, nil
}
func (c *localPeerConn) Write(value []byte) (int, error) {
	if err := c.writer.write(localPeerData, value); err != nil {
		return 0, err
	}
	return len(value), nil
}
func (c *localPeerConn) Resize(rows, cols uint16) error {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload, rows)
	binary.BigEndian.PutUint16(payload[2:], cols)
	return c.writer.write(localPeerResize, payload)
}
func (c *localPeerConn) CloseWrite() error { return c.writer.write(localPeerCloseWrite, nil) }
func (c *localPeerConn) Wait() (int, error) {
	select {
	case result := <-c.result:
		return result.code, result.err
	default:
	}
	if err := c.writer.write(localPeerWait, nil); err != nil {
		select {
		case result := <-c.result:
			return result.code, result.err
		default:
		}
		return 1, err
	}
	result := <-c.result
	return result.code, result.err
}
func (c *localPeerConn) Close() error {
	var err error
	c.once.Do(func() {
		if writeErr := c.writer.write(localPeerClose, nil); writeErr == nil {
			select {
			case <-c.closed:
			case <-c.done:
			case <-time.After(3 * time.Second):
			}
		}
		err = c.connection.Close()
	})
	return err
}

func (c *localPeerConn) Events() <-chan ExecEvent { return c.events }
func (c *localPeerConn) Cancel() error {
	if !c.exec {
		return ErrPeerTerminalInvalid
	}
	return c.writer.write(localPeerExecCancel, nil)
}
func (c *localPeerConn) Signal(signal string) error {
	if !c.exec || signal == "" || len(signal) > 64 {
		return ErrPeerTerminalInvalid
	}
	return c.writer.write(localPeerExecSignal, []byte(signal))
}
func (c *localPeerConn) Detach() error {
	if !c.exec {
		return ErrPeerTerminalInvalid
	}
	return c.writer.write(localPeerExecDetach, nil)
}

var _ Conn = (*localPeerConn)(nil)
var _ InputHalfCloser = (*localPeerConn)(nil)
var _ ExecConn = (*localPeerConn)(nil)
