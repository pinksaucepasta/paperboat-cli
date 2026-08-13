package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/resolver"
	"github.com/quic-go/quic-go/http3"
)

// DialPrivatePreview opens one full-duplex HTTP/3 CONNECT stream on the
// preview-class direct QUIC session. Concurrent browser connections multiplex
// on that session while their TCP byte streams remain independent.
func (t *PeerTerminalTunnel) DialPrivatePreview(ctx context.Context, info resolver.ConnectInfo, port uint16) (Conn, error) {
	if port == 0 {
		return nil, ErrPeerTerminalInvalid
	}
	return t.dial(ctx, info, "private_preview", peerApplication{quic: func(openCtx context.Context, client *http3.ClientConn, _ func() error) (Conn, error) {
		// The attachment context is bounded by the short-lived operation
		// descriptor. It authorizes CONNECT setup only; carrying its deadline into
		// the established HTTP/3 request truncates long uploads at credential
		// expiry. WithoutCancel preserves values while removing both cancellation
		// and deadline, and this explicit cancel owns the CONNECT stream lifetime.
		streamCtx, cancelStream := context.WithCancel(context.WithoutCancel(openCtx))
		reader, writer := io.Pipe()
		request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: "private-preview.paperboat", Path: "/"}, Host: "private-preview.paperboat", Header: make(http.Header), Body: reader}
		request.Header.Set("X-Paperboat-Preview-Port", strconv.Itoa(int(port)))
		request = request.WithContext(streamCtx)
		type result struct {
			response *http.Response
			err      error
		}
		ready := make(chan result, 1)
		go func() {
			response, err := client.RoundTrip(request)
			ready <- result{response: response, err: err}
		}()
		var response *http.Response
		var err error
		select {
		case value := <-ready:
			response, err = value.response, value.err
		case <-openCtx.Done():
			cancelStream()
			return nil, openCtx.Err()
		}
		if err != nil {
			cancelStream()
			_ = writer.CloseWithError(err)
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
			_ = response.Body.Close()
			_ = writer.Close()
			cancelStream()
			return nil, fmt.Errorf("private preview HTTP/3 CONNECT rejected with status %d: %s", response.StatusCode, string(body))
		}
		return &previewH3Conn{reader: response.Body, writer: writer, cancel: cancelStream}, nil
	}}, nil)
}

type previewH3Conn struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	cancel context.CancelFunc
	once   sync.Once
	err    error
}

func (c *previewH3Conn) Read(value []byte) (int, error)  { return c.reader.Read(value) }
func (c *previewH3Conn) Write(value []byte) (int, error) { return c.writer.Write(value) }
func (c *previewH3Conn) CloseWrite() error               { return c.writer.Close() }
func (c *previewH3Conn) Close() error {
	c.once.Do(func() {
		c.cancel()
		c.err = errors.Join(c.writer.Close(), c.reader.Close())
	})
	return c.err
}
func (*previewH3Conn) Resize(uint16, uint16) error { return ErrPeerTerminalInvalid }
func (c *previewH3Conn) Wait() (int, error) {
	if c == nil || c.reader == nil {
		return 1, net.ErrClosed
	}
	return 0, nil
}
func (*previewH3Conn) SetDeadline(time.Time) error      { return nil }
func (*previewH3Conn) SetReadDeadline(time.Time) error  { return nil }
func (*previewH3Conn) SetWriteDeadline(time.Time) error { return nil }

type previewStreamConn struct{ io.ReadWriteCloser }

func (*previewStreamConn) Resize(uint16, uint16) error { return ErrPeerTerminalInvalid }
func (c *previewStreamConn) CloseWrite() error {
	if closer, ok := c.ReadWriteCloser.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return c.Close()
}
func (c *previewStreamConn) Wait() (int, error) {
	if c == nil || c.ReadWriteCloser == nil {
		return 1, net.ErrClosed
	}
	var value [1]byte
	_, err := c.Read(value[:])
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return 0, nil
	}
	return 1, err
}

func (c *previewStreamConn) SetDeadline(value time.Time) error {
	if deadline, ok := c.ReadWriteCloser.(interface{ SetDeadline(time.Time) error }); ok {
		return deadline.SetDeadline(value)
	}
	return ErrPeerTerminalInvalid
}
func (c *previewStreamConn) SetReadDeadline(value time.Time) error {
	if deadline, ok := c.ReadWriteCloser.(interface{ SetReadDeadline(time.Time) error }); ok {
		return deadline.SetReadDeadline(value)
	}
	return ErrPeerTerminalInvalid
}
func (c *previewStreamConn) SetWriteDeadline(value time.Time) error {
	if deadline, ok := c.ReadWriteCloser.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return deadline.SetWriteDeadline(value)
	}
	return ErrPeerTerminalInvalid
}
