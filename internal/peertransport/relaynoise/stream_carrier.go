package relaynoise

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

type deadlineStream interface {
	io.ReadWriteCloser
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// StreamCarrier preserves relay Noise record boundaries over one ordered QUIC
// stream or WSS virtual stream. Application and rekey records must share this
// carrier so their bytes cannot interleave.
type StreamCarrier struct {
	stream  deadlineStream
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func NewStreamCarrier(stream io.ReadWriteCloser) (*StreamCarrier, error) {
	deadlineCapable, ok := stream.(deadlineStream)
	if !ok || deadlineCapable == nil {
		return nil, errors.New("relay E2EE stream requires read and write deadlines")
	}
	return &StreamCarrier{stream: deadlineCapable}, nil
}

func (c *StreamCarrier) SendRekeyRecord(ctx context.Context, record []byte) error {
	return c.SendRecord(ctx, record)
}

func (c *StreamCarrier) Send(ctx context.Context, session *Session, plaintext []byte, closeAfter bool) error {
	if c == nil || session == nil {
		return ErrProtocol
	}
	return session.sealAndSend(ctx, plaintext, closeAfter, false, func(record []byte) error { return c.SendRecord(ctx, record) })
}

func (c *StreamCarrier) ReceiveRekeyRecord(ctx context.Context) ([]byte, error) {
	return c.ReceiveRecord(ctx)
}

func (c *StreamCarrier) SendRecord(ctx context.Context, record []byte) error {
	if c == nil || c.stream == nil || ctx == nil || !validWireRecord(record) {
		return ErrProtocol
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = c.stream.SetWriteDeadline(time.Now()) })
	defer func() {
		stop()
		_ = c.stream.SetWriteDeadline(time.Time{})
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.stream.SetWriteDeadline(deadline); err != nil {
			return err
		}
	}
	written := 0
	for written < len(record) {
		n, err := c.stream.Write(record[written:])
		written += n
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (c *StreamCarrier) ReceiveRecord(ctx context.Context) ([]byte, error) {
	if c == nil || c.stream == nil || ctx == nil {
		return nil, ErrProtocol
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = c.stream.SetReadDeadline(time.Now()) })
	defer func() {
		stop()
		_ = c.stream.SetReadDeadline(time.Time{})
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.stream.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
	}
	header := make([]byte, headerLength)
	if _, err := io.ReadFull(c.stream, header); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[26:28]))
	if header[0] != recordVersion || length < authenticationBytes || length > maximumCiphertext {
		return nil, ErrProtocol
	}
	record := make([]byte, headerLength+length)
	copy(record, header)
	if _, err := io.ReadFull(c.stream, record[headerLength:]); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return record, nil
}

func (c *StreamCarrier) Close() error {
	if c == nil || c.stream == nil {
		return nil
	}
	return c.stream.Close()
}

func validWireRecord(record []byte) bool {
	if len(record) < headerLength+authenticationBytes || len(record) > headerLength+maximumCiphertext || record[0] != recordVersion {
		return false
	}
	return int(binary.BigEndian.Uint16(record[26:28])) == len(record)-headerLength
}

var _ RekeyCarrier = (*StreamCarrier)(nil)
