// Package privatepreview defines the bounded control preface and byte proxy for
// one private-preview TCP connection.
package privatepreview

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
)

var (
	ErrInvalid     = errors.New("invalid private preview stream")
	ErrUnavailable = errors.New("private preview target unavailable")
	magic          = [5]byte{'P', 'B', 'P', 'V', 1}
)

const (
	requestSize          = 7
	statusReady          = 0
	statusFailed         = 1
	HTTP3ConnectProtocol = "paperboat-preview"
)

type DialContext func(context.Context, string, string) (net.Conn, error)

func Open(ctx context.Context, stream io.ReadWriteCloser, port uint16) error {
	if ctx == nil || stream == nil || port == 0 {
		return ErrInvalid
	}
	var request [requestSize]byte
	copy(request[:5], magic[:])
	binary.BigEndian.PutUint16(request[5:], port)
	if err := writeAll(stream, request[:]); err != nil {
		return err
	}
	done := make(chan struct{})
	var cancellation sync.Mutex
	finished := false
	go func() {
		select {
		case <-ctx.Done():
			cancellation.Lock()
			if !finished {
				_ = stream.Close()
			}
			cancellation.Unlock()
		case <-done:
		}
	}()
	var status [1]byte
	_, err := io.ReadFull(stream, status[:])
	cancellation.Lock()
	finished = true
	cancellation.Unlock()
	close(done)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	if status[0] != statusReady {
		return ErrUnavailable
	}
	return nil
}

func Serve(ctx context.Context, stream io.ReadWriteCloser, dial DialContext) error {
	if ctx == nil || stream == nil || dial == nil {
		return ErrInvalid
	}
	var request [requestSize]byte
	if _, err := io.ReadFull(stream, request[:]); err != nil {
		return errors.Join(ErrInvalid, err)
	}
	port := binary.BigEndian.Uint16(request[5:])
	if !bytes.Equal(request[:5], magic[:]) || port == 0 {
		return ErrInvalid
	}
	target, err := dial(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		_ = writeAll(stream, []byte{statusFailed})
		return errors.Join(ErrUnavailable, err)
	}
	if err := writeAll(stream, []byte{statusReady}); err != nil {
		return errors.Join(err, target.Close())
	}
	return bridge(ctx, stream, target)
}

func bridge(ctx context.Context, left io.ReadWriteCloser, right net.Conn) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = left.Close()
			_ = right.Close()
		case <-done:
		}
	}()
	results := make(chan error, 2)
	copyDirection := func(destination io.Writer, source io.Reader, closeWrite func() error) {
		_, copyErr := io.Copy(destination, source)
		if closeWrite != nil {
			copyErr = errors.Join(copyErr, closeWrite())
		}
		results <- copyErr
	}
	// net.Pipe and other generic io.ReadWriteClosers have no half-close
	// operation. Closing them after the first direction completes destroys the
	// opposite direction and turns ordinary HTTP responses into empty replies.
	// Defer full close until both copies finish; use a real half-close when the
	// stream provides one.
	leftCloseWrite := func() error { return nil }
	if closer, ok := left.(interface{ CloseWrite() error }); ok {
		leftCloseWrite = closer.CloseWrite
	}
	rightCloseWrite := right.Close
	if closer, ok := right.(interface{ CloseWrite() error }); ok {
		rightCloseWrite = closer.CloseWrite
	}
	go copyDirection(right, left, rightCloseWrite)
	go copyDirection(left, right, leftCloseWrite)
	first := <-results
	second := <-results
	close(done)
	closeErr := errors.Join(left.Close(), right.Close())
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(first, second, closeErr)
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		count, err := writer.Write(value)
		if err != nil {
			return err
		}
		if count <= 0 || count > len(value) {
			return fmt.Errorf("%w: %w", ErrInvalid, io.ErrShortWrite)
		}
		value = value[count:]
	}
	return nil
}
