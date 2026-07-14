// Package tunnel abstracts reaching a project VM's terminal. In production the
// connection is carried through agentunnel (never a raw exposed port); the
// Tunnel/Conn interfaces keep the production transport testable through injected doubles.
package tunnel

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/resolver"
)

var ErrInputEOFUnsupported = errors.New("terminal protocol does not support stdin EOF")

// Conn is an attached remote terminal: a bidirectional byte stream plus the
// out-of-band controls a PTY needs.
type Conn interface {
	io.ReadWriteCloser
	// Resize propagates a local terminal resize to the remote PTY.
	Resize(rows, cols uint16) error
	// Wait blocks until the remote session ends and returns its exit code.
	Wait() (exitCode int, err error)
}

type InputHalfCloser interface {
	CloseWrite() error
}

func readBufferedChunks(p []byte, pending *[]byte, out <-chan []byte) (int, error) {
	return readBufferedChunksWithWait(p, pending, out, 0)
}

func readBufferedChunksWithWait(p []byte, pending *[]byte, out <-chan []byte, wait time.Duration) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := 0
	if len(*pending) > 0 {
		copied := copy(p, *pending)
		n += copied
		*pending = (*pending)[copied:]
		if n == len(p) {
			return n, nil
		}
	}
	if n == 0 {
		b, ok := <-out
		if !ok {
			return 0, io.EOF
		}
		copied := copy(p, b)
		n += copied
		if copied < len(b) {
			*pending = append(*pending, b[copied:]...)
			return n, nil
		}
	}
	var timer *time.Timer
	var timerC <-chan time.Time
	if wait > 0 {
		timer = time.NewTimer(wait)
		timerC = timer.C
		defer timer.Stop()
	}
	for n < len(p) {
		select {
		case b, ok := <-out:
			if !ok {
				return n, nil
			}
			copied := copy(p[n:], b)
			n += copied
			if copied < len(b) {
				*pending = append(*pending, b[copied:]...)
				return n, nil
			}
		case <-timerC:
			return n, nil
		default:
			if wait <= 0 {
				return n, nil
			}
			select {
			case b, ok := <-out:
				if !ok {
					return n, nil
				}
				copied := copy(p[n:], b)
				n += copied
				if copied < len(b) {
					*pending = append(*pending, b[copied:]...)
					return n, nil
				}
			case <-timerC:
				return n, nil
			}
		}
	}
	return n, nil
}

// Tunnel dials a project VM and attaches its terminal.
type Tunnel interface {
	Dial(ctx context.Context, info resolver.ConnectInfo) (Conn, error)
}
