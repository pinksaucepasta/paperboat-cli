package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/tunnel"
)

type testConn struct {
	io.Reader
	writes       bytes.Buffer
	wait         chan struct{}
	code         int
	closed       atomic.Bool
	halfClosed   atomic.Bool
	halfCloseErr error
}

func (c *testConn) Write(p []byte) (int, error) { return c.writes.Write(p) }
func (c *testConn) Close() error {
	c.closed.Store(true)
	select {
	case <-c.wait:
	default:
		close(c.wait)
	}
	return nil
}
func (c *testConn) Resize(uint16, uint16) error { return nil }
func (c *testConn) Wait() (int, error)          { <-c.wait; return c.code, nil }
func (c *testConn) CloseWrite() error           { c.halfClosed.Store(true); return c.halfCloseErr }

type sink struct{ bytes.Buffer }

func (s *sink) Close() error { return nil }

type failingSink struct{}

func (failingSink) Write([]byte) (int, error) { return 0, errors.New("route lost") }
func (failingSink) Close() error              { return nil }

func TestRunPropagatesRemoteOutputExitAndCloses(t *testing.T) {
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut; _ = inR.Close(); _ = outR.Close() }()
	_, _ = inW.Write([]byte("input"))
	_ = inW.Close()
	c := &testConn{Reader: bytes.NewBufferString("output"), wait: make(chan struct{}), code: 7}
	go func() {
		for !c.halfClosed.Load() {
			time.Sleep(time.Millisecond)
		}
		close(c.wait)
	}()
	s := &sink{}
	code, err := Run(context.Background(), c, s)
	_ = outW.Close()
	got, _ := io.ReadAll(outR)
	if err != nil || code != 7 || string(got) != "output" || !c.closed.Load() || !c.halfClosed.Load() {
		t.Fatalf("code=%d err=%v output=%q closed=%v halfClosed=%v", code, err, got, c.closed.Load(), c.halfClosed.Load())
	}
}

func TestRunContinuesAfterUnsupportedStdinEOF(t *testing.T) {
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut; _ = inR.Close(); _ = outR.Close() }()
	_ = inW.Close()
	c := &testConn{Reader: bytes.NewBufferString("done"), wait: make(chan struct{}), code: 0, halfCloseErr: tunnel.ErrInputEOFUnsupported}
	go func() {
		for !c.halfClosed.Load() {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(5 * time.Millisecond)
		close(c.wait)
	}()
	code, err := Run(context.Background(), c, &sink{})
	_ = outW.Close()
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func TestRunCancellationReturns130AndCloses(t *testing.T) {
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	defer func() {
		os.Stdin, os.Stdout = oldIn, oldOut
		_ = inR.Close()
		_ = inW.Close()
		_ = outR.Close()
		_ = outW.Close()
	}()
	c := &testConn{Reader: bytes.NewBuffer(nil), wait: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	code, err := Run(ctx, c, &sink{})
	if err != nil || code != 130 || !c.closed.Load() {
		t.Fatalf("code=%d err=%v closed=%v", code, err, c.closed.Load())
	}
}

func TestRunSurfacesInputWriteFailure(t *testing.T) {
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut; _ = inR.Close(); _ = outR.Close(); _ = outW.Close() }()
	_, _ = inW.Write([]byte("input"))
	_ = inW.Close()
	c := &testConn{Reader: bytes.NewBuffer(nil), wait: make(chan struct{})}
	code, err := Run(context.Background(), c, failingSink{})
	if code != 1 || err == nil || !strings.Contains(err.Error(), "send terminal input") || !c.closed.Load() {
		t.Fatalf("code=%d err=%v closed=%v", code, err, c.closed.Load())
	}
}
