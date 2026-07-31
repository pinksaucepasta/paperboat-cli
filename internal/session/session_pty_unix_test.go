//go:build !windows

package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/pinksaucepasta/paperboat/internal/statusbar"
	"golang.org/x/term"
)

type statusPTYConn struct {
	chunks   [][]byte
	readDone chan struct{}
	readOnce sync.Once
	resizeMu sync.Mutex
	rows     uint16
	cols     uint16
	writes   bytes.Buffer
}

type controlThenFailWriter struct {
	writes bytes.Buffer
	count  int
}

func (w *controlThenFailWriter) Write(p []byte) (int, error) {
	w.count++
	if w.count == 3 {
		return 0, errors.New("terminal output lost")
	}
	return w.writes.Write(p)
}

func (c *statusPTYConn) Read(p []byte) (int, error) {
	if len(c.chunks) == 0 {
		c.readOnce.Do(func() { close(c.readDone) })
		return 0, io.EOF
	}
	chunk := c.chunks[0]
	c.chunks = c.chunks[1:]
	return copy(p, chunk), nil
}
func (c *statusPTYConn) Write(p []byte) (int, error) { return c.writes.Write(p) }
func (c *statusPTYConn) Resize(rows, cols uint16) error {
	c.resizeMu.Lock()
	c.rows, c.cols = rows, cols
	c.resizeMu.Unlock()
	return nil
}
func (c *statusPTYConn) Close() error { return nil }
func (c *statusPTYConn) Wait() (int, error) {
	<-c.readDone
	return 0, nil
}

func TestRunRestoresRawTerminalState(t *testing.T) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer ptmx.Close()
	defer tty.Close()
	before, err := term.GetState(int(tty.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	oldIn, oldOut := os.Stdin, os.Stdout
	outR, outW, _ := os.Pipe()
	os.Stdin, os.Stdout = tty, outW
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut; _ = outR.Close(); _ = outW.Close() }()
	c := &testConn{Reader: bytes.NewBuffer(nil), wait: make(chan struct{}), code: 0}
	close(c.wait)
	if code, err := Run(context.Background(), c, &sink{}); err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	_ = outW.Close()
	output, err := io.ReadAll(outR)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(output), terminalCleanupSequence) != 2 {
		t.Fatalf("terminal cleanup count = %d, want 2", strings.Count(string(output), terminalCleanupSequence))
	}
	after, err := term.GetState(int(tty.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("terminal state was not restored after session exit")
	}
}

func TestRunEnablesBracketedPasteAfterCleanupAndRestoresIt(t *testing.T) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer ptmx.Close()
	defer tty.Close()
	oldIn, oldOut := os.Stdin, os.Stdout
	outR, outW, _ := os.Pipe()
	os.Stdin, os.Stdout = tty, outW
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut; _ = outR.Close(); _ = outW.Close() }()
	c := &testConn{Reader: bytes.NewBuffer(nil), wait: make(chan struct{}), code: 0}
	close(c.wait)
	if code, err := Run(context.Background(), c, &sink{}, WithBracketedPaste()); err != nil || code != 0 {
		t.Fatalf("Run = %d, %v", code, err)
	}
	_ = outW.Close()
	output, err := io.ReadAll(outR)
	if err != nil {
		t.Fatal(err)
	}
	want := terminalCleanupSequence + bracketedPasteEnableSequence + terminalCleanupSequence
	if got := string(output); got != want {
		t.Fatalf("terminal control output = %q, want %q", got, want)
	}
	if c.writes.Len() != 0 {
		t.Fatalf("terminal control bytes reached remote connection: %q", c.writes.Bytes())
	}
}

func TestRunBracketedPasteRestoresOnCancellation(t *testing.T) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer ptmx.Close()
	defer tty.Close()
	oldIn, oldOut := os.Stdin, os.Stdout
	outR, outW, _ := os.Pipe()
	os.Stdin, os.Stdout = tty, outW
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut; _ = outR.Close(); _ = outW.Close() }()
	c := &testConn{Reader: bytes.NewBuffer(nil), wait: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if code, err := Run(ctx, c, &sink{}, WithBracketedPaste()); err != nil || code != 130 {
		t.Fatalf("Run = %d, %v", code, err)
	}
	_ = outW.Close()
	output, err := io.ReadAll(outR)
	if err != nil {
		t.Fatal(err)
	}
	want := terminalCleanupSequence + bracketedPasteEnableSequence + terminalCleanupSequence
	if got := string(output); got != want {
		t.Fatalf("terminal control output = %q, want %q", got, want)
	}
}

func TestRunBracketedPasteRestoresOnInputFailure(t *testing.T) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer ptmx.Close()
	defer tty.Close()
	oldIn, oldOut := os.Stdin, os.Stdout
	outR, outW, _ := os.Pipe()
	os.Stdin, os.Stdout = tty, outW
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut; _ = outR.Close(); _ = outW.Close() }()
	if _, err := ptmx.Write([]byte("input\n")); err != nil {
		t.Fatal(err)
	}
	c := &testConn{Reader: bytes.NewBuffer(nil), wait: make(chan struct{})}
	code, runErr := Run(context.Background(), c, failingSink{}, WithBracketedPaste())
	if code != 1 || runErr == nil || !strings.Contains(runErr.Error(), "send terminal input") {
		t.Fatalf("Run = %d, %v", code, runErr)
	}
	_ = outW.Close()
	output, err := io.ReadAll(outR)
	if err != nil {
		t.Fatal(err)
	}
	want := terminalCleanupSequence + bracketedPasteEnableSequence + terminalCleanupSequence
	if got := string(output); got != want {
		t.Fatalf("terminal control output = %q, want %q", got, want)
	}
}

func TestRunBracketedPasteRestoresOnOutputFailure(t *testing.T) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer ptmx.Close()
	defer tty.Close()
	oldIn := os.Stdin
	os.Stdin = tty
	defer func() { os.Stdin = oldIn }()
	output := &controlThenFailWriter{}
	c := &testConn{Reader: bytes.NewBufferString("agent output"), wait: make(chan struct{})}
	code, runErr := Run(context.Background(), c, &sink{}, WithOutput(output), WithBracketedPaste())
	if code != 1 || runErr == nil || !strings.Contains(runErr.Error(), "write terminal output") {
		t.Fatalf("Run = %d, %v", code, runErr)
	}
	want := terminalCleanupSequence + bracketedPasteEnableSequence + terminalCleanupSequence
	if got := output.writes.String(); got != want {
		t.Fatalf("terminal control output = %q, want %q", got, want)
	}
}

func TestRunWithStatusBarReservesRemoteRowWithoutRemoteStatusBytes(t *testing.T) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer ptmx.Close()
	defer tty.Close()
	// A real terminal emulator continuously consumes the slave's output. Drain
	// the PTY master so status-bar redraws cannot fill the synthetic terminal.
	go func() { _, _ = io.Copy(io.Discard, ptmx) }()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = tty, tty
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()
	bar := statusbar.New(statusbar.Options{
		Mode:           statusbar.ModeAuto,
		Term:           "xterm-256color",
		Input:          tty,
		Output:         tty,
		NoticeDuration: time.Second,
		IsTerminal:     func(int) bool { return true },
		GetSize:        func(int) (int, int, error) { return 120, 40, nil },
	})
	defer bar.Close()
	bar.SetIdentity("demo", "default")
	bar.SetConnection("connected")
	conn := &statusPTYConn{
		// Split CSI and alternate-screen transitions exercise the renderer's
		// ANSI-safe boundary tracking while session remains in raw mode.
		chunks:   [][]byte{[]byte("\x1b["), []byte("?1049hfull-screen\x1b[?1049l")},
		readDone: make(chan struct{}),
	}
	code, err := Run(context.Background(), conn, &sink{}, WithOutput(bar), WithRemoteSize(bar.RemoteSize), WithBracketedPaste())
	if err != nil || code != 0 {
		t.Fatalf("Run = %d, %v", code, err)
	}
	conn.resizeMu.Lock()
	rows, cols := conn.rows, conn.cols
	conn.resizeMu.Unlock()
	if rows != 39 || cols != 120 {
		t.Fatalf("remote resize = %dx%d, want 39x120", rows, cols)
	}
	if conn.writes.Len() != 0 {
		t.Fatalf("status bytes reached remote connection: %q", conn.writes.Bytes())
	}
}
