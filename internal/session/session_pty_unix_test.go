//go:build !windows

package session

import (
	"bytes"
	"context"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/creack/pty"
	"golang.org/x/term"
)

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
