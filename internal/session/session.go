// Package session runs the transparent terminal wrapper: it puts the local
// terminal into raw mode, streams bytes to/from the remote PTY, propagates
// window resizes, and passes the remote exit code back. Correct raw-mode
// handling and clean teardown are the UX bar (see AGENTS.md).
package session

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"

	"github.com/pujan-modha/paperboat-cli/internal/tunnel"
	"golang.org/x/term"
)

// Run wires the local terminal to conn. stdinSink is the writer local input is
// copied into — typically the paste interceptor wrapping conn. Run blocks until
// the remote session ends (or ctx is cancelled) and returns the remote exit
// code.
func Run(ctx context.Context, conn tunnel.Conn, stdinSink io.WriteCloser) (int, error) {
	stdinFd := int(os.Stdin.Fd())
	restore := func() {}
	if term.IsTerminal(stdinFd) {
		oldState, err := term.MakeRaw(stdinFd)
		if err != nil {
			return 1, err
		}
		restore = func() { _ = term.Restore(stdinFd, oldState) }
	}
	defer restore()

	// Propagate the initial size and subsequent resizes.
	stopResize := watchResize(conn)
	defer stopResize()

	// Remote -> local. Ends when the remote PTY closes; that is normal EOF, not
	// an error, so it does not by itself end the session — conn.Wait does.
	go func() { _, _ = io.Copy(os.Stdout, conn) }()

	// Local -> remote (through the paste interceptor).
	go func() {
		_, _ = io.Copy(stdinSink, os.Stdin)
		_ = stdinSink.Close()
	}()

	// The remote exit code is the source of truth for when we're done.
	type result struct {
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		code, err := conn.Wait()
		done <- result{code, err}
	}()

	select {
	case <-ctx.Done():
		// External cancellation (e.g. parent signalled): tear down and report.
		_ = conn.Close()
		if r := <-done; r.err == nil {
			return r.code, nil
		}
		return 130, nil
	case r := <-done:
		_ = conn.Close()
		return r.code, r.err
	}
}

// watchResize sends the current terminal size to conn immediately and on every
// SIGWINCH, returning a stop function.
func watchResize(conn tunnel.Conn) (stop func()) {
	pushSize(conn)
	ch := make(chan os.Signal, 1)
	notifyWinch(ch)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				pushSize(conn)
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

func pushSize(conn tunnel.Conn) {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return
	}
	_ = conn.Resize(uint16(h), uint16(w))
}

// ErrNotTerminal is returned by callers that require an interactive terminal.
var ErrNotTerminal = errors.New("stdin is not a terminal")
