// Package session runs the transparent terminal wrapper: it puts the local
// terminal into raw mode, streams bytes to/from the remote PTY, propagates
// window resizes, and passes the remote exit code back. Correct raw-mode
// handling and clean teardown are the UX bar (see AGENTS.md).
package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/tunnel"
	"golang.org/x/term"
)

const terminalOutputBufferBytes = 128 * 1024

const terminalCleanupSequence = "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1015l\x1b[?2004l\x1b[?1049l\x1b[?25h"

type RunOption func(*runOptions)

type runOptions struct {
	outputBufferBytes int
	output            io.Writer
	remoteSize        func() (uint16, uint16)
}

func WithOutputBufferBytes(size int) RunOption {
	return func(options *runOptions) {
		if size > 0 {
			options.outputBufferBytes = size
		}
	}
}

// WithOutput sends remote terminal bytes through output. A status renderer can
// use this to serialize remote output with local redraws.
func WithOutput(output io.Writer) RunOption {
	return func(options *runOptions) {
		if output != nil {
			options.output = output
		}
	}
}

// WithRemoteSize supplies the remote PTY viewport for initial and resize
// propagation.
func WithRemoteSize(size func() (uint16, uint16)) RunOption {
	return func(options *runOptions) { options.remoteSize = size }
}

// Run wires the local terminal to conn. stdinSink is the writer local input is
// copied into — typically the paste interceptor wrapping conn. Run blocks until
// the remote session ends (or ctx is cancelled) and returns the remote exit
// code.
func Run(ctx context.Context, conn tunnel.Conn, stdinSink io.WriteCloser) (int, error) {
	return RunWithActivity(ctx, conn, stdinSink, nil)
}

// RunWithActivity is Run with an optional, non-blocking activity callback.
// The callback is rate-limited and runs asynchronously so it cannot stall PTY I/O.
func RunWithActivity(ctx context.Context, conn tunnel.Conn, stdinSink io.WriteCloser, activity func(source string), opts ...RunOption) (int, error) {
	options := runOptions{outputBufferBytes: terminalOutputBufferBytes, output: os.Stdout}
	for _, option := range opts {
		option(&options)
	}
	inputCtx, cancelInput := context.WithCancel(ctx)
	defer cancelInput()
	stdinFd := int(os.Stdin.Fd())
	restore := func() {}
	isTerminal := term.IsTerminal(stdinFd)
	if isTerminal {
		oldState, err := term.MakeRaw(stdinFd)
		if err != nil {
			return 1, err
		}
		restore = func() { _ = term.Restore(stdinFd, oldState) }
	}
	defer restore()
	if isTerminal {
		resetTerminalEmulator := func() { _, _ = options.output.Write([]byte(terminalCleanupSequence)) }
		resetTerminalEmulator()
		defer resetTerminalEmulator()
	}

	// Propagate the initial size and subsequent resizes.
	stopResize := watchResize(conn, options.remoteSize)
	defer stopResize()

	// Remote -> local. Ends when the remote PTY closes; that is normal EOF, not
	// an error, so it does not by itself end the session — conn.Wait does.
	var activityMu sync.Mutex
	lastActivity := time.Time{}
	report := func(source string) {
		if activity == nil {
			return
		}
		activityMu.Lock()
		if time.Since(lastActivity) < time.Second {
			activityMu.Unlock()
			return
		}
		lastActivity = time.Now()
		activityMu.Unlock()
		go activity(source)
	}
	outputDone := make(chan struct{})
	streamErr := make(chan error, 2)
	go func() {
		defer close(outputDone)
		buf := make([]byte, options.outputBufferBytes)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				started := time.Now()
				if _, writeErr := options.output.Write(buf[:n]); writeErr != nil {
					streamErr <- fmt.Errorf("write terminal output: %w", writeErr)
					return
				}
				if observer, ok := conn.(interface{ ObserveLocalWrite(int, time.Duration) }); ok {
					observer.ObserveLocalWrite(n, time.Since(started))
				}
				report("agent_output")
			}
			if err != nil {
				return
			}
		}
	}()

	// Local -> remote (through the paste interceptor).
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		buf := make([]byte, 32*1024)
		for {
			n, readErr := readLocalInput(inputCtx, os.Stdin, buf)
			if n > 0 {
				if _, writeErr := stdinSink.Write(buf[:n]); writeErr != nil {
					if errors.Is(writeErr, tunnel.ErrWriteUncertain) {
						if discarder, ok := stdinSink.(interface{ Discard() }); ok {
							discarder.Discard()
						}
						continue
					}
					streamErr <- fmt.Errorf("send terminal input: %w", writeErr)
					return
				}
				report("human_input")
			}
			if readErr != nil {
				break
			}
		}
		_ = stdinSink.Close()
		if halfCloser, ok := conn.(tunnel.InputHalfCloser); ok {
			if err := halfCloser.CloseWrite(); err != nil && !errors.Is(err, tunnel.ErrInputEOFUnsupported) {
				streamErr <- fmt.Errorf("close terminal input: %w", err)
			}
		}
	}()
	stopInput := func() {
		if aborter, ok := stdinSink.(interface{ Abort() }); ok {
			aborter.Abort()
		}
		cancelInput()
	}

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
	var sinkErrors <-chan error
	if source, ok := stdinSink.(interface{ Errors() <-chan error }); ok {
		sinkErrors = source.Errors()
	}

	select {
	case <-ctx.Done():
		// External cancellation (e.g. parent signalled): tear down and report.
		stopInput()
		_ = conn.Close()
		<-outputDone
		<-inputDone
		<-done
		return 130, nil
	case r := <-done:
		stopInput()
		_ = conn.Close()
		<-outputDone
		<-inputDone
		return r.code, r.err
	case streamError := <-streamErr:
		stopInput()
		_ = conn.Close()
		<-outputDone
		<-inputDone
		<-done
		return 1, streamError
	case sinkError := <-sinkErrors:
		stopInput()
		_ = conn.Close()
		<-outputDone
		<-inputDone
		<-done
		return 1, fmt.Errorf("send terminal input: %w", sinkError)
	}
}

// watchResize sends the current terminal size to conn immediately and on every
// SIGWINCH, returning a stop function.
func watchResize(conn tunnel.Conn, remoteSize func() (uint16, uint16)) (stop func()) {
	pushSize(conn, remoteSize)
	ch := make(chan os.Signal, 1)
	notifyWinch(ch)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				pushSize(conn, remoteSize)
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

func pushSize(conn tunnel.Conn, remoteSize func() (uint16, uint16)) {
	if remoteSize != nil {
		cols, rows := remoteSize()
		if cols > 0 && rows > 0 {
			_ = conn.Resize(rows, cols)
		}
		return
	}
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return
	}
	_ = conn.Resize(uint16(h), uint16(w))
}

// ErrNotTerminal is returned by callers that require an interactive terminal.
var ErrNotTerminal = errors.New("stdin is not a terminal")
