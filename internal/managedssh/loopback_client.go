package managedssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

var (
	ErrSSHLoopbackInvalid       = errors.New("managed SSH loopback request is invalid")
	ErrSSHLoopbackAccept        = errors.New("native OpenSSH did not connect to its managed loopback proxy")
	ErrSSHLoopbackProcessExited = errors.New("native OpenSSH exited before connecting to its managed loopback proxy")
	ErrSSHLoopbackOwner         = errors.New("managed SSH loopback client ownership could not be verified")
	ErrSSHLoopbackShutdown      = errors.New("managed SSH loopback did not shut down")
)

// LoopbackSSHStream is the authenticated peer stream presented to native
// OpenSSH through the Windows one-shot TCP listener. CloseWrite must preserve
// the opposite read direction until all remote SSH bytes have drained.
type LoopbackSSHStream interface {
	io.ReadWriteCloser
	CloseWrite() error
}

type loopbackSSHProcess interface {
	Wait() error
	Kill() error
	PID() uint32
}

type loopbackSSHProcessStarter func(port uint16) (loopbackSSHProcess, error)
type loopbackSSHOwnerValidator func(context.Context, *net.TCPConn, uint32) error

type loopbackAcceptResult struct {
	connection *net.TCPConn
	err        error
}

const maximumSSHLoopbackDuration = 30 * time.Second

// runOneShotSSHLoopback owns one listener, one native OpenSSH process, and one
// authenticated peer stream. Every return path closes all three and reaps the
// process. The listener is closed immediately after the first accepted socket.
func runOneShotSSHLoopback(ctx context.Context, stream LoopbackSSHStream, acceptTimeout, processExitTimeout time.Duration, start loopbackSSHProcessStarter, validateOwner loopbackSSHOwnerValidator) error {
	if ctx == nil || stream == nil || start == nil || validateOwner == nil || acceptTimeout <= 0 || acceptTimeout > maximumSSHLoopbackDuration || processExitTimeout <= 0 || processExitTimeout > maximumSSHLoopbackDuration {
		if stream != nil {
			_ = stream.Close()
		}
		return ErrSSHLoopbackInvalid
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = stream.Close()
		return fmt.Errorf("%w: %v", ErrSSHLoopbackAccept, err)
	}
	closeResources := func(connection *net.TCPConn) {
		_ = listener.Close()
		if connection != nil {
			_ = connection.Close()
		}
		_ = stream.Close()
	}
	if err := listener.SetDeadline(time.Now().Add(acceptTimeout)); err != nil {
		closeResources(nil)
		return fmt.Errorf("%w: %v", ErrSSHLoopbackAccept, err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	process, err := start(port)
	if err != nil || process == nil {
		closeResources(nil)
		if err == nil {
			err = ErrOpenSSHExecution
		}
		return err
	}
	processDone := make(chan error, 1)
	go func() { processDone <- process.Wait() }()
	acceptDone := make(chan loopbackAcceptResult, 1)
	go func() {
		connection, acceptErr := listener.AcceptTCP()
		acceptDone <- loopbackAcceptResult{connection: connection, err: acceptErr}
	}()
	stopAccept := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopAccept()

	var connection *net.TCPConn
	select {
	case result := <-acceptDone:
		_ = listener.Close()
		if result.err != nil {
			closeResources(nil)
			_ = stopAndWaitSSHProcess(process, processDone)
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
			return fmt.Errorf("%w: %v", ErrSSHLoopbackAccept, result.err)
		}
		connection = result.connection
		remote, ok := connection.RemoteAddr().(*net.TCPAddr)
		if !ok || !remote.IP.IsLoopback() {
			closeResources(connection)
			_ = stopAndWaitSSHProcess(process, processDone)
			return ErrSSHLoopbackAccept
		}
		if err := validateOwner(ctx, connection, process.PID()); err != nil {
			closeResources(connection)
			_ = stopAndWaitSSHProcess(process, processDone)
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
			return errors.Join(ErrSSHLoopbackOwner, err)
		}
	case processErr := <-processDone:
		closeResources(nil)
		if processErr != nil {
			return processErr
		}
		return ErrSSHLoopbackProcessExited
	case <-ctx.Done():
		closeResources(nil)
		_ = stopAndWaitSSHProcess(process, processDone)
		return context.Cause(ctx)
	}

	bridgeDone := make(chan error, 1)
	go func() { bridgeDone <- bridgeOneShotSSHLoopback(ctx, connection, stream) }()
	var (
		bridgeErr  error
		processErr error
		bridgeOK   bool
		processOK  bool
		shutdown   *time.Timer
		shutdownC  <-chan time.Time
	)
	startShutdownTimer := func() {
		if shutdown == nil {
			shutdown = time.NewTimer(processExitTimeout)
			shutdownC = shutdown.C
		}
	}
	defer func() {
		if shutdown != nil {
			shutdown.Stop()
		}
	}()
	for !bridgeOK || !processOK {
		select {
		case bridgeErr = <-bridgeDone:
			bridgeOK = true
			if bridgeErr != nil {
				closeResources(connection)
				if !processOK {
					_ = stopAndWaitSSHProcess(process, processDone)
					processOK = true
				}
				return bridgeErr
			}
			if !processOK {
				startShutdownTimer()
			}
		case processErr = <-processDone:
			processOK = true
			if !bridgeOK {
				// Wait briefly for the bridge to drain bytes already committed to
				// the process socket before forcing transport cleanup.
				startShutdownTimer()
			}
		case <-ctx.Done():
			closeResources(connection)
			if !processOK {
				_ = stopAndWaitSSHProcess(process, processDone)
			}
			if !bridgeOK {
				<-bridgeDone
			}
			return context.Cause(ctx)
		case <-shutdownC:
			closeResources(connection)
			if !processOK {
				_ = stopAndWaitSSHProcess(process, processDone)
			}
			if !bridgeOK {
				<-bridgeDone
			}
			return ErrSSHLoopbackShutdown
		}
	}
	closeResources(connection)
	return errors.Join(processErr, bridgeErr)
}

func stopAndWaitSSHProcess(process loopbackSSHProcess, done <-chan error) error {
	select {
	case <-done:
		return nil
	default:
	}
	killErr := process.Kill()
	<-done
	if errors.Is(killErr, os.ErrProcessDone) {
		return nil
	}
	return killErr
}

func bridgeOneShotSSHLoopback(ctx context.Context, local *net.TCPConn, stream LoopbackSSHStream) error {
	if ctx == nil || local == nil || stream == nil {
		return ErrSSHLoopbackInvalid
	}
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = local.Close()
			_ = stream.Close()
		})
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	defer closeBoth()
	results := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(stream, local)
		copyErr = normalizeBridgeError(copyErr)
		closeErr := normalizeBridgeError(stream.CloseWrite())
		if copyErr != nil || closeErr != nil {
			closeBoth()
		}
		results <- errors.Join(copyErr, closeErr)
	}()
	go func() {
		_, copyErr := io.Copy(local, stream)
		copyErr = normalizeBridgeError(copyErr)
		closeErr := normalizeBridgeError(local.CloseWrite())
		// Authenticated remote EOF is terminal for the raw SSH transport. Full
		// close releases a client that still has its TCP write side open.
		closeBoth()
		results <- errors.Join(copyErr, closeErr)
	}()
	err := errors.Join(<-results, <-results)
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return err
}
