//go:build darwin || linux

package codexsession

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func codexAppServerEndpoint(directory string) (endpoint, listen string, err error) {
	endpoint = filepath.Join(directory, "app.sock")
	if len(endpoint) >= 104 {
		return "", "", errors.New("Codex runtime state path is too long for a Unix socket")
	}
	return endpoint, "unix://" + endpoint, nil
}

func waitCodexAppServer(ctx context.Context, endpoint string, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if info, err := os.Stat(endpoint); err == nil && info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("codex app-server readiness timed out")
		case <-ticker.C:
		}
	}
}

func dialCodexAppServer(ctx context.Context, endpoint string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", endpoint)
}

func stopCodexCommand(command Command) error { return command.Signal(syscall.SIGTERM) }

func terminateCodexPID(pid int) error {
	if pid <= 0 {
		return nil
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Signal(syscall.SIGTERM)
}
