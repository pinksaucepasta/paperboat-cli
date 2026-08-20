//go:build windows

package codexsession

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/windows"
)

// Codex's official Windows app-server supports a loopback WebSocket listener.
// A named-pipe endpoint is not part of that public protocol, so each session
// gets an ephemeral loopback-only endpoint. The Paperboat HTTP gateway remains
// the authenticated boundary; this endpoint is never returned to a peer.
func codexAppServerEndpoint(string) (endpoint, listen string, err error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", err
	}
	address := listener.Addr().(*net.TCPAddr)
	if err := listener.Close(); err != nil {
		return "", "", err
	}
	endpoint = "ws://127.0.0.1:" + strconv.Itoa(address.Port)
	return endpoint, endpoint, nil
}

func waitCodexAppServer(ctx context.Context, endpoint string, timeout time.Duration) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "ws" || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" {
		return ErrInvalid
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		requestCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		request, requestErr := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://"+parsed.Host+"/readyz", nil)
		if requestErr == nil {
			response, responseErr := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(request)
			if responseErr == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					cancel()
					return nil
				}
			}
		}
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if requestErr == nil {
			// A listener that is not Codex must not satisfy readiness.
			// Continue until the bounded deadline so a racing local listener
			// cannot be mistaken for the app-server.
			if err := ctx.Err(); err != nil {
				return err
			}
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
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "ws" || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" {
		return nil, ErrInvalid
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", parsed.Host)
}

func stopCodexCommand(command Command) error {
	if command == nil {
		return nil
	}
	// Windows has no SIGTERM. os.Interrupt asks console-aware Codex wrappers to
	// stop, after which Manager applies its bounded Kill fallback.
	return command.Signal(os.Interrupt)
}

func terminateCodexPID(pid int) error {
	if pid <= 0 {
		return nil
	}
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return windows.TerminateProcess(handle, 1)
}
