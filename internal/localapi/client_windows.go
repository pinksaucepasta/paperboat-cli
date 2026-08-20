//go:build windows

package localapi

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// NewClient connects to the same HTTP/1.1 local API contract as Unix, using
// a byte-mode local named pipe. A pipe name is not a network address: the
// server DACL and client-token verification are the authorization boundary.
func NewClient(socketPath string, timeout time.Duration) (*Client, error) {
	if !validPipePath(socketPath) || timeout <= 0 || timeout > time.Minute {
		return nil, ErrInvalidConfig
	}
	return newClient(socketPath, timeout), nil
}

func dialLocal(ctx context.Context, socketPath string, timeout time.Duration) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Identification is required for the server to obtain the authenticated
	// client token from the pipe. Anonymous pipe dialing defeats the token
	// boundary even when the pipe DACL is correct.
	return winio.DialPipeAccessImpLevel(dialCtx, socketPath, windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
}

func validPipePath(path string) bool {
	const prefix = `\\.\pipe\`
	if !strings.HasPrefix(strings.ToLower(path), prefix) || len(path) <= len(prefix) || len(path) > 256 {
		return false
	}
	return !strings.ContainsAny(path[len(prefix):], "/\\:*?\"<>|\x00\r\n")
}
