//go:build windows

package localapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const systemSID = "S-1-5-18"

func currentUserSID() (string, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", ErrPermission
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return "", ErrPermission
	}
	return user.User.Sid.String(), nil
}

func validateServerConfig(config ServerConfig) error {
	if !validPipePath(config.SocketPath) || !validSID(config.OwnerSID) {
		return ErrInvalidConfig
	}
	return nil
}

func defaultReadAuthorizer(config ServerConfig) ReadAuthorizer {
	return func(peer Peer) bool { return peer.SID == config.OwnerSID || peer.SID == systemSID }
}

// listen creates a byte-mode pipe with a protected DACL. This is the mode
// required for HTTP/1.1 request/response framing; hijacked peer and transfer
// streams remain full-duplex and retain their existing cancellation behavior.
// The only allowed principals are the enrolled user and LocalSystem.
// pipeListener also checks the client process ID and token SID before HTTP
// sees the connection. go-winio v0.6.2 creates pipes with
// FILE_PIPE_REJECT_REMOTE_CLIENTS, so network clients are rejected by Windows
// before an accept reaches this code.
func (s *Server) listen(context.Context) (net.Listener, error) {
	listener, err := winio.ListenPipe(s.config.SocketPath, &winio.PipeConfig{
		SecurityDescriptor: pipeSecurityDescriptor(s.config.OwnerSID),
		MessageMode:        false,
		InputBufferSize:    maxHeaderBytes + maxJSONBytes + 64<<10,
		OutputBufferSize:   maxHeaderBytes + maxJSONBytes + 64<<10,
	})
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || strings.Contains(strings.ToLower(err.Error()), "exists") {
			return nil, ErrAlreadyRunning
		}
		return nil, err
	}
	return &pipeListener{Listener: listener, ownerSID: s.config.OwnerSID}, nil
}

func validSID(value string) bool {
	sid, err := windows.StringToSid(value)
	return err == nil && sid != nil && sid.String() == value
}

func pipeSecurityDescriptor(ownerSID string) string {
	return "D:P(A;;GWGR;;;SY)(A;;GWGR;;;" + ownerSID + ")"
}

type pipeListener struct {
	net.Listener
	ownerSID string
}

func (l *pipeListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peer, err := windowsPeerIdentity(connection)
		if err != nil || peer.SID != l.ownerSID && peer.SID != systemSID {
			_ = connection.Close()
			continue
		}
		return authenticatedPipeConn{Conn: connection, peer: peer}, nil
	}
}

type authenticatedPipeConn struct {
	net.Conn
	peer Peer
}

func (c authenticatedPipeConn) localAPIPeer() Peer { return c.peer }

func windowsPeerIdentity(connection net.Conn) (Peer, error) {
	withHandle, ok := connection.(interface{ Fd() uintptr })
	if !ok {
		return Peer{}, ErrPermission
	}
	pipeHandle := windows.Handle(withHandle.Fd())
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(pipeHandle, &pid); err != nil || pid == 0 {
		return Peer{}, ErrPermission
	}
	ownerSID, err := windowsNamedPipeClientSID(pipeHandle)
	if err != nil {
		return Peer{}, ErrPermission
	}
	return Peer{UID: -1, GID: -1, PID: int(pid), SID: ownerSID}, nil
}

var advapi32 = windows.NewLazySystemDLL("advapi32.dll")
var impersonateNamedPipeClientProc = advapi32.NewProc("ImpersonateNamedPipeClient")

func windowsNamedPipeClientSID(pipe windows.Handle) (string, error) {
	if pipe == 0 {
		return "", ErrPermission
	}

	// Impersonation changes thread-local security state. Keep the complete
	// operation on one OS thread and always revert before returning to HTTP.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result, _, callErr := impersonateNamedPipeClientProc.Call(uintptr(pipe))
	if result == 0 {
		if callErr != nil {
			return "", callErr
		}
		return "", ErrPermission
	}
	defer func() {
		// Returning an impersonated thread to the Go scheduler would leak the
		// client's security context into unrelated work. This is unrecoverable
		// in-process, so fail closed if Windows cannot restore the service token.
		if err := windows.RevertToSelf(); err != nil {
			panic(fmt.Errorf("revert named-pipe client impersonation: %w", err))
		}
	}()

	var token windows.Token
	openErr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if openErr != nil {
		return "", openErr
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return "", ErrPermission
	}
	return user.User.Sid.String(), nil
}
