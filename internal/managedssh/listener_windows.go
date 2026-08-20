//go:build windows

package managedssh

import (
	"errors"
	"net"
	"strings"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func ListenOwnerSocket(path string) (net.Listener, error) {
	if !validWindowsAgentPipe(path) {
		return nil, ErrAgentDenied
	}
	sid, err := currentManagedSSHSID()
	if err != nil {
		return nil, err
	}
	want, err := ownerAgentSocket("")
	if err != nil || !strings.EqualFold(path, want) {
		return nil, ErrAgentDenied
	}
	listener, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: managedSSHPipeSDDL(sid), MessageMode: false, InputBufferSize: MaxAgentRequestBytes + 4, OutputBufferSize: MaxAgentRequestBytes + 4})
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || strings.Contains(strings.ToLower(err.Error()), "exists") {
			return nil, ErrAgentDenied
		}
		return nil, err
	}
	return listener, nil
}
