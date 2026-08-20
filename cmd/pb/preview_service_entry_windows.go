//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	hostruntime "github.com/pinksaucepasta/paperboat/internal/hostruntime/runtime"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const windowsPreviewOwnerWorkload = "PAPERBOAT_WINDOWS_PREVIEW_OWNER_WORKLOAD"

// enterWindowsPreviewService converts the LocalSystem SCM entry into a
// passwordless enrolled-owner process. The child marker is generated only by
// this service boundary and the child verifies its SID before touching user
// state, credentials, source files, or local APIs.
func enterWindowsPreviewService(_ context.Context, stateRoot, name string) (bool, error) {
	install, err := hostinstall.LoadWindowsRuntimeConfig()
	if err != nil || filepath.Clean(stateRoot) != install.StateRoot || name == "" {
		return false, errors.New("preview service does not match the enrolled Windows runtime")
	}
	if os.Getenv(windowsPreviewOwnerWorkload) == "1" {
		user, tokenErr := windows.GetCurrentProcessToken().GetTokenUser()
		if tokenErr != nil || user == nil || user.User.Sid == nil || user.User.Sid.String() != install.OwnerSID {
			return false, errors.New("preview workload is not running as the enrolled Windows owner")
		}
		return false, nil
	}
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, errors.New("preview runtime command must be started by its Paperboat Windows service")
	}
	executable, err := os.Executable()
	if err != nil {
		return true, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return true, err
	}
	serviceName, err := hostruntime.WindowsPreviewServiceName(name)
	if err != nil {
		return true, err
	}
	return true, service.RunWindowsService(service.ServiceEntryConfig{
		Name: serviceName, Executable: executable, Arguments: append([]string(nil), os.Args[1:]...),
		EnrolledSID: install.OwnerSID, DeleteOnExit: true,
		Environment: map[string]string{
			windowsPreviewOwnerWorkload:       "1",
			"PAPERBOAT_RUNTIME_STATE_ROOT":    install.StateRoot,
			"PAPERBOAT_WORKSPACE_ROOT":        install.Workspace,
			"PAPERBOAT_CONTROL_URL":           install.ControlURL,
			"PAPERBOAT_MACHINE_ID":            install.MachineID,
			"PAPERBOAT_RUNTIME_SERVICE_SCOPE": "user",
		},
	})
}
