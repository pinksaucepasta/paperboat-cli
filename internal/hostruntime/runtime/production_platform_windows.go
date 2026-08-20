//go:build windows

package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/availability"
	runtimeidentity "github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
	"github.com/pinksaucepasta/paperboat/internal/windowsopenssh"
	"golang.org/x/sys/windows"
)

// Compatibility names keep the existing Windows contract tests attached to
// the full production composition rather than the retired reduced runtime.
type windowsConnectorService = connectorReadinessService

func windowsWorkspace(environ func(string) string) (string, error) {
	workspace := strings.TrimSpace(environ("PAPERBOAT_WORKSPACE_ROOT"))
	if workspace == "" {
		var err error
		workspace, err = os.UserHomeDir()
		if err != nil {
			return "", errors.Join(ErrProductionInvalid, err)
		}
	}
	if !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace {
		return "", ErrProductionInvalid
	}
	info, err := os.Lstat(workspace)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrProductionInvalid
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(workspace))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", ErrProductionInvalid
	}
	return workspace, nil
}

func productionManagedSSH(ctx context.Context, controlURL string, transport http.RoundTripper, registration runtimeidentity.Registration, identity managedSSHIdentitySource, generation uint64) (*managedssh.Host, Service, error) {
	if registration.MachineID == "" || registration.InstallationGeneration < 1 || registration.SSHPort == 0 || registration.SSHUser == "" || identity == nil {
		return nil, nil, errors.Join(ErrManagedSSHUnavailable, errors.New("Windows managed SSH registration is incomplete"))
	}
	host, err := managedssh.NewHost(managedssh.HostConfig{MaxStreams: 32, ProbeTimeout: 3 * time.Second, DialTimeout: 10 * time.Second})
	if err != nil {
		return nil, nil, err
	}
	// PaperboatSshd is an SCM-managed service and can still be binding its
	// loopback sockets while the owner-scoped host supervisor starts. A single
	// probe here turns that normal startup race into a permanent stopped hostd.
	// Retry only within a bounded startup window; genuine failures still fail
	// closed and are reported to the control plane.
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		_, err = host.ReconcileTarget(probeCtx, uint64(registration.InstallationGeneration), registration.SSHPort)
		if err == nil || !errors.Is(err, managedssh.ErrSSHTargetUnavailable) {
			break
		}
		retry := time.NewTimer(250 * time.Millisecond)
		select {
		case <-probeCtx.Done():
			retry.Stop()
			err = errors.Join(managedssh.ErrSSHTargetUnavailable, probeCtx.Err())
		case <-retry.C:
		}
		if probeCtx.Err() != nil {
			err = errors.Join(managedssh.ErrSSHTargetUnavailable, probeCtx.Err())
			break
		}
	}
	if errors.Is(err, managedssh.ErrSSHTargetUnavailable) {
		return nil, nil, errors.Join(ErrManagedSSHUnavailable, errors.New("PaperboatSshd loopback target is unavailable"), err)
	}
	if err != nil {
		return nil, nil, err
	}
	programData := strings.TrimSpace(os.Getenv("ProgramData"))
	if programData == "" {
		return nil, nil, errors.Join(ErrProductionInvalid, errors.New("ProgramData is unavailable"))
	}
	paths := []string{filepath.Join(programData, "Paperboat", "ssh", "hostkeys", "ssh_host_ed25519_key.pub")}
	inventory, err := managedssh.ReadHostPublicKeys(paths, 0)
	if err != nil {
		return nil, nil, errors.Join(ErrManagedSSHUnavailable, errors.New("read Windows Paperboat host keys"), err)
	}
	if len(inventory.Keys) == 0 || generation == 0 {
		return nil, nil, errors.Join(ErrManagedSSHUnavailable, errors.New("Windows Paperboat host-key inventory is empty"))
	}
	publicKeys := make([]string, len(inventory.Keys))
	for i := range inventory.Keys {
		publicKeys[i] = inventory.Keys[i].PublicKey
	}
	// Include the installation generation so a previously rejected observation
	// cannot permanently reserve the fingerprint-only set ID. This matters when
	// a host is repaired or re-enrolled with the same persisted host key: the
	// rejected historical row remains immutable, while the new observation gets
	// a distinct set identity.
	setID := "sshks_" + fmtHex(inventory.Fingerprint[:16]) + "_" + fmtHexUint(uint64(registration.InstallationGeneration))
	client := api.New(controlURL, config.Credential{}, &http.Client{Transport: transport, Timeout: 15 * time.Second})
	keys, active, err := reconcileManagedSSHAuthority(ctx, client, identity, registration, generation, setID, publicKeys)
	if err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) {
			return nil, nil, errors.Join(ErrManagedSSHUnavailable, fmt.Errorf("Windows managed SSH authority reconciliation failed: code=%s status=%d request=%s", apiErr.Code, apiErr.Status, apiErr.RequestID), err)
		}
		return nil, nil, err
	}
	if !active {
		keys.Keys = nil
	}
	sshStateRoot := filepath.Join(programData, "Paperboat", "ssh")
	if _, err := windowsopenssh.ReconcileAuthorizedKeys(sshStateRoot, keys.Keys); err != nil {
		return nil, nil, err
	}
	return host, &managedSSHKeyReconciler{client: client, identity: identity, registration: registration, workerGeneration: generation, setID: setID, publicKeys: publicKeys, home: sshStateRoot, interval: 30 * time.Second, timeout: 10 * time.Second}, nil
}

func fmtHex(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for i, v := range value {
		result[i*2], result[i*2+1] = digits[v>>4], digits[v&15]
	}
	return string(result)
}

func fmtHexUint(value uint64) string {
	const digits = "0123456789abcdef"
	if value == 0 {
		return "0"
	}
	var reversed [16]byte
	index := len(reversed)
	for value != 0 {
		index--
		reversed[index] = digits[value&15]
		value >>= 4
	}
	return string(reversed[index:])
}

func validatedBYODShell(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		path = os.Getenv("ComSpec")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ErrProductionInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrProductionInvalid
	}
	return path, nil
}

func validateBYODWorkspace(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrProductionInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrProductionInvalid
	}
	return nil
}

func newProductionAvailabilityHostClient(timeout time.Duration) (*availability.HostClient, error) {
	return availability.NewHostClient(`\\.\pipe\PaperboatHostService`, timeout)
}
