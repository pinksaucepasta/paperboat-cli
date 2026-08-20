//go:build windows

package updated

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/nativesignature"
	"golang.org/x/sys/windows"
)

// WindowsConfig contains only fixed paths supplied by the SCM installation.
// Release metadata is never accepted over the local service command channel.
type WindowsConfig struct {
	StateRoot, RuntimeCurrent, RuntimeRollback, RuntimeStaged, CLICurrent, CLIRollback string
	OwnerSID, MachineID, RepositoryURL, TokenFile, InstallState                        string
	Architecture                                                                       string
	VerifyExecutable                                                                   func(context.Context, string, string) error
}

var ErrInvalidWindowsConfig = errors.New("invalid Windows updater configuration")

// RunWindows performs crash recovery before publishing updater readiness. The
// normal update controller connects through the protected named-pipe client;
// this service intentionally keeps its public SCM invocation argument-free.
func RunWindows(ctx context.Context, config WindowsConfig) error {
	if !validWindowsConfig(config) {
		return ErrInvalidWindowsConfig
	}
	if err := secureWindowsDirectory(config.StateRoot, config.OwnerSID); err != nil {
		return err
	}
	if err := secureWindowsFile(config.TokenFile, config.OwnerSID); err != nil {
		return err
	}
	if err := secureWindowsFile(config.InstallState, config.OwnerSID); err != nil {
		return err
	}
	if err := recoverWindowsSlots(ctx, config); err != nil {
		return err
	}
	state := struct {
		Schema      string    `json:"schema"`
		MachineID   string    `json:"machine_id"`
		RecoveredAt time.Time `json:"recovered_at"`
	}{Schema: "paperboat.windows-updated/v1", MachineID: config.MachineID, RecoveredAt: time.Now().UTC()}
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := atomicfile.Write(filepath.Join(config.StateRoot, "service-state.json"), body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
		return err
	}
	if err := applyWindowsUpdateACL(filepath.Join(config.StateRoot, "service-state.json"), config.OwnerSID); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

func validWindowsConfig(config WindowsConfig) bool {
	for _, value := range []string{config.StateRoot, config.RuntimeCurrent, config.RuntimeRollback, config.RuntimeStaged, config.CLICurrent, config.CLIRollback, config.TokenFile, config.InstallState} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsAny(value, "\x00\r\n") {
			return false
		}
	}
	sid, err := windows.StringToSid(config.OwnerSID)
	return err == nil && sid != nil && sid.IsValid() && config.MachineID != "" && config.RepositoryURL != "" && (config.Architecture == "amd64" || config.Architecture == "arm64")
}
func recoverWindowsSlots(ctx context.Context, config WindowsConfig) error {
	verify := config.VerifyExecutable
	if verify == nil {
		verify = verifyWindowsRecoveryExecutable
	}
	runtimeRestore, runtimeErr := validateWindowsSlot(ctx, config.RuntimeCurrent, config.RuntimeRollback, config.Architecture, verify)
	cliRestore, cliErr := validateWindowsSlot(ctx, config.CLICurrent, config.CLIRollback, config.Architecture, verify)
	// A staged file without a committed transaction is deliberately discarded.
	// This is the safe reboot recovery point: never activate unknown bytes.
	stagedErr := os.Remove(config.RuntimeStaged)
	if errors.Is(stagedErr, os.ErrNotExist) {
		stagedErr = nil
	}
	if err := errors.Join(runtimeErr, cliErr, stagedErr); err != nil {
		return err
	}
	if runtimeRestore {
		//paperboat:allow-source-policy atomic-replacement owner=windows-updater reason=verified-runtime-rollback-slot-activation
		if err := os.Rename(config.RuntimeRollback, config.RuntimeCurrent); err != nil {
			return err
		}
	}
	if cliRestore {
		//paperboat:allow-source-policy atomic-replacement owner=windows-updater reason=verified-cli-rollback-slot-activation
		if err := os.Rename(config.CLIRollback, config.CLICurrent); err != nil {
			var rollbackErr error
			if runtimeRestore {
				//paperboat:allow-source-policy atomic-replacement owner=windows-updater reason=restore-runtime-slot-after-cli-rollback-failure
				rollbackErr = os.Rename(config.RuntimeCurrent, config.RuntimeRollback)
			}
			return errors.Join(err, rollbackErr)
		}
	}
	return nil
}

func validateWindowsSlot(ctx context.Context, current, rollback, architecture string, verify func(context.Context, string, string) error) (bool, error) {
	if _, err := os.Stat(current); errors.Is(err, os.ErrNotExist) {
		if _, rollbackErr := os.Stat(rollback); rollbackErr == nil {
			if err := verify(ctx, rollback, architecture); err != nil {
				return false, err
			}
			return true, nil
		} else if !errors.Is(rollbackErr, os.ErrNotExist) {
			return false, rollbackErr
		}
		return false, nil
	} else if err != nil {
		return false, err
	}
	return false, verify(ctx, current, architecture)
}

func verifyWindowsRecoveryExecutable(ctx context.Context, path, architecture string) error {
	if err := binarytarget.Validate(path, "windows", architecture); err != nil {
		return err
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return nativesignature.New(nil).Verify(verifyCtx, path, "windows", architecture)
}
func secureWindowsDirectory(path, sid string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrInvalidWindowsConfig
	}
	return applyWindowsUpdateACL(path, sid)
}
func secureWindowsFile(path, sid string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidWindowsConfig
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrInvalidWindowsConfig
	}
	return applyWindowsUpdateACL(path, sid)
}
func applyWindowsUpdateACL(path, sid string) error {
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + sid + ")")
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
