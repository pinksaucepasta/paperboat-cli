//go:build windows

package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

const peerErrorDiagnosticSDDL = "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"

func writePeerLastError(stateRoot string, body []byte) error {
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot || filepath.Dir(stateRoot) == stateRoot {
		return ErrProductionInvalid
	}
	path := filepath.Join(stateRoot, "runtime", "peer-last-error.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := validatePeerErrorDiagnosticPath(stateRoot, path); err != nil {
		return err
	}
	if err := atomicfile.Write(path, body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: peerErrorDiagnosticSDDL}); err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil || !windowssecurity.OwnerMatchesSID(path, system) || !windowssecurity.ProtectedDACLMatches(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)") {
		return errors.Join(ErrProductionInvalid, err)
	}
	return nil
}

func validatePeerErrorDiagnosticPath(root, path string) error {
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(ErrProductionInvalid, err)
		}
		attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(current))
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.Join(ErrProductionInvalid, err)
		}
		if strings.EqualFold(current, root) {
			return nil
		}
		if parent := filepath.Dir(current); parent == current || !strings.HasPrefix(strings.ToLower(current), strings.ToLower(root)+string(filepath.Separator)) {
			return ErrProductionInvalid
		}
	}
}
