//go:build windows

package runtime

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
)

func writePeerLastError(stateRoot string, body []byte) error {
	if !validWindowsPreviewStateRoot(stateRoot) {
		return ErrProductionInvalid
	}
	path := filepath.Join(stateRoot, "runtime", "peer-last-error.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := validateWindowsPreviewDescriptorAncestors(path); err != nil {
		return err
	}
	sddl, err := previewDescriptorSDDL(path)
	if err != nil {
		return err
	}
	if err := atomicfile.Write(path, body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: sddl}); err != nil {
		return err
	}
	if err := validatePreviewDescriptorSecurity(path); err != nil {
		return err
	}
	ownerSID, err := previewDescriptorSID(path)
	if err != nil || !windowssecurity.OwnerMatchesSID(path, ownerSID) {
		return errors.Join(ErrProductionInvalid, err)
	}
	return nil
}
