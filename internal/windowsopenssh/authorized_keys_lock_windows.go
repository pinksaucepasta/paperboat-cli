//go:build windows

package windowsopenssh

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

func lockAuthorizedKeys(stateRoot string) (func(), error) {
	sum := sha256.Sum256([]byte(strings.ToLower(stateRoot)))
	name, err := windows.UTF16PtrFromString("Local\\PaperboatOpenSSHAuthorizedKeys-" + hex.EncodeToString(sum[:16]))
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		return nil, err
	}
	state, waitErr := windows.WaitForSingleObject(handle, uint32((30*time.Second)/time.Millisecond))
	if waitErr != nil || state != windows.WAIT_OBJECT_0 && state != windows.WAIT_ABANDONED {
		windows.CloseHandle(handle)
		return nil, errors.Join(ErrQualificationEnrollment, waitErr)
	}
	return func() {
		_ = windows.ReleaseMutex(handle)
		_ = windows.CloseHandle(handle)
	}, nil
}
