//go:build windows

package windowsopenssh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

func lockAuthorizedKeys(ctx context.Context, stateRoot string) (func(), error) {
	sum := sha256.Sum256([]byte(strings.ToLower(stateRoot)))
	name, err := windows.UTF16PtrFromString("Local\\PaperboatOpenSSHAuthorizedKeys-" + hex.EncodeToString(sum[:16]))
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			windows.CloseHandle(handle)
			return nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			windows.CloseHandle(handle)
			return nil, ErrQualificationEnrollment
		}
		wait := min(remaining, 50*time.Millisecond)
		state, waitErr := windows.WaitForSingleObject(handle, uint32(wait/time.Millisecond))
		if waitErr != nil {
			windows.CloseHandle(handle)
			return nil, errors.Join(ErrQualificationEnrollment, waitErr)
		}
		if state == windows.WAIT_OBJECT_0 || state == windows.WAIT_ABANDONED {
			break
		}
		if state != uint32(windows.WAIT_TIMEOUT) {
			windows.CloseHandle(handle)
			return nil, ErrQualificationEnrollment
		}
	}
	return func() {
		_ = windows.ReleaseMutex(handle)
		_ = windows.CloseHandle(handle)
	}, nil
}
