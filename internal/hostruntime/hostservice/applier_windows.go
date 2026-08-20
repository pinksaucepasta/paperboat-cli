//go:build windows

package hostservice

import (
	"context"
	"errors"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	powerRequestContextVersion      = 0
	powerRequestContextSimpleString = 0x1
	powerRequestSystemRequired      = 1
)

var (
	powerCreateRequest = windows.NewLazySystemDLL("kernel32.dll").NewProc("PowerCreateRequest")
	powerSetRequest    = windows.NewLazySystemDLL("kernel32.dll").NewProc("PowerSetRequest")
	powerClearRequest  = windows.NewLazySystemDLL("kernel32.dll").NewProc("PowerClearRequest")
)

type powerRequestContext struct {
	Version            uint32
	Flags              uint32
	SimpleReasonString *uint16
}

type platformApplier struct {
	mu     sync.Mutex
	handle windows.Handle
	active bool
	lid    lidPolicy
	create func() (windows.Handle, error)
	set    func(windows.Handle) error
	clear  func(windows.Handle) error
	close  func(windows.Handle) error
}

// NewPlatformApplier owns one process-scoped system power request. Unlike
// SetThreadExecutionState, this cannot accumulate requirements when Go moves
// repeated reconciliation calls between operating-system threads.
func NewPlatformApplier(baselinePath string) Applier {
	return &platformApplier{lid: newWindowsLidPolicy(baselinePath), create: createWindowsPowerRequest, set: setWindowsPowerRequest, clear: clearWindowsPowerRequest, close: windows.CloseHandle}
}

func (a *platformApplier) Apply(_ context.Context, mode string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if mode != KeepAwake && mode != AllowSleep {
		return ErrInvalidRequest
	}
	if mode == KeepAwake {
		if err := a.lid.KeepAwake(); err != nil {
			return err
		}
		if a.active {
			return nil
		}
		if a.handle == 0 {
			handle, err := a.create()
			if err != nil {
				return err
			}
			a.handle = handle
		}
		if err := a.set(a.handle); err != nil {
			closeErr := a.close(a.handle)
			a.handle = 0
			return errors.Join(err, closeErr, a.lid.Restore())
		}
		a.active = true
		return nil
	}
	return errors.Join(a.releaseLocked(), a.lid.Restore())
}

func (a *platformApplier) Close(context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return errors.Join(a.releaseLocked(), a.lid.Restore())
}

func (a *platformApplier) releaseLocked() error {
	if a.handle == 0 {
		a.active = false
		return nil
	}
	var clearErr error
	if a.active {
		clearErr = a.clear(a.handle)
	}
	closeErr := a.close(a.handle)
	a.handle, a.active = 0, false
	return errors.Join(clearErr, closeErr)
}

func createWindowsPowerRequest() (windows.Handle, error) {
	reason, err := windows.UTF16PtrFromString("Paperboat keep-awake availability policy")
	if err != nil {
		return 0, err
	}
	requestContext := powerRequestContext{Version: powerRequestContextVersion, Flags: powerRequestContextSimpleString, SimpleReasonString: reason}
	result, _, callErr := powerCreateRequest.Call(uintptr(unsafe.Pointer(&requestContext)))
	handle := windows.Handle(result)
	if handle == 0 || handle == windows.InvalidHandle {
		if callErr != nil && !errors.Is(callErr, windows.ERROR_SUCCESS) {
			return 0, callErr
		}
		return 0, errors.New("PowerCreateRequest failed")
	}
	return handle, nil
}

func setWindowsPowerRequest(handle windows.Handle) error {
	result, _, callErr := powerSetRequest.Call(uintptr(handle), powerRequestSystemRequired)
	if result != 0 {
		return nil
	}
	if callErr != nil && !errors.Is(callErr, windows.ERROR_SUCCESS) {
		return callErr
	}
	return errors.New("PowerSetRequest failed")
}

func clearWindowsPowerRequest(handle windows.Handle) error {
	result, _, callErr := powerClearRequest.Call(uintptr(handle), powerRequestSystemRequired)
	if result != 0 {
		return nil
	}
	if callErr != nil && !errors.Is(callErr, windows.ERROR_SUCCESS) {
		return callErr
	}
	return errors.New("PowerClearRequest failed")
}
