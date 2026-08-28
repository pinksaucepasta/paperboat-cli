//go:build windows

package main

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var shellExecuteW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteW")

func platformOpenBrowser(target string) error {
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	value, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	result, _, callErr := shellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(value)), 0, 0, windows.SW_SHOWNORMAL)
	if result <= 32 {
		if callErr == nil || errors.Is(callErr, windows.ERROR_SUCCESS) {
			callErr = syscall.Errno(result)
		}
		return callErr
	}
	return nil
}
