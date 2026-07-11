//go:build windows

package config

import "golang.org/x/sys/windows"

func processAlive(pid int) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	return windows.CloseHandle(handle) == nil
}
