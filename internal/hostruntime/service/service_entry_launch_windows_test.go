//go:build windows

package service

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestEnrolledProcessLaunchIsSilentAndSuspended(t *testing.T) {
	want := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW | windows.CREATE_SUSPENDED)
	if got := enrolledProcessCreationFlags(); got != want {
		t.Fatalf("creation flags=%#x want=%#x", got, want)
	}
	startup := enrolledProcessStartupInfo()
	if startup.Flags&windows.STARTF_USESHOWWINDOW == 0 || startup.ShowWindow != windows.SW_HIDE {
		t.Fatalf("startup does not hide the enrolled process: %+v", startup)
	}
}
