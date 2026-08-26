//go:build windows

package pty

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var getHandleInformation = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetHandleInformation")

func TestAnonymousPipeKeepsOnlyConPTYEndpointInheritable(t *testing.T) {
	tests := []struct {
		name        string
		inheritRead bool
	}{
		{name: "input", inheritRead: true},
		{name: "output", inheritRead: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			read, write, err := anonymousPipe(test.inheritRead)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				windows.Close(read)
				windows.Close(write)
			})
			for _, endpoint := range []struct {
				name   string
				handle windows.Handle
				want   bool
			}{
				{name: "read", handle: read, want: test.inheritRead},
				{name: "write", handle: write, want: !test.inheritRead},
			} {
				var flags uint32
				result, _, callErr := getHandleInformation.Call(uintptr(endpoint.handle), uintptr(unsafe.Pointer(&flags)))
				if result == 0 {
					t.Fatalf("%s endpoint handle information: %v", endpoint.name, callErr)
				}
				got := flags&windows.HANDLE_FLAG_INHERIT != 0
				if got != endpoint.want {
					t.Fatalf("%s endpoint inheritable=%t want %t", endpoint.name, got, endpoint.want)
				}
			}
		})
	}
}
