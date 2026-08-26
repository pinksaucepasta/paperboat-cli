//go:build windows

package pty

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
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

func TestEnvironmentBlockUsesEmbeddedUTF16Terminators(t *testing.T) {
	block, err := environmentBlock([]string{"TERM=xterm", "PATH=C:\\Windows\\System32"})
	if err != nil {
		t.Fatal(err)
	}
	if block == nil {
		t.Fatal("environment block is nil")
	}
	// Bound the read to the exact number of UTF-16 code units required by the
	// test environment. This avoids scanning past the allocated environment
	// block while still checking both trailing terminators.
	values := unsafe.Slice(block, len("PATH=C:\\Windows\\System32")+1+len("TERM=xterm")+2)
	end := -1
	for index := 0; index+1 < len(values); index++ {
		if values[index] == 0 && values[index+1] == 0 {
			end = index + 2
			break
		}
	}
	if end < 0 {
		t.Fatal("environment block is not double-NUL terminated")
	}
	decoded := strings.TrimRight(string(utf16.Decode(values[:end])), "\x00")
	if got, want := strings.Split(decoded, "\x00"), []string{"PATH=C:\\Windows\\System32", "TERM=xterm"}; !slices.Equal(got, want) {
		t.Fatalf("environment block=%q want=%q", got, want)
	}
}
