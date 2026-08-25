//go:build windows

package managedssh

import (
	"strings"
	"testing"
)

func TestValidEnvironmentAcceptsWindowsDriveCurrentDirectory(t *testing.T) {
	for _, values := range [][]string{
		nil,
		{"Path=C:\\Windows\\System32"},
		{"=C:=C:\\Users\\Pujan", "Path=C:\\Windows\\System32"},
		{"=z:=Z:/workspace"},
	} {
		if !validEnvironment(values) {
			t.Fatalf("validEnvironment(%q) = false", values)
		}
	}
}

func TestValidEnvironmentRejectsMalformedWindowsEntries(t *testing.T) {
	for _, value := range []string{
		"missing-separator",
		"=C=C:\\Users\\Pujan",
		"=CC:=C:\\Users\\Pujan",
		"=1:=1:\\Users\\Pujan",
		"=C:=D:\\Users\\Pujan",
		"=C:=C:relative",
		"=C:=relative",
		"=C:=",
		"==C:\\Users\\Pujan",
		"NAME=contains\x00nul",
		strings.Repeat("x", 1<<20+1) + "=value",
	} {
		if validEnvironment([]string{value}) {
			t.Fatalf("validEnvironment(%q) = true", value)
		}
	}
}
