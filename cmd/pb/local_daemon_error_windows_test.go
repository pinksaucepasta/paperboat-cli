//go:build windows

package main

import (
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

func TestLocalDaemonSocketUnavailableRecognizesMissingWindowsPipe(t *testing.T) {
	if !localDaemonSocketUnavailable(fmt.Errorf("open local API pipe: %w", windows.ERROR_FILE_NOT_FOUND)) {
		t.Fatal("missing Windows named pipe was not treated as a startable local-daemon condition")
	}
}
