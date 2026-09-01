//go:build windows

package hostruntimeentry

import (
	"context"
	"testing"
)

func TestWindowsConfigWorkerEntryRejectsInvalidConfiguration(t *testing.T) {
	if err := RunConfigWorker(context.Background(), ConfigWorkerConfig{}); err == nil {
		t.Fatal("RunConfigWorker accepted an invalid native configuration")
	}
}
