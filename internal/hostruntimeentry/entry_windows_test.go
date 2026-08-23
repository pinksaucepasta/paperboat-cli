//go:build windows

package hostruntimeentry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
)

func TestWindowsWorkerEntriesValidateTheirNativeContracts(t *testing.T) {
	if err := RunConfigWorker(context.Background(), ConfigWorkerConfig{}); err == nil {
		t.Fatal("RunConfigWorker accepted an invalid native configuration")
	}
	if err := RunPreviewWorker(context.Background(), PreviewWorkerConfig{}); err == nil {
		t.Fatal("RunPreviewWorker accepted an invalid native configuration")
	}
	if err := RunServeWorker(context.Background(), ServeWorkerConfig{}); err == nil {
		t.Fatal("RunServeWorker accepted an invalid native configuration")
	}
}

func TestWindowsPreviewMutationShapeAllowsLifecycleOperationsWithoutExpiry(t *testing.T) {
	for _, kind := range []string{"remove", "remove_all", "reconcile"} {
		if !validWindowsPreviewMutationShape(WindowsPreviewMutation{Kind: kind, Root: `C:\Paperboat\state`, Name: kind}) {
			t.Fatalf("%s mutation was rejected", kind)
		}
	}
	expires := time.Now().UTC().Add(time.Minute)
	if !validWindowsPreviewMutationShape(WindowsPreviewMutation{Kind: "preview", Root: `C:\Paperboat\state`, Name: "preview", ExpiresAt: &expires}) {
		t.Fatal("expiring preview mutation was rejected")
	}
	if validWindowsPreviewMutationShape(WindowsPreviewMutation{Kind: "preview", Root: `C:\Paperboat\state`, Name: "preview"}) {
		t.Fatal("preview mutation without an expiry policy was accepted")
	}
}

func TestApplyWindowsPreviewMutationLifecycleDoesNotRequireRuntimeCurrent(t *testing.T) {
	previousLoad := loadWindowsPreviewRuntimeConfig
	previousEval := evalWindowsPreviewExecutable
	t.Cleanup(func() {
		loadWindowsPreviewRuntimeConfig = previousLoad
		evalWindowsPreviewExecutable = previousEval
	})

	root := t.TempDir()
	loadWindowsPreviewRuntimeConfig = func() (hostinstall.WindowsRuntimeConfig, error) {
		return hostinstall.WindowsRuntimeConfig{StateRoot: root}, nil
	}
	evaluated := false
	evalWindowsPreviewExecutable = func(string) (string, error) {
		evaluated = true
		return "", errors.New("runtime-current must not be resolved for lifecycle mutation")
	}

	for _, mutation := range []WindowsPreviewMutation{
		{Kind: "remove", Root: root, Name: "remove"},
		{Kind: "reconcile", Root: root, Name: "reconcile", Now: time.Now().UTC()},
		{Kind: "remove_all", Root: root, Name: "remove-all"},
	} {
		evaluated = false
		if err := ApplyWindowsPreviewMutation(context.Background(), mutation); err != nil {
			t.Fatalf("%s mutation returned error: %v", mutation.Kind, err)
		}
		if evaluated {
			t.Fatalf("%s mutation resolved RuntimeCurrent", mutation.Kind)
		}
	}
}
