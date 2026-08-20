//go:build windows

package hostruntimeentry

import (
	"context"
	"testing"
	"time"
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
