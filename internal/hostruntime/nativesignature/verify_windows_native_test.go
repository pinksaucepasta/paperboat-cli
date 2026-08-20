//go:build windows

package nativesignature

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeAuthenticodeSurvivesRuntimeStagingCopy(t *testing.T) {
	source := os.Getenv("PAPERBOAT_NATIVE_TEST_ARTIFACT")
	if source == "" {
		t.Skip("PAPERBOAT_NATIVE_TEST_ARTIFACT is not set")
	}
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	target := filepath.Join(t.TempDir(), "paperboat-runtime.exe")
	output, err := os.Create(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err = output.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := New(nil).Verify(ctx, target, "windows", "amd64"); err != nil {
		t.Fatal(err)
	}
}
