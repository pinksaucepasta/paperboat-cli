package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCheckedInWindowsPackagingContract(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	if err := validate(root); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSourceHygieneRejectsPrivateKey(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("-----BEGIN "+"PRIVATE "+"KEY-----"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateSourceHygiene(root); err == nil {
		t.Fatal("expected private key marker to be rejected")
	}
}
