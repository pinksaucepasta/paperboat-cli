package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestNetworkFingerprintSecretIsDurableAndPrivate(t *testing.T) {
	store, err := Open(Config{StateRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.NetworkFingerprintSecret()
	if err != nil || len(first) != networkFingerprintSecretSize {
		t.Fatalf("secret length=%d err=%v", len(first), err)
	}
	second, err := store.NetworkFingerprintSecret()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("network fingerprint secret was not durable")
	}
	info, err := os.Lstat(filepath.Join(store.config.StateRoot, "network-fingerprint-secret.json"))
	if err != nil || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("secret mode=%v err=%v", info.Mode(), err)
	}
}
