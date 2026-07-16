package connect

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestSignManifestProducesVerifiableEnvelope(t *testing.T) {
	pub, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "paperboat-connect")
	if err := os.WriteFile(path, []byte("release artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := SignManifest("1.2.3", []SignableArtifact{{Component: "paperboat-connect", OS: "darwin", Arch: "arm64", URL: "https://releases.example/paperboat-connect", Path: path}}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := VerifyManifest(raw, pub)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Artifacts[0].SHA256 == "" {
		t.Fatal("expected computed artifact checksum")
	}
}
