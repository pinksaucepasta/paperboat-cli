package connect

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestVerifyManifest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload := struct {
		Version   string     `json:"version"`
		Artifacts []Artifact `json:"artifacts"`
	}{"1.0.0", []Artifact{{OS: "darwin", Arch: "arm64", URL: "https://example.test/a", SHA256: "00"}}}
	raw, _ := json.Marshal(payload)
	sig := ed25519.Sign(priv, raw)
	signed, _ := json.Marshal(Manifest{Version: payload.Version, Artifacts: payload.Artifacts, Signature: base64.StdEncoding.EncodeToString(sig)})
	if _, err := VerifyManifest(signed, pub); err != nil {
		t.Fatal(err)
	}
}
