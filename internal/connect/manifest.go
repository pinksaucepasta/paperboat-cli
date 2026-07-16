// Package connect verifies signed connector release manifests before any
// supervisor artifact is installed or activated.
package connect

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
)

var ErrInvalidManifest = errors.New("invalid connector release manifest")

type Manifest struct {
	Version   string     `json:"version"`
	Artifacts []Artifact `json:"artifacts"`
	Signature string     `json:"signature"`
}
type Artifact struct {
	Component string `json:"component"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Format    string `json:"format,omitempty"`
}

// SignableArtifact describes one local release file and its public download URL.
// Path is deliberately excluded from the signed manifest.
type SignableArtifact struct {
	Component string `json:"component"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	URL       string `json:"url"`
	Path      string `json:"path"`
	Format    string `json:"format,omitempty"`
}

func (m Manifest) ArtifactFor(component, operatingSystem, architecture string) (Artifact, error) {
	for _, a := range m.Artifacts {
		if a.Component == component && a.OS == operatingSystem && a.Arch == architecture {
			return a, nil
		}
	}
	return Artifact{}, fmt.Errorf("%w: no %s artifact for %s/%s", ErrInvalidManifest, component, operatingSystem, architecture)
}

func (m Manifest) ArtifactForCurrentPlatform() (Artifact, error) {
	for _, a := range m.Artifacts {
		if a.Component == "paperboat-connect" && a.OS == runtime.GOOS && a.Arch == runtime.GOARCH {
			return a, nil
		}
	}
	return Artifact{}, fmt.Errorf("%w: no artifact for %s/%s", ErrInvalidManifest, runtime.GOOS, runtime.GOARCH)
}
func VerifyManifest(raw []byte, publicKey ed25519.PublicKey) (Manifest, error) {
	var envelope struct {
		Version   string     `json:"version"`
		Artifacts []Artifact `json:"artifacts"`
		Signature string     `json:"signature"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return Manifest{}, ErrInvalidManifest
	}
	payload, err := json.Marshal(struct {
		Version   string     `json:"version"`
		Artifacts []Artifact `json:"artifacts"`
	}{envelope.Version, envelope.Artifacts})
	if err != nil || !ed25519.Verify(publicKey, payload, sig) {
		return Manifest{}, ErrInvalidManifest
	}
	if strings.TrimSpace(envelope.Version) == "" || len(envelope.Artifacts) == 0 {
		return Manifest{}, ErrInvalidManifest
	}
	return Manifest{Version: envelope.Version, Artifacts: envelope.Artifacts, Signature: envelope.Signature}, nil
}
func VerifyArtifact(contents []byte, expected string) error {
	got := sha256.Sum256(contents)
	if !strings.EqualFold(hex.EncodeToString(got[:]), strings.TrimPrefix(expected, "sha256:")) {
		return fmt.Errorf("%w: artifact checksum mismatch", ErrInvalidManifest)
	}
	return nil
}

func ParseManifestPublicKey(value string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, ErrInvalidManifest
	}
	return ed25519.PublicKey(decoded), nil
}
