package connect

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// SignManifest creates the canonical release envelope accepted by VerifyManifest.
func SignManifest(version string, inputs []SignableArtifact, privateKey ed25519.PrivateKey) ([]byte, error) {
	if strings.TrimSpace(version) == "" || len(inputs) == 0 || len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidManifest
	}
	artifacts := make([]Artifact, 0, len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		if strings.TrimSpace(input.Component) == "" || strings.TrimSpace(input.OS) == "" || strings.TrimSpace(input.Arch) == "" || strings.TrimSpace(input.URL) == "" || strings.TrimSpace(input.Path) == "" || !supportedArtifactFormat(input.Format) {
			return nil, ErrInvalidManifest
		}
		key := input.Component + "\x00" + input.OS + "\x00" + input.Arch
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("%w: duplicate artifact %s/%s/%s", ErrInvalidManifest, input.Component, input.OS, input.Arch)
		}
		contents, err := os.ReadFile(input.Path)
		if err != nil {
			return nil, err
		}
		checksum := sha256.Sum256(contents)
		artifacts = append(artifacts, Artifact{Component: input.Component, OS: input.OS, Arch: input.Arch, URL: input.URL, SHA256: hex.EncodeToString(checksum[:]), Format: input.Format})
		seen[key] = struct{}{}
	}
	payload, err := json.Marshal(struct {
		Version   string     `json:"version"`
		Artifacts []Artifact `json:"artifacts"`
	}{Version: version, Artifacts: artifacts})
	if err != nil {
		return nil, err
	}
	return json.Marshal(Manifest{Version: version, Artifacts: artifacts, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))})
}

func supportedArtifactFormat(format string) bool {
	return format == "" || format == "binary" || format == "tar.gz"
}
