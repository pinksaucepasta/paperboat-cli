package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
)

type signaturePayload struct {
	Architecture string `json:"architecture"`
	ByteLength   int64  `json:"byte_length"`
	Kind         string `json:"kind"`
	Platform     string `json:"platform"`
	Schema       string `json:"schema"`
	SHA256       string `json:"sha256"`
	URL          string `json:"url"`
	Version      string `json:"version"`
}

func main() {
	artifact := flag.String("artifact", "", "pb executable to sign")
	privateKey := flag.String("private-key", "", "base64 Ed25519 seed or private-key file")
	version := flag.String("version", "", "release version")
	platform := flag.String("platform", "", "target platform")
	architecture := flag.String("architecture", "", "target architecture")
	publicURL := flag.String("url", "", "published executable URL")
	manifestOutput := flag.String("manifest-output", "", "manifest output path")
	publicKeyOutput := flag.String("public-key-output", "", "public-key output path")
	flag.Parse()
	if err := generate(*artifact, *privateKey, *version, *platform, *architecture, *publicURL, *manifestOutput, *publicKeyOutput); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(artifactPath, keyPath, version, platform, architecture, publicURL, manifestPath, publicPath string) error {
	for _, path := range []string{artifactPath, keyPath, manifestPath, publicPath} {
		if !filepath.IsAbs(path) {
			return errors.New("artifact, private-key, manifest-output, and public-key-output must be absolute paths")
		}
	}
	parsed, err := url.Parse(publicURL)
	if !validReleaseVersion(version) || err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("version and a canonical HTTPS artifact URL are required")
	}
	if err := binarytarget.Validate(artifactPath, platform, architecture); err != nil {
		return err
	}
	artifact, err := os.ReadFile(artifactPath)
	if err != nil || len(artifact) == 0 || len(artifact) > 256<<20 {
		return errors.New("artifact must be a readable non-empty executable")
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil || keyInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("private-key file must have owner-only permissions")
	}
	encodedKey, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	decodedKey, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(encodedKey)))
	if err != nil {
		decodedKey, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(encodedKey)))
	}
	if err != nil || len(decodedKey) != ed25519.SeedSize && len(decodedKey) != ed25519.PrivateKeySize {
		return errors.New("private-key must contain a base64 Ed25519 seed or private key")
	}
	private := ed25519.PrivateKey(decodedKey)
	if len(decodedKey) == ed25519.SeedSize {
		private = ed25519.NewKeyFromSeed(decodedKey)
	}
	digest := sha256.Sum256(artifact)
	manifest := bootstrap.ArtifactManifest{
		Schema: bootstrap.ArtifactSchemaV1, Kind: bootstrap.ArtifactKindPB, Version: version,
		Platform: platform, Architecture: architecture, URL: publicURL, ByteLength: int64(len(artifact)), SHA256: hex.EncodeToString(digest[:]),
	}
	payload, err := json.Marshal(signaturePayload{manifest.Architecture, manifest.ByteLength, manifest.Kind, manifest.Platform, manifest.Schema, manifest.SHA256, manifest.URL, manifest.Version})
	if err != nil {
		return err
	}
	manifest.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, payload))
	body, err := json.MarshalIndent([]bootstrap.ArtifactManifest{manifest}, "", "  ")
	if err != nil {
		return err
	}
	if err := writePrivate(manifestPath, append(body, '\n')); err != nil {
		return err
	}
	return writePrivate(publicPath, []byte(base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))+"\n"))
}

func validReleaseVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 3 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

func writePrivate(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	_, err = file.Write(body)
	return err
}
