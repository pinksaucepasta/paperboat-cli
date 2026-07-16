package connect

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var ErrInstallationFailed = errors.New("connector installation failed")

// Installer verifies all component artifacts before replacing any active
// executable. It leaves the previous files in place until Activate succeeds.
type Installer struct {
	HTTP      *http.Client
	PublicKey ed25519.PublicKey
	OS        string
	Arch      string
}

type InstallRequest struct {
	ManifestURL string
	InstallDir  string
	Components  []string
	Activate    func() error
}

func (i Installer) Install(ctx context.Context, request InstallRequest) (Manifest, error) {
	if len(i.PublicKey) != ed25519.PublicKeySize || !filepath.IsAbs(request.InstallDir) || len(request.Components) == 0 {
		return Manifest{}, ErrInstallationFailed
	}
	manifestRaw, err := i.download(ctx, request.ManifestURL)
	if err != nil {
		return Manifest{}, err
	}
	manifest, err := VerifyManifest(manifestRaw, i.PublicKey)
	if err != nil {
		return Manifest{}, err
	}
	operatingSystem, architecture := i.OS, i.Arch
	if operatingSystem == "" {
		operatingSystem = runtime.GOOS
	}
	if architecture == "" {
		architecture = runtime.GOARCH
	}
	staged := make(map[string]stagedArtifact, len(request.Components))
	for _, component := range request.Components {
		artifact, err := manifest.ArtifactFor(component, operatingSystem, architecture)
		if err != nil {
			return Manifest{}, err
		}
		contents, err := i.download(ctx, artifact.URL)
		if err != nil {
			return Manifest{}, err
		}
		if err := VerifyArtifact(contents, artifact.SHA256); err != nil {
			return Manifest{}, err
		}
		staged[component] = stagedArtifact{contents: contents, format: artifact.Format}
	}
	if err := replaceArtifacts(request.InstallDir, staged, request.Activate); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (i Installer) download(ctx context.Context, rawURL string) ([]byte, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, ErrInstallationFailed
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, ErrInstallationFailed
	}
	client := i.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrInstallationFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrInstallationFailed
	}
	contents, err := io.ReadAll(io.LimitReader(resp.Body, 1<<30))
	if err != nil || len(contents) == 0 {
		return nil, ErrInstallationFailed
	}
	return contents, nil
}

type stagedArtifact struct {
	contents []byte
	format   string
}

func replaceArtifacts(dir string, artifacts map[string]stagedArtifact, activate func() error) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	stagingDir, err := os.MkdirTemp(dir, ".staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stagingDir)
	backupDir, err := os.MkdirTemp(dir, ".rollback-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(backupDir)
	replaced := make([]string, 0, len(artifacts))
	for component, artifact := range artifacts {
		if component == "" || strings.Contains(component, string(filepath.Separator)) {
			return ErrInstallationFailed
		}
		stage := filepath.Join(stagingDir, component)
		switch artifact.format {
		case "", "binary":
			if err := atomicWrite(stage, artifact.contents, 0o700); err != nil {
				return err
			}
		case "tar.gz":
			if err := os.MkdirAll(stage, 0o700); err != nil {
				return err
			}
			if err := extractTarGz(artifact.contents, stage); err != nil {
				return err
			}
		default:
			return ErrInstallationFailed
		}
		path := filepath.Join(dir, component)
		backup := filepath.Join(backupDir, component)
		if _, err := os.Lstat(path); err == nil {
			if err := os.Rename(path, backup); err != nil {
				return err
			}
		}
		if err := os.Rename(stage, path); err != nil {
			return err
		}
		replaced = append(replaced, component)
	}
	if activate == nil || activate() == nil {
		return nil
	}
	for _, component := range replaced {
		path, backup := filepath.Join(dir, component), filepath.Join(backupDir, component)
		_ = os.RemoveAll(path)
		if _, err := os.Lstat(backup); err == nil {
			_ = os.Rename(backup, path)
		}
	}
	return fmt.Errorf("%w: service activation failed; previous release restored", ErrInstallationFailed)
}
