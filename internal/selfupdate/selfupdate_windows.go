//go:build windows

package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/nativesignature"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

const currentSchemaV1 = "paperboat.release-current/v1"

var ErrInvalidRelease = errors.New("signed release is invalid")

type Current struct {
	Schema     string                  `json:"schema"`
	Version    string                  `json:"version"`
	Repository string                  `json:"repository"`
	Assets     map[string]CurrentAsset `json:"assets"`
}

type CurrentAsset struct {
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Format       string `json:"format"`
	URL          string `json:"url"`
	SHA256       string `json:"sha256"`
	Length       int64  `json:"length"`
}

func Resolve(ctx context.Context, releaseURL string, client *http.Client) (bootstrap.ArtifactTarget, error) {
	if client == nil {
		return bootstrap.ArtifactTarget{}, ErrInvalidRelease
	}
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(releaseURL), "/"))
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return bootstrap.ArtifactTarget{}, ErrInvalidRelease
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/current.json", nil)
	if err != nil {
		return bootstrap.ArtifactTarget{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return bootstrap.ArtifactTarget{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return bootstrap.ArtifactTarget{}, fmt.Errorf("%w: release origin returned HTTP %d", ErrInvalidRelease, response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10+1))
	var current Current
	var extra any
	if decoder.Decode(&current) != nil || decoder.Decode(&extra) != io.EOF || current.Schema != currentSchemaV1 || !validVersion(current.Version) || !validCurrentAsset(current) {
		return bootstrap.ArtifactTarget{}, ErrInvalidRelease
	}
	return bootstrap.ArtifactTarget{Schema: bootstrap.ArtifactTargetSchemaV1, Kind: bootstrap.ArtifactKindPB, Version: current.Version, Platform: runtime.GOOS, Architecture: runtime.GOARCH, RepositoryURL: base.String() + "/tuf", TargetPath: releaseindex.AssetName(runtime.GOOS, runtime.GOARCH)}, nil
}

func validCurrentAsset(current Current) bool {
	assetName := releaseindex.AssetName(runtime.GOOS, runtime.GOARCH)
	asset, ok := current.Assets[assetName]
	if !ok || current.Repository == "" || asset.Platform != runtime.GOOS || asset.Architecture != runtime.GOARCH || asset.Format == "" || asset.URL == "" || asset.SHA256 == "" || asset.Length < 1 {
		return false
	}
	return true
}

// InstallBinary replaces the one installed Paperboat executable. Windows
// keeps a running image open, so callers that are themselves the active pb
// process must invoke this through a short-lived copy of the same executable
// after the service processes have been stopped.
func InstallBinary(currentExecutable, verifiedArtifact string) error {
	currentExecutable, err := filepath.Abs(currentExecutable)
	if err != nil || !filepath.IsAbs(verifiedArtifact) || !strings.EqualFold(filepath.Ext(currentExecutable), ".exe") {
		return ErrInvalidRelease
	}
	if err := safeRegular(currentExecutable); err != nil {
		return err
	}
	if err := binarytarget.Validate(verifiedArtifact, runtime.GOOS, runtime.GOARCH); err != nil {
		return ErrInvalidRelease
	}
	verifyCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := nativesignature.New(nil).Verify(verifyCtx, verifiedArtifact, runtime.GOOS, runtime.GOARCH); err != nil {
		return ErrInvalidRelease
	}
	input, err := os.Open(verifiedArtifact)
	if err != nil {
		return err
	}
	defer input.Close()
	body, err := io.ReadAll(io.LimitReader(input, 256<<20+1))
	if err != nil || len(body) == 0 || len(body) > 256<<20 {
		return ErrInvalidRelease
	}
	temporaryPath := currentExecutable + ".new"
	_ = os.Remove(temporaryPath)
	if err := windowssecurity.WithRestorePrivilege(func() error {
		return atomicfile.Write(temporaryPath, body, atomicfile.Options{Mode: 0o755, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"})
	}); err != nil {
		return err
	}
	defer os.Remove(temporaryPath)
	if err := windowssecurity.WithRestorePrivilege(func() error {
		from, err := windows.UTF16PtrFromString(temporaryPath)
		if err != nil {
			return err
		}
		to, err := windows.UTF16PtrFromString(currentExecutable)
		if err != nil {
			return err
		}
		return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	}); err != nil {
		return err
	}
	return nil
}

// InstallCLI is retained as a source-compatible name for older callers. CLI
// and runtime now share the same signed executable and stable path.
func InstallCLI(currentExecutable, verifiedArtifact string) error {
	return InstallBinary(currentExecutable, verifiedArtifact)
}

func safeRegular(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 512<<20 {
		return ErrInvalidRelease
	}
	return nil
}

func validVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 || len(parts[0]) != 4 || len(parts[1]) != 2 || len(parts[2]) != 2 || parts[3] == "" || len(parts[3]) > 4 || len(parts[3]) > 1 && parts[3][0] == '0' {
		return false
	}
	for _, part := range parts {
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func CompareVersions(left, right string) (int, error) {
	if !validVersion(left) || !validVersion(right) {
		return 0, ErrInvalidRelease
	}
	leftParts, rightParts := strings.Split(left, "."), strings.Split(right, ".")
	for index := range leftParts {
		leftValue, _ := strconv.Atoi(leftParts[index])
		rightValue, _ := strconv.Atoi(rightParts[index])
		if leftValue < rightValue {
			return -1, nil
		}
		if leftValue > rightValue {
			return 1, nil
		}
	}
	return 0, nil
}
