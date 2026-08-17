//go:build darwin || linux

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

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
)

const currentSchemaV1 = "paperboat.release-current/v1"

var ErrInvalidRelease = errors.New("signed release is invalid")

type Current struct {
	Schema  string `json:"schema"`
	Version string `json:"version"`
}

func Resolve(ctx context.Context, releaseURL string, client *http.Client) (bootstrap.ArtifactTarget, error) {
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(releaseURL), "/"))
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return bootstrap.ArtifactTarget{}, ErrInvalidRelease
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/current.json", nil)
	if err != nil {
		return bootstrap.ArtifactTarget{}, err
	}
	if client == nil {
		client = http.DefaultClient
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
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4097))
	decoder.DisallowUnknownFields()
	var current Current
	var extra any
	if decoder.Decode(&current) != nil || decoder.Decode(&extra) != io.EOF || current.Schema != currentSchemaV1 || !validVersion(current.Version) {
		return bootstrap.ArtifactTarget{}, ErrInvalidRelease
	}
	return bootstrap.ArtifactTarget{Schema: bootstrap.ArtifactTargetSchemaV1, Kind: bootstrap.ArtifactKindPB, Version: current.Version, Platform: runtime.GOOS, Architecture: runtime.GOARCH, RepositoryURL: base.String() + "/tuf", TargetPath: "pb-" + runtime.GOOS + "-" + runtime.GOARCH}, nil
}

func InstallCLI(currentExecutable, verifiedArtifact string) error {
	currentExecutable, err := filepath.Abs(currentExecutable)
	if err != nil || !filepath.IsAbs(verifiedArtifact) {
		return ErrInvalidRelease
	}
	info, err := os.Lstat(currentExecutable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return ErrInvalidRelease
	}
	if err := binarytarget.Validate(verifiedArtifact, runtime.GOOS, runtime.GOARCH); err != nil {
		return ErrInvalidRelease
	}
	input, err := os.Open(verifiedArtifact)
	if err != nil {
		return err
	}
	defer input.Close()
	temporary, err := os.CreateTemp(filepath.Dir(currentExecutable), ".pb-update-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := io.Copy(temporary, io.LimitReader(input, 256<<20+1)); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o755); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	rollback := currentExecutable + ".update-rollback"
	if err := os.Remove(rollback); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(currentExecutable, rollback); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, currentExecutable); err != nil {
		_ = os.Rename(rollback, currentExecutable)
		return err
	}
	directory, err := os.Open(filepath.Dir(currentExecutable))
	if err == nil {
		err = directory.Sync()
		_ = directory.Close()
	}
	if err != nil {
		_ = os.Remove(currentExecutable)
		_ = os.Rename(rollback, currentExecutable)
		return err
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
