//go:build windows

package selfupdate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/nativesignature"
	"time"
)

const currentSchemaV1 = "paperboat.release-current/v1"

var ErrInvalidRelease = errors.New("signed release is invalid")

type Current struct {
	Schema  string `json:"schema"`
	Version string `json:"version"`
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
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4097))
	decoder.DisallowUnknownFields()
	var current Current
	var extra any
	if decoder.Decode(&current) != nil || decoder.Decode(&extra) != io.EOF || current.Schema != currentSchemaV1 || !validVersion(current.Version) {
		return bootstrap.ArtifactTarget{}, ErrInvalidRelease
	}
	return bootstrap.ArtifactTarget{Schema: bootstrap.ArtifactTargetSchemaV1, Kind: bootstrap.ArtifactKindPB, Version: current.Version, Platform: runtime.GOOS, Architecture: runtime.GOARCH, RepositoryURL: base.String() + "/tuf", TargetPath: "pb-" + runtime.GOOS + "-" + runtime.GOARCH}, nil
}

// InstallCLI uses a side-by-side slot on Windows. A running PE image cannot
// be renamed safely, so the old image remains valid while the launcher reads
// the atomically replaced active-slot record for subsequent invocations.
func InstallCLI(currentExecutable, verifiedArtifact string) error {
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
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	slotName := strings.TrimSuffix(filepath.Base(currentExecutable), filepath.Ext(currentExecutable)) + ".slot-" + hex.EncodeToString(suffix[:]) + ".exe"
	slotPath := filepath.Join(filepath.Dir(currentExecutable), slotName)
	if err := atomicfile.Write(slotPath, body, atomicfile.Options{Mode: 0o755, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"}); err != nil {
		return err
	}
	activePath := filepath.Join(filepath.Dir(currentExecutable), strings.TrimSuffix(filepath.Base(currentExecutable), filepath.Ext(currentExecutable))+".active")
	if err := atomicfile.Write(activePath, []byte(slotName+"\n"), atomicfile.Options{Mode: 0o644, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"}); err != nil {
		_ = os.Remove(slotPath)
		return err
	}
	return nil
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
