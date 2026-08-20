//go:build windows

package runtime

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
)

var windowsChezmoiDigests = map[string]string{
	"amd64": "18e8a7956b873583f4d53dde850d38fcc2e1cb8b821d90dc3f05cec8054e538c",
	"arm64": "ba434456f2432b82b517bded91a838519b8602de5e0da8926989f4d6f0bd0706",
}

// ensureChezmoi accepts a configured native executable when present. Normal
// installs otherwise acquire the immutable upstream archive pinned by version
// and SHA-256, extract only chezmoi.exe, validate its PE machine, and retain
// the archive for future byte-for-byte cache verification.
func ensureChezmoi(ctx context.Context, configured, stateRoot string, client *http.Client) (string, error) {
	if windowsChezmoiExecutable(configured) {
		return configured, nil
	}
	if !filepath.IsAbs(stateRoot) || client == nil {
		return "", ErrProductionInvalid
	}
	digest, ok := windowsChezmoiDigests[goruntime.GOARCH]
	if !ok {
		return "", ErrProductionInvalid
	}
	directory := filepath.Join(stateRoot, "dependencies")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	destination := filepath.Join(directory, "chezmoi-"+chezmoiVersion+".exe")
	archivePath := destination + ".zip"
	if verifiedCachedWindowsChezmoi(destination, archivePath, digest) {
		return destination, nil
	}
	url := "https://github.com/twpayne/chezmoi/releases/download/v" + chezmoiVersion + "/chezmoi_" + chezmoiVersion + "_windows_" + goruntime.GOARCH + ".zip"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > 64<<20 {
		return "", ErrProductionInvalid
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, (64<<20)+1))
	if err != nil || len(archive) > 64<<20 {
		return "", errors.Join(ErrProductionInvalid, err)
	}
	sum := sha256.Sum256(archive)
	if hex.EncodeToString(sum[:]) != digest {
		return "", ErrProductionInvalid
	}
	binary, err := extractWindowsChezmoi(archive)
	if err != nil {
		return "", err
	}
	if err := atomicfile.Write(archivePath, archive, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
		return "", err
	}
	if err := atomicfile.Write(destination, binary, atomicfile.Options{Mode: 0o700, OwnerUID: -1, OwnerGID: -1}); err != nil {
		return "", err
	}
	if err := binarytarget.Validate(destination, "windows", goruntime.GOARCH); err != nil {
		_ = os.Remove(destination)
		return "", errors.Join(ErrProductionInvalid, err)
	}
	return destination, nil
}

func extractWindowsChezmoi(archive []byte) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, ErrProductionInvalid
	}
	var binary []byte
	for _, file := range reader.File {
		if !strings.EqualFold(filepath.ToSlash(file.Name), "chezmoi.exe") {
			continue
		}
		if file.FileInfo().IsDir() || file.Mode()&os.ModeSymlink != 0 || file.UncompressedSize64 < 1 || file.UncompressedSize64 > 64<<20 || binary != nil {
			return nil, ErrProductionInvalid
		}
		stream, openErr := file.Open()
		if openErr != nil {
			return nil, ErrProductionInvalid
		}
		binary, err = io.ReadAll(io.LimitReader(stream, int64(file.UncompressedSize64)+1))
		closeErr := stream.Close()
		if err != nil || closeErr != nil || uint64(len(binary)) != file.UncompressedSize64 {
			return nil, ErrProductionInvalid
		}
	}
	if len(binary) == 0 {
		return nil, ErrProductionInvalid
	}
	return binary, nil
}

func verifiedCachedWindowsChezmoi(destination, archivePath, digest string) bool {
	if !windowsChezmoiExecutable(destination) {
		return false
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil || len(archive) > 64<<20 {
		return false
	}
	sum := sha256.Sum256(archive)
	if hex.EncodeToString(sum[:]) != digest {
		return false
	}
	expected, err := extractWindowsChezmoi(archive)
	if err != nil {
		return false
	}
	actual, err := os.ReadFile(destination)
	return err == nil && bytes.Equal(actual, expected)
}

func windowsChezmoiExecutable(path string) bool {
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".exe") {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && binarytarget.Validate(path, "windows", goruntime.GOARCH) == nil
}
