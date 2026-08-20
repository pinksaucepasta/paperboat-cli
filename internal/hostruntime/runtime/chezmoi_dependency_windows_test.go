//go:build windows

package runtime

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestExtractWindowsChezmoiSelectsOnlyExecutable(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	readme, _ := writer.Create("README.md")
	_, _ = readme.Write([]byte("docs"))
	binary, _ := writer.Create("chezmoi.exe")
	_, _ = binary.Write([]byte("MZ-test"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := extractWindowsChezmoi(archive.Bytes())
	if err != nil || string(got) != "MZ-test" {
		t.Fatalf("binary=%q err=%v", got, err)
	}
}

func TestWindowsChezmoiOfficialArtifact(t *testing.T) {
	if os.Getenv("PAPERBOAT_WINDOWS_E2E_CHEZMOI") != "1" {
		t.Skip("set PAPERBOAT_WINDOWS_E2E_CHEZMOI=1 for native dependency qualification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 2 * time.Minute}
	if archive := os.Getenv("PAPERBOAT_WINDOWS_E2E_CHEZMOI_ARCHIVE"); archive != "" {
		client.Transport = archiveTransport{path: archive}
	}
	path, err := ensureChezmoi(ctx, `C:\Program Files\Paperboat\chezmoi.exe`, t.TempDir(), client)
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(output), chezmoiVersion) {
		t.Fatalf("chezmoi --version output=%q err=%v", output, err)
	}
}

type archiveTransport struct{ path string }

func (transport archiveTransport) RoundTrip(*http.Request) (*http.Response, error) {
	file, err := os.Open(transport.path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, ContentLength: info.Size(), Body: file, Header: make(http.Header)}, nil
}

func TestExtractWindowsChezmoiRejectsMissingAndDuplicate(t *testing.T) {
	for _, names := range [][]string{{"README.md"}, {"chezmoi.exe", "CHEZMOI.EXE"}} {
		var archive bytes.Buffer
		writer := zip.NewWriter(&archive)
		for _, name := range names {
			entry, _ := writer.Create(name)
			_, _ = entry.Write([]byte("value"))
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := extractWindowsChezmoi(archive.Bytes()); err == nil {
			t.Fatalf("archive %v was accepted", names)
		}
	}
}
