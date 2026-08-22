package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPackageArchiveIsIndependentOfInputMtime(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	for _, directory := range []string{first, second} {
		if err := os.WriteFile(filepath.Join(directory, "pb.exe"), []byte("cli bytes"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "pb-launcher.exe"), []byte("launcher bytes"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(filepath.Join(first, "pb.exe"), time.Unix(1, 0), time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(second, "pb.exe"), time.Unix(1_700_000_000, 0), time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	firstOutput := filepath.Join(t.TempDir(), "first.zip")
	secondOutput := filepath.Join(t.TempDir(), "second.zip")
	base := options{version: "2026.08.18.0", architecture: "amd64", channel: "stable", epoch: 0}
	firstOptions := base
	firstOptions.stagingDirectory = first
	firstOptions.outputPath = firstOutput
	secondOptions := base
	secondOptions.stagingDirectory = second
	secondOptions.outputPath = secondOutput
	if err := packageArchive(firstOptions); err != nil {
		t.Fatal(err)
	}
	if err := packageArchive(secondOptions); err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(firstOutput)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(secondOutput)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("archives differ despite identical inputs and fixed epoch")
	}
}

func TestPackageArchiveEntriesAndMetadata(t *testing.T) {
	staging := t.TempDir()
	for _, name := range []string{"pb.exe", "pb-launcher.exe"} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(t.TempDir(), "paperboat.zip")
	if err := packageArchive(options{
		version:          "2026.08.18.1",
		architecture:     "arm64",
		channel:          "stable",
		stagingDirectory: staging,
		outputPath:       output,
		epoch:            0,
	}); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.OpenReader(output)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if len(reader.File) != 3 {
		t.Fatalf("got %d entries, want 3", len(reader.File))
	}
	wantNames := []string{"paperboat-windows.json", "pb-launcher.exe", "pb.exe"}
	for index, entry := range reader.File {
		if entry.Name != wantNames[index] {
			t.Fatalf("entry %d is %q, want %q", index, entry.Name, wantNames[index])
		}
		if entry.Modified.UTC() != time.Unix(defaultEpoch, 0).UTC() {
			t.Fatalf("entry %s has non-deterministic timestamp %s", entry.Name, entry.Modified)
		}
	}
	metadataEntry, err := reader.Open("paperboat-windows.json")
	if err != nil {
		t.Fatal(err)
	}
	var metadata archiveMetadata
	if err := json.NewDecoder(metadataEntry).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	if err := metadataEntry.Close(); err != nil {
		t.Fatal(err)
	}
	if metadata.Architecture != "arm64" || metadata.Channel != "stable" || metadata.SigningStatus != "tuf_checksums_required" {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
}

func TestFillDefaultsRejectsArchitectureChannelMismatch(t *testing.T) {
	opts := options{version: "2026.08.18.0", architecture: "arm64", channel: "beta", stagingDirectory: "stage", outputPath: "out.zip"}
	if err := fillDefaults(&opts); err == nil {
		t.Fatal("expected arm64 beta mismatch to fail")
	}
}
