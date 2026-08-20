// Command package-zip creates deterministic Paperboat Windows client archives.
// It intentionally does not sign or publish the resulting archive.
package main

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
)

const (
	productName       = "paperboat"
	metadataName      = "paperboat-windows.json"
	defaultEpoch      = int64(315532800) // 1980-01-01, the ZIP timestamp floor.
	versionExpression = `^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.(0|[1-9][0-9]*)$`
)

var versionPattern = regexp.MustCompile(versionExpression)

type options struct {
	version          string
	architecture     string
	channel          string
	stagingDirectory string
	outputPath       string
	epoch            int64
}

type archiveMetadata struct {
	Schema             string   `json:"schema"`
	Product            string   `json:"product"`
	Version            string   `json:"version"`
	Platform           string   `json:"platform"`
	Architecture       string   `json:"architecture"`
	Channel            string   `json:"channel"`
	Stability          string   `json:"stability"`
	NativeE2E          string   `json:"native_e2e"`
	SigningStatus      string   `json:"signing_status"`
	IncludedComponents []string `json:"included_components"`
}

type inputFile struct {
	name string
	path string
}

func main() {
	var opts options
	flag.StringVar(&opts.version, "version", "", "Paperboat release version")
	flag.StringVar(&opts.architecture, "architecture", "", "Windows architecture: amd64 or arm64")
	flag.StringVar(&opts.channel, "channel", "", "release channel; defaults from architecture")
	flag.StringVar(&opts.stagingDirectory, "staging", "", "directory containing release-built client files")
	flag.StringVar(&opts.outputPath, "output", "", "output ZIP path")
	flag.Parse()

	if err := fillDefaults(&opts); err != nil {
		fatal(err)
	}
	if err := packageArchive(opts); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "package-zip: %v\n", err)
	os.Exit(2)
}

func fillDefaults(opts *options) error {
	if opts.version == "" || !versionPattern.MatchString(opts.version) {
		return fmt.Errorf("version must match YYYY.MM.DD.X")
	}
	if opts.architecture != "amd64" && opts.architecture != "arm64" {
		return fmt.Errorf("architecture must be amd64 or arm64")
	}
	expectedChannel := map[string]string{"amd64": "stable", "arm64": "beta"}[opts.architecture]
	if opts.channel == "" {
		opts.channel = expectedChannel
	}
	if opts.channel != expectedChannel {
		return fmt.Errorf("architecture %s requires channel %s, got %s", opts.architecture, expectedChannel, opts.channel)
	}
	if opts.stagingDirectory == "" {
		return fmt.Errorf("staging is required")
	}
	if opts.outputPath == "" {
		return fmt.Errorf("output is required")
	}
	if opts.epoch == 0 {
		opts.epoch = defaultEpoch
		if value := os.Getenv("SOURCE_DATE_EPOCH"); value != "" {
			epoch, err := strconv.ParseInt(value, 10, 64)
			if err != nil || epoch < 0 {
				return fmt.Errorf("SOURCE_DATE_EPOCH must be a non-negative integer")
			}
			opts.epoch = epoch
		}
	}
	return nil
}

func packageArchive(opts options) error {
	if opts.epoch == 0 {
		opts.epoch = defaultEpoch
	}
	if err := validateStaging(opts.stagingDirectory); err != nil {
		return err
	}
	if _, err := os.Stat(opts.outputPath); err == nil {
		return fmt.Errorf("output already exists: %s", opts.outputPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output: %w", err)
	}

	inputs := []inputFile{
		{name: "pb-launcher.exe", path: filepath.Join(opts.stagingDirectory, "pb-launcher.exe")},
		{name: "pb.exe", path: filepath.Join(opts.stagingDirectory, "pb.exe")},
	}
	metadata := archiveMetadata{
		Schema:             "paperboat.windows-portable/v1",
		Product:            productName,
		Version:            opts.version,
		Platform:           "windows",
		Architecture:       opts.architecture,
		Channel:            opts.channel,
		Stability:          opts.channel,
		NativeE2E:          map[string]string{"amd64": "required_before_stable_release", "arm64": "required_before_stable_promotion"}[opts.architecture],
		SigningStatus:      "tuf_checksums_required",
		IncludedComponents: []string{"cli", "launcher"},
	}
	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("encode archive metadata: %w", err)
	}
	metadataBytes = append(metadataBytes, '\n')

	inputs = append(inputs, inputFile{name: metadataName, path: ""})
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].name < inputs[j].name })

	if err := os.MkdirAll(filepath.Dir(opts.outputPath), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	//paperboat:allow-source-policy atomic-replacement owner=windows-packaging reason=same-directory-deterministic-zip-staging
	temporary, err := os.CreateTemp(filepath.Dir(opts.outputPath), ".paperboat-zip-*")
	if err != nil {
		return fmt.Errorf("create temporary archive: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	archive := zip.NewWriter(temporary)
	archiveTime := time.Unix(opts.epoch, 0).UTC()
	for _, input := range inputs {
		header := &zip.FileHeader{Name: input.name, Method: zip.Deflate}
		header.SetModTime(archiveTime)
		header.SetMode(0o100644)
		writer, err := archive.CreateHeader(header)
		if err != nil {
			_ = archive.Close()
			_ = temporary.Close()
			return fmt.Errorf("create archive entry %s: %w", input.name, err)
		}
		if input.name == metadataName {
			if _, err := writer.Write(metadataBytes); err != nil {
				_ = archive.Close()
				_ = temporary.Close()
				return fmt.Errorf("write archive metadata: %w", err)
			}
			continue
		}
		file, err := os.Open(input.path)
		if err != nil {
			_ = archive.Close()
			_ = temporary.Close()
			return fmt.Errorf("open %s: %w", input.name, err)
		}
		_, copyErr := io.Copy(writer, file)
		closeErr := file.Close()
		if copyErr != nil {
			_ = archive.Close()
			_ = temporary.Close()
			return fmt.Errorf("copy %s: %w", input.name, copyErr)
		}
		if closeErr != nil {
			_ = archive.Close()
			_ = temporary.Close()
			return fmt.Errorf("close %s: %w", input.name, closeErr)
		}
	}
	if err := archive.Close(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("close archive: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary archive: %w", err)
	}
	//paperboat:allow-source-policy atomic-replacement owner=windows-packaging reason=validated-same-directory-zip-publication
	if err := os.Rename(temporaryPath, opts.outputPath); err != nil {
		return fmt.Errorf("publish archive: %w", err)
	}
	return nil
}

func validateStaging(directory string) error {
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("staging directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("staging path is not a directory: %s", directory)
	}
	for _, name := range []string{"pb.exe", "pb-launcher.exe"} {
		path := filepath.Join(directory, name)
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("required staging file %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("required staging file is not regular: %s", name)
		}
	}
	return nil
}
