// Package winget validates rendered WinGet manifests before publication.
package winget

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	PackageIdentifier = "Pinksaucepasta.Paperboat"
	ManifestVersion   = "1.6.0"
	DefaultLocale     = "en-US"
	DisplayName       = "Paperboat"
	InstallerType     = "msi"
	InstallerScope    = "machine"
	UpgradeBehavior   = "install"
	SilentSwitches    = "/qn /norestart"
	ProgressSwitches  = "/qb /norestart"
	PublisherURL      = "https://github.com/pinksaucepasta/paperboat"
	PackageURL        = "https://github.com/pinksaucepasta/paperboat"
	LicenseURL        = "https://github.com/pinksaucepasta/paperboat/blob/main/LICENSE"
)

const (
	versionManifestFile   = "Pinksaucepasta.Paperboat.yaml"
	localeManifestFile    = "Pinksaucepasta.Paperboat.locale.en-US.yaml"
	installerManifestFile = "Pinksaucepasta.Paperboat.installer.yaml"
	maxManifestSize       = 1 << 20
)

var (
	releaseVersionPattern = regexp.MustCompile(`^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$`)
	repositoryPattern     = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	sha256Pattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	guidPattern           = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)
)

// Options controls release-specific checks. Repository and Version are
// optional for callers that only have a rendered directory. When omitted,
// the validator still requires both installer URLs to have the exact same
// GitHub repository and release version derived from PackageVersion.
//
// Supplying MSI paths additionally binds each manifest hash to the final MSI
// bytes. Supplying product codes binds the rendered AppsAndFeaturesEntries to
// the product codes read from those MSI files by the renderer.
type Options struct {
	Repository       string
	Version          string
	AMD64MSI         string
	ARM64MSI         string
	AMD64ProductCode string
	ARM64ProductCode string
}

type versionManifest struct {
	PackageIdentifier string `yaml:"PackageIdentifier"`
	PackageVersion    string `yaml:"PackageVersion"`
	DefaultLocale     string `yaml:"DefaultLocale"`
	ManifestType      string `yaml:"ManifestType"`
	ManifestVersion   string `yaml:"ManifestVersion"`
}

type localeManifest struct {
	PackageIdentifier string `yaml:"PackageIdentifier"`
	PackageVersion    string `yaml:"PackageVersion"`
	PackageLocale     string `yaml:"PackageLocale"`
	Publisher         string `yaml:"Publisher"`
	PublisherURL      string `yaml:"PublisherUrl"`
	PackageName       string `yaml:"PackageName"`
	PackageURL        string `yaml:"PackageUrl"`
	License           string `yaml:"License"`
	LicenseURL        string `yaml:"LicenseUrl"`
	ShortDescription  string `yaml:"ShortDescription"`
	ReleaseNotesURL   string `yaml:"ReleaseNotesUrl"`
	ManifestType      string `yaml:"ManifestType"`
	ManifestVersion   string `yaml:"ManifestVersion"`
}

type installerManifest struct {
	PackageIdentifier string      `yaml:"PackageIdentifier"`
	PackageVersion    string      `yaml:"PackageVersion"`
	Installers        []installer `yaml:"Installers"`
	ManifestType      string      `yaml:"ManifestType"`
	ManifestVersion   string      `yaml:"ManifestVersion"`
}

type installer struct {
	Architecture           string                 `yaml:"Architecture"`
	InstallerType          string                 `yaml:"InstallerType"`
	InstallerURL           string                 `yaml:"InstallerUrl"`
	InstallerSHA256        string                 `yaml:"InstallerSha256"`
	Scope                  string                 `yaml:"Scope"`
	InstallerSwitches      installerSwitches      `yaml:"InstallerSwitches"`
	UpgradeBehavior        string                 `yaml:"UpgradeBehavior"`
	AppsAndFeaturesEntries []appsAndFeaturesEntry `yaml:"AppsAndFeaturesEntries"`
}

type installerSwitches struct {
	Silent             string `yaml:"Silent"`
	SilentWithProgress string `yaml:"SilentWithProgress"`
}

type appsAndFeaturesEntry struct {
	DisplayName string `yaml:"DisplayName"`
	ProductCode string `yaml:"ProductCode"`
}

// ValidateDirectory validates the three rendered stable manifests in
// directory. It rejects extra YAML manifests so a candidate cannot silently
// publish an unvalidated fourth file.
func ValidateDirectory(directory string, options Options) error {
	if strings.TrimSpace(directory) == "" {
		return errors.New("manifest directory is required")
	}
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("stat manifest directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("manifest path is not a directory: %s", directory)
	}

	paths := map[string]string{
		"version":   filepath.Join(directory, versionManifestFile),
		"locale":    filepath.Join(directory, localeManifestFile),
		"installer": filepath.Join(directory, installerManifestFile),
	}
	if err := rejectExtraYAML(directory); err != nil {
		return err
	}

	var version versionManifest
	if err := decodeManifest(paths["version"], &version); err != nil {
		return err
	}
	var locale localeManifest
	if err := decodeManifest(paths["locale"], &locale); err != nil {
		return err
	}
	var installer installerManifest
	if err := decodeManifest(paths["installer"], &installer); err != nil {
		return err
	}

	if err := validateIdentity(version, locale, installer, options); err != nil {
		return err
	}
	return validateInstallers(installer.Installers, version.PackageVersion, options)
}

func rejectExtraYAML(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read manifest directory: %w", err)
	}
	wanted := map[string]struct{}{
		versionManifestFile:   {},
		localeManifestFile:    {},
		installerManifestFile: {},
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".yaml") {
			continue
		}
		if _, ok := wanted[entry.Name()]; !ok {
			return fmt.Errorf("unexpected YAML manifest %q", entry.Name())
		}
	}
	return nil
}

func decodeManifest(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read rendered WinGet manifest %s: %w", filepath.Base(path), err)
	}
	if len(data) == 0 {
		return fmt.Errorf("rendered WinGet manifest %s is empty", filepath.Base(path))
	}
	if len(data) > maxManifestSize {
		return fmt.Errorf("rendered WinGet manifest %s exceeds %d bytes", filepath.Base(path), maxManifestSize)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode rendered WinGet manifest %s: %w", filepath.Base(path), err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("rendered WinGet manifest %s contains multiple YAML documents", filepath.Base(path))
		}
		return fmt.Errorf("decode trailing YAML in %s: %w", filepath.Base(path), err)
	}
	return nil
}

func validateIdentity(version versionManifest, locale localeManifest, installer installerManifest, options Options) error {
	if version.PackageIdentifier != PackageIdentifier || locale.PackageIdentifier != PackageIdentifier || installer.PackageIdentifier != PackageIdentifier {
		return fmt.Errorf("all manifests must use PackageIdentifier %q", PackageIdentifier)
	}
	if !releaseVersionPattern.MatchString(version.PackageVersion) {
		return fmt.Errorf("invalid PackageVersion %q; want YYYY.MM.DD.N", version.PackageVersion)
	}
	if options.Version != "" && version.PackageVersion != options.Version {
		return fmt.Errorf("PackageVersion %q does not match expected release %q", version.PackageVersion, options.Version)
	}
	if locale.PackageVersion != version.PackageVersion || installer.PackageVersion != version.PackageVersion {
		return fmt.Errorf("PackageVersion must match across all three manifests")
	}
	if version.DefaultLocale != DefaultLocale || locale.PackageLocale != DefaultLocale {
		return fmt.Errorf("default locale must be %q", DefaultLocale)
	}
	if version.ManifestType != "version" || locale.ManifestType != "defaultLocale" || installer.ManifestType != "installer" {
		return fmt.Errorf("manifest types must be version, defaultLocale, and installer")
	}
	if version.ManifestVersion != ManifestVersion || locale.ManifestVersion != ManifestVersion || installer.ManifestVersion != ManifestVersion {
		return fmt.Errorf("all manifests must use ManifestVersion %q", ManifestVersion)
	}
	if locale.Publisher != "Paperboat" || locale.PackageName != "Paperboat" || locale.License != "MIT" || locale.ShortDescription != "Native Paperboat client and host for Windows." {
		return errors.New("default locale metadata does not match the Paperboat contract")
	}
	if locale.PublisherURL != PublisherURL || locale.PackageURL != PackageURL || locale.LicenseURL != LicenseURL {
		return errors.New("default locale project URLs do not match the Paperboat contract")
	}

	if options.Repository != "" && !repositoryPattern.MatchString(options.Repository) {
		return fmt.Errorf("invalid GitHub repository %q", options.Repository)
	}
	if options.Repository != "" {
		wantReleaseNotes := "https://github.com/" + options.Repository + "/releases/tag/" + version.PackageVersion
		if locale.ReleaseNotesURL != wantReleaseNotes {
			return fmt.Errorf("ReleaseNotesUrl %q does not match %q", locale.ReleaseNotesURL, wantReleaseNotes)
		}
	}
	return nil
}

func validateInstallers(installers []installer, version string, options Options) error {
	if len(installers) != 2 {
		return fmt.Errorf("installer manifest must contain exactly x64 and arm64 entries, got %d", len(installers))
	}
	wantArchitectures := []string{"x64", "arm64"}
	seen := make(map[string]struct{}, len(installers))
	for index, value := range installers {
		architecture := wantArchitectures[index]
		if value.Architecture != architecture {
			return fmt.Errorf("installer %d has architecture %q, want %q", index, value.Architecture, architecture)
		}
		if _, ok := seen[value.Architecture]; ok {
			return fmt.Errorf("duplicate installer architecture %q", value.Architecture)
		}
		seen[value.Architecture] = struct{}{}
		if err := validateInstaller(value, architecture, version, options); err != nil {
			return err
		}
	}
	return nil
}

func validateInstaller(value installer, architecture, version string, options Options) error {
	if value.InstallerType != InstallerType {
		return fmt.Errorf("%s installer type must be %q", architecture, InstallerType)
	}
	if value.InstallerSHA256 == "" || !sha256Pattern.MatchString(value.InstallerSHA256) {
		return fmt.Errorf("%s InstallerSha256 must be 64 lowercase hexadecimal characters", architecture)
	}
	if value.Scope != InstallerScope {
		return fmt.Errorf("%s Scope must be %q", architecture, InstallerScope)
	}
	if value.InstallerSwitches.Silent != SilentSwitches || value.InstallerSwitches.SilentWithProgress != ProgressSwitches {
		return fmt.Errorf("%s installer switches do not match the MSI contract", architecture)
	}
	if value.UpgradeBehavior != UpgradeBehavior {
		return fmt.Errorf("%s UpgradeBehavior must be %q", architecture, UpgradeBehavior)
	}
	if len(value.AppsAndFeaturesEntries) != 1 {
		return fmt.Errorf("%s must contain exactly one AppsAndFeaturesEntries item", architecture)
	}
	entry := value.AppsAndFeaturesEntries[0]
	if entry.DisplayName != DisplayName {
		return fmt.Errorf("%s AppsAndFeaturesEntries DisplayName must be %q", architecture, DisplayName)
	}
	if !guidPattern.MatchString(entry.ProductCode) {
		return fmt.Errorf("%s ProductCode %q is not a canonical MSI product GUID", architecture, entry.ProductCode)
	}

	wantURL, err := expectedInstallerURL(value.InstallerURL, architecture, version, options.Repository)
	if err != nil {
		return fmt.Errorf("%s InstallerUrl: %w", architecture, err)
	}
	if value.InstallerURL != wantURL {
		return fmt.Errorf("%s InstallerUrl %q does not match %q", architecture, value.InstallerURL, wantURL)
	}
	if expectedPath := msiPath(architecture, options); expectedPath != "" {
		digest, err := fileSHA256(expectedPath)
		if err != nil {
			return fmt.Errorf("%s MSI hash: %w", architecture, err)
		}
		if value.InstallerSHA256 != digest {
			return fmt.Errorf("%s InstallerSha256 %q does not match final MSI hash %q", architecture, value.InstallerSHA256, digest)
		}
	}
	if expectedCode := productCode(architecture, options); expectedCode != "" && !strings.EqualFold(entry.ProductCode, expectedCode) {
		return fmt.Errorf("%s ProductCode %q does not match expected MSI product code %q", architecture, entry.ProductCode, expectedCode)
	}
	return nil
}

func expectedInstallerURL(actual, architecture, version, repository string) (string, error) {
	if repository != "" {
		if !repositoryPattern.MatchString(repository) {
			return "", fmt.Errorf("repository %q is invalid", repository)
		}
		return fmt.Sprintf("https://github.com/%s/releases/download/%s/paperboat_%s_windows_%s.msi", repository, version, version, map[string]string{"x64": "amd64", "arm64": "arm64"}[architecture]), nil
	}
	const prefix = "https://github.com/"
	const marker = "/releases/download/"
	if !strings.HasPrefix(actual, prefix) {
		return "", errors.New("must use an HTTPS GitHub release URL")
	}
	rest := strings.TrimPrefix(actual, prefix)
	parts := strings.Split(rest, marker)
	if len(parts) != 2 || !repositoryPattern.MatchString(parts[0]) {
		return "", errors.New("must use exactly one GitHub repository and release-download path")
	}
	return fmt.Sprintf("https://github.com/%s/releases/download/%s/paperboat_%s_windows_%s.msi", parts[0], version, version, map[string]string{"x64": "amd64", "arm64": "arm64"}[architecture]), nil
}

func msiPath(architecture string, options Options) string {
	if architecture == "x64" {
		return options.AMD64MSI
	}
	return options.ARM64MSI
}

func productCode(architecture string, options Options) string {
	if architecture == "x64" {
		return options.AMD64ProductCode
	}
	return options.ARM64ProductCode
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
