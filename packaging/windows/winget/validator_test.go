package winget

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testVersion    = "2026.08.22.16"
	testRepository = "pinksaucepasta/paperboat-cli"
)

func TestValidateDirectoryAcceptsRenderedStableManifests(t *testing.T) {
	directory := writeValidManifests(t)
	if err := ValidateDirectory(directory, Options{Repository: testRepository, Version: testVersion}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDirectoryRejectsUnknownFields(t *testing.T) {
	tests := []struct {
		name string
		file string
		body string
	}{
		{name: "top level", file: versionManifestFile, body: "Unexpected: true\n"},
		{name: "installer switch", file: installerManifestFile, body: "      Unexpected: /bad\n"},
		{name: "apps and features", file: installerManifestFile, body: "        Unexpected: true\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := writeValidManifests(t)
			path := filepath.Join(directory, test.file)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			switch test.name {
			case "top level":
				text += test.body
			case "installer switch":
				text = strings.Replace(text, "      SilentWithProgress: /qb /norestart\n", "      SilentWithProgress: /qb /norestart\n"+test.body, 1)
			case "apps and features":
				text = strings.Replace(text, "        ProductCode: \"{11111111-1111-1111-1111-111111111111}\"\n", "        ProductCode: \"{11111111-1111-1111-1111-111111111111}\"\n"+test.body, 1)
			}
			if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ValidateDirectory(directory, Options{Repository: testRepository, Version: testVersion}); err == nil {
				t.Fatal("manifest with an unknown field was accepted")
			}
		})
	}
}

func TestValidateDirectoryRejectsMultipleDocumentsAndDuplicateKeys(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "multiple documents", body: "\n---\nPackageIdentifier: Pinksaucepasta.Paperboat\n"},
		{name: "duplicate key", body: "PackageVersion: \"2026.08.22.99\"\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := writeValidManifests(t)
			path := filepath.Join(directory, versionManifestFile)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "multiple documents" {
				data = append(data, []byte(test.body)...)
			} else {
				data = append(data, []byte("\n"+test.body)...)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ValidateDirectory(directory, Options{Repository: testRepository, Version: testVersion}); err == nil {
				t.Fatal("invalid YAML document was accepted")
			}
		})
	}
}

func TestValidateDirectoryRejectsCrossFileMismatches(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		oldValue string
		newValue string
	}{
		{name: "package identifier", file: localeManifestFile, oldValue: "PackageIdentifier: Pinksaucepasta.Paperboat", newValue: "PackageIdentifier: Other.Package"},
		{name: "package version", file: installerManifestFile, oldValue: "PackageVersion: \"2026.08.22.16\"", newValue: "PackageVersion: \"2026.08.22.17\""},
		{name: "default locale", file: versionManifestFile, oldValue: "DefaultLocale: en-US", newValue: "DefaultLocale: de-DE"},
		{name: "manifest type", file: localeManifestFile, oldValue: "ManifestType: defaultLocale", newValue: "ManifestType: installer"},
		{name: "manifest version", file: installerManifestFile, oldValue: "ManifestVersion: 1.6.0", newValue: "ManifestVersion: 1.5.0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := writeValidManifests(t)
			replaceManifestText(t, directory, test.file, test.oldValue, test.newValue)
			if err := ValidateDirectory(directory, Options{Repository: testRepository, Version: testVersion}); err == nil {
				t.Fatal("cross-file mismatch was accepted")
			}
		})
	}
}

func TestValidateDirectoryRejectsWrongLocaleProjectURL(t *testing.T) {
	directory := writeValidManifests(t)
	replaceManifestText(t, directory, localeManifestFile, PublisherURL, "https://example.com/paperboat")
	if err := ValidateDirectory(directory, Options{Repository: testRepository, Version: testVersion}); err == nil {
		t.Fatal("wrong locale project URL was accepted")
	}
}

func TestValidateDirectoryRejectsMissingOrDuplicateArchitecture(t *testing.T) {
	directory := writeValidManifests(t)
	path := filepath.Join(directory, installerManifestFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	armInstaller := `  - Architecture: arm64
    InstallerType: msi
    InstallerUrl: "https://github.com/pinksaucepasta/paperboat-cli/releases/download/2026.08.22.16/paperboat_2026.08.22.16_windows_arm64.msi"
    InstallerSha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    Scope: machine
    InstallerSwitches:
      Silent: /qn /norestart
      SilentWithProgress: /qb /norestart
    UpgradeBehavior: install
    AppsAndFeaturesEntries:
      - DisplayName: Paperboat
        ProductCode: "{22222222-2222-2222-2222-222222222222}"
`
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), armInstaller, "", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDirectory(directory, Options{Repository: testRepository, Version: testVersion}); err == nil {
		t.Fatal("manifest with a missing architecture was accepted")
	}

	directory = writeValidManifests(t)
	data, err = os.ReadFile(filepath.Join(directory, installerManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	duplicate := strings.Replace(string(data), "Architecture: arm64", "Architecture: x64", 1)
	if err := os.WriteFile(filepath.Join(directory, installerManifestFile), []byte(duplicate), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDirectory(directory, Options{Repository: testRepository, Version: testVersion}); err == nil {
		t.Fatal("manifest with duplicate architectures was accepted")
	}
}

func TestValidateDirectoryRejectsBadInstallerFields(t *testing.T) {
	tests := []struct {
		name     string
		oldValue string
		newValue string
	}{
		{name: "URL", oldValue: "paperboat_2026.08.22.16_windows_arm64.msi", newValue: "paperboat_2026.08.22.16_windows_arm64.zip"},
		{name: "uppercase hash", oldValue: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", newValue: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"},
		{name: "short hash", oldValue: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", newValue: "bbbb"},
		{name: "scope", oldValue: "Scope: machine", newValue: "Scope: user"},
		{name: "silent switch", oldValue: "Silent: /qn /norestart", newValue: "Silent: /quiet"},
		{name: "progress switch", oldValue: "SilentWithProgress: /qb /norestart", newValue: "SilentWithProgress: /passive"},
		{name: "upgrade behavior", oldValue: "UpgradeBehavior: install", newValue: "UpgradeBehavior: uninstallPrevious"},
		{name: "product GUID", oldValue: "{22222222-2222-2222-2222-222222222222}", newValue: "not-a-guid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := writeValidManifests(t)
			replaceManifestText(t, directory, installerManifestFile, test.oldValue, test.newValue)
			if err := ValidateDirectory(directory, Options{Repository: testRepository, Version: testVersion}); err == nil {
				t.Fatal("invalid installer field was accepted")
			}
		})
	}
}

func TestValidateDirectoryBindsMSIHashesAndProductCodes(t *testing.T) {
	directory := writeValidManifests(t)
	amd64MSI := filepath.Join(directory, "amd64.msi")
	arm64MSI := filepath.Join(directory, "arm64.msi")
	if err := os.WriteFile(amd64MSI, []byte("amd64-msi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(arm64MSI, []byte("arm64-msi"), 0o600); err != nil {
		t.Fatal(err)
	}
	amd64Hash := fmt.Sprintf("%x", sha256.Sum256([]byte("amd64-msi")))
	arm64Hash := fmt.Sprintf("%x", sha256.Sum256([]byte("arm64-msi")))
	replaceManifestText(t, directory, installerManifestFile, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", amd64Hash)
	replaceManifestText(t, directory, installerManifestFile, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", arm64Hash)
	options := Options{
		Repository:       testRepository,
		Version:          testVersion,
		AMD64MSI:         amd64MSI,
		ARM64MSI:         arm64MSI,
		AMD64ProductCode: "{11111111-1111-1111-1111-111111111111}",
		ARM64ProductCode: "{22222222-2222-2222-2222-222222222222}",
	}
	if err := ValidateDirectory(directory, options); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(arm64MSI, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDirectory(directory, options); err == nil {
		t.Fatal("manifest with an MSI hash mismatch was accepted")
	}
}

func TestValidateDirectoryRejectsExtraYAML(t *testing.T) {
	directory := writeValidManifests(t)
	if err := os.WriteFile(filepath.Join(directory, "unexpected.yaml"), []byte("PackageIdentifier: Other.Package\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDirectory(directory, Options{Repository: testRepository, Version: testVersion}); err == nil {
		t.Fatal("extra YAML manifest was accepted")
	}
}

func writeValidManifests(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	baseURL := "https://github.com/" + testRepository + "/releases/download/" + testVersion
	if err := os.WriteFile(filepath.Join(directory, versionManifestFile), []byte(fmt.Sprintf(`PackageIdentifier: %s
PackageVersion: "%s"
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
`, PackageIdentifier, testVersion)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, localeManifestFile), []byte(fmt.Sprintf(`PackageIdentifier: %s
PackageVersion: "%s"
PackageLocale: en-US
Publisher: Paperboat
PublisherUrl: https://github.com/pinksaucepasta/paperboat
PackageName: Paperboat
PackageUrl: https://github.com/pinksaucepasta/paperboat
License: MIT
LicenseUrl: https://github.com/pinksaucepasta/paperboat/blob/main/LICENSE
ShortDescription: Native Paperboat client and host for Windows.
ReleaseNotesUrl: "https://github.com/%s/releases/tag/%s"
ManifestType: defaultLocale
ManifestVersion: 1.6.0
`, PackageIdentifier, testVersion, testRepository, testVersion)), 0o600); err != nil {
		t.Fatal(err)
	}
	installer := fmt.Sprintf(`PackageIdentifier: %s
PackageVersion: "%s"
Installers:
  - Architecture: x64
    InstallerType: msi
    InstallerUrl: "%s/paperboat_%s_windows_amd64.msi"
    InstallerSha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    Scope: machine
    InstallerSwitches:
      Silent: /qn /norestart
      SilentWithProgress: /qb /norestart
    UpgradeBehavior: install
    AppsAndFeaturesEntries:
      - DisplayName: Paperboat
        ProductCode: "{11111111-1111-1111-1111-111111111111}"
  - Architecture: arm64
    InstallerType: msi
    InstallerUrl: "%s/paperboat_%s_windows_arm64.msi"
    InstallerSha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    Scope: machine
    InstallerSwitches:
      Silent: /qn /norestart
      SilentWithProgress: /qb /norestart
    UpgradeBehavior: install
    AppsAndFeaturesEntries:
      - DisplayName: Paperboat
        ProductCode: "{22222222-2222-2222-2222-222222222222}"
ManifestType: installer
ManifestVersion: 1.6.0
`, PackageIdentifier, testVersion, baseURL, testVersion, baseURL, testVersion)
	if err := os.WriteFile(filepath.Join(directory, installerManifestFile), []byte(installer), 0o600); err != nil {
		t.Fatal(err)
	}
	return directory
}

func replaceManifestText(t *testing.T, directory, name, oldValue, newValue string) {
	t.Helper()
	path := filepath.Join(directory, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, oldValue) {
		t.Fatalf("fixture %s does not contain %q", name, oldValue)
	}
	text = strings.Replace(text, oldValue, newValue, 1)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}
