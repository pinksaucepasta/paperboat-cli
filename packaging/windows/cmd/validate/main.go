// Command validate checks the checked-in Windows packaging contract without
// requiring WiX, WinGet, a Windows host, or a signing certificate.
package main

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	windowsmanifest "github.com/pinksaucepasta/paperboat/packaging/windows/manifest"
)

type metadata struct {
	Schema      string         `json:"schema"`
	Product     string         `json:"product"`
	Platform    string         `json:"platform"`
	PackageID   string         `json:"package_identifier"`
	PortableZip portableZip    `json:"portable_zip"`
	Machine     machineInstall `json:"machine_install"`
	Components  []component    `json:"components"`
	Services    []service      `json:"services"`
	OpenSSH     openSSH        `json:"openssh"`
	Targets     []target       `json:"targets"`
	Signing     signing        `json:"signing"`
}

type portableZip struct {
	ClientOnly        bool     `json:"client_only"`
	RequiredFiles     []string `json:"required_files"`
	GeneratedMetadata string   `json:"generated_metadata"`
}

type machineInstall struct {
	InstallRoot     string `json:"install_root"`
	BinaryRoot      string `json:"binary_root"`
	StateRoot       string `json:"state_root"`
	UserStateRoot   string `json:"user_state_root"`
	UserConfigRoot  string `json:"user_config_root"`
	LocalIPC        string `json:"local_ipc"`
	InboundFirewall string `json:"inbound_firewall_rule"`
}

type component struct {
	ID   string `json:"id"`
	File string `json:"file"`
	Role string `json:"role"`
}

type service struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Binary      string `json:"binary"`
	Arguments   string `json:"arguments"`
	Start       string `json:"start"`
	Account     string `json:"account"`
}

type openSSH struct {
	PackageID              string   `json:"package_id"`
	ApprovedVersion        string   `json:"approved_version"`
	Installer              string   `json:"installer"`
	InstallScope           string   `json:"install_scope"`
	RequiredParts          []string `json:"required_parts"`
	Service                string   `json:"service"`
	StateRoot              string   `json:"state_root"`
	BindPolicy             []string `json:"bind_policy"`
	CapabilityInstallation string   `json:"capability_installation"`
	ExistingSystemSSHD     string   `json:"existing_system_sshd"`
}

type target struct {
	Architecture           string `json:"architecture"`
	WixPlatform            string `json:"wix_platform"`
	WingetArchitecture     string `json:"winget_architecture"`
	Channel                string `json:"channel"`
	Stability              string `json:"stability"`
	NativeE2E              string `json:"native_e2e"`
	NativeHardwareEvidence string `json:"native_hardware_evidence"`
}

type signing struct {
	RequiredForRelease bool   `json:"required_for_release"`
	Status             string `json:"status"`
	Authenticode       string `json:"authenticode"`
	Timestamping       string `json:"timestamping"`
	Publisher          string `json:"publisher"`
	PrivateMaterial    string `json:"private_material"`
}

var versionPlaceholder = regexp.MustCompile(`\{\{VERSION\}\}`)
var secretPattern = regexp.MustCompile(`(?i)(-----BEGIN .*PRIVATE KEY-----|password\s*[:=]|passwd\s*[:=]|client[_-]?secret\s*[:=]|api[_-]?key\s*[:=])`)

func main() {
	root := flag.String("root", "", "packaging/windows directory")
	flag.Parse()
	resolvedRoot := *root
	if resolvedRoot == "" {
		workingDirectory, err := os.Getwd()
		if err != nil {
			fatal(err)
		}
		resolvedRoot = filepath.Join(workingDirectory, "packaging", "windows")
		if _, err := os.Stat(filepath.Join(resolvedRoot, "metadata.json")); errors.Is(err, os.ErrNotExist) {
			resolvedRoot = workingDirectory
		}
	}
	if err := validate(resolvedRoot); err != nil {
		fatal(err)
	}
	fmt.Println("Windows packaging contract is valid.")
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "validate-windows-packaging: %v\n", err)
	os.Exit(1)
}

func validate(root string) error {
	metadataBytes, err := read(root, "metadata.json")
	if err != nil {
		return err
	}
	var policy metadata
	if err := json.Unmarshal(metadataBytes, &policy); err != nil {
		return fmt.Errorf("metadata.json is not valid JSON: %w", err)
	}
	if err := validatePolicy(policy); err != nil {
		return fmt.Errorf("metadata policy: %w", err)
	}
	if err := validateWix(root, policy); err != nil {
		return err
	}
	if err := validateWinget(root); err != nil {
		return err
	}
	if err := validateAssets(root, policy); err != nil {
		return err
	}
	return validateSourceHygiene(root)
}

func validatePolicy(policy metadata) error {
	if policy.Schema != "paperboat.windows-packaging/v1" || policy.Product != "paperboat" || policy.Platform != "windows" {
		return fmt.Errorf("schema, product, or platform is incorrect")
	}
	if policy.PackageID != "Pinksaucepasta.Paperboat" {
		return fmt.Errorf("unexpected stable package identifier %q", policy.PackageID)
	}
	if !policy.PortableZip.ClientOnly || policy.PortableZip.GeneratedMetadata != "paperboat-windows.json" || !sameStrings(policy.PortableZip.RequiredFiles, []string{"pb.exe", "pb-launcher.exe"}) {
		return fmt.Errorf("portable ZIP contract is incorrect")
	}
	if policy.Machine.InstallRoot != `C:\Program Files\Paperboat` || policy.Machine.BinaryRoot != `C:\Program Files\Paperboat\bin` || policy.Machine.StateRoot != `C:\ProgramData\Paperboat` {
		return fmt.Errorf("machine-wide path contract is incorrect")
	}
	if policy.Machine.UserStateRoot != `%LOCALAPPDATA%\Paperboat` || policy.Machine.UserConfigRoot != `%APPDATA%\Paperboat` || policy.Machine.LocalIPC != `\\.\pipe\Paperboat-*` || policy.Machine.InboundFirewall != "none" {
		return fmt.Errorf("user state, IPC, or firewall contract is incorrect")
	}
	wantComponents := []component{
		{ID: "cli", File: "pb.exe", Role: "client"},
		{ID: "launcher", File: "pb-launcher.exe", Role: "client_launcher"},
		{ID: "runtime", File: "paperboat-runtime.exe", Role: "runtime"},
		{ID: "host_supervisor", File: "paperboat-hostd.exe", Role: "host_supervisor"},
		{ID: "updater", File: "paperboat-updater.exe", Role: "updater"},
	}
	if !sameComponents(policy.Components, wantComponents) {
		return fmt.Errorf("component contract is incorrect")
	}
	wantServices := []service{
		{ID: "host_supervisor", Name: "PaperboatHostd", DisplayName: "Paperboat Host Supervisor", Binary: "paperboat-hostd.exe", Arguments: "__runtime-hostd", Start: "demand_until_enrolled", Account: "LocalSystem"},
		{ID: "updater", Name: "PaperboatUpdated", DisplayName: "Paperboat Updater", Binary: "paperboat-updater.exe", Arguments: "__runtime-updated", Start: "demand", Account: "LocalSystem"},
	}
	if !sameServices(policy.Services, wantServices) {
		return fmt.Errorf("service contract is incorrect")
	}
	if policy.OpenSSH.PackageID != "Microsoft.OpenSSH.Preview" || policy.OpenSSH.ApprovedVersion != "10.0.0.0" || policy.OpenSSH.Installer != "winget" || policy.OpenSSH.InstallScope != "machine" || policy.OpenSSH.Service != "PaperboatSshd" || policy.OpenSSH.StateRoot != `C:\ProgramData\Paperboat\ssh` || policy.OpenSSH.CapabilityInstallation != "never" || policy.OpenSSH.ExistingSystemSSHD != "preserve" || !sameStrings(policy.OpenSSH.RequiredParts, []string{"client", "server"}) || !sameStrings(policy.OpenSSH.BindPolicy, []string{"127.0.0.1", "::1"}) {
		return fmt.Errorf("OpenSSH contract is incorrect")
	}
	wantTargets := []target{
		{Architecture: "amd64", WixPlatform: "x64", WingetArchitecture: "x64", Channel: "stable", Stability: "stable", NativeE2E: "required_before_stable_release", NativeHardwareEvidence: "release_gate"},
		{Architecture: "arm64", WixPlatform: "arm64", WingetArchitecture: "arm64", Channel: "beta", Stability: "beta", NativeE2E: "required_before_stable_promotion", NativeHardwareEvidence: "blocked_no_hardware_until_runner_exists"},
	}
	if !sameTargets(policy.Targets, wantTargets) {
		return fmt.Errorf("architecture/channel targets are incorrect")
	}
	if policy.Signing.RequiredForRelease || policy.Signing.Status != "tuf_checksums_required" || policy.Signing.Authenticode != "optional" || policy.Signing.Timestamping != "optional" || policy.Signing.Publisher != "not_required" || policy.Signing.PrivateMaterial != "never_committed" {
		return fmt.Errorf("Windows release integrity must rely on TUF and checksums; Authenticode is optional")
	}
	return nil
}

func validateWix(root string, policy metadata) error {
	source, err := read(root, "wix/Paperboat.wxs")
	if err != nil {
		return err
	}
	var document struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(source, &document); err != nil {
		return fmt.Errorf("wix/Paperboat.wxs is not well-formed XML: %w", err)
	}
	if document.XMLName.Local != "Wix" {
		return fmt.Errorf("wix/Paperboat.wxs root is %q, want Wix", document.XMLName.Local)
	}
	for _, required := range []string{
		`Value="$(var.WixPlatform)"`,
		`Name="PaperboatHostd"`,
		`Name="PaperboatUpdated"`,
		`Value="PaperboatSshd"`,
		`Microsoft.OpenSSH.Preview`,
		`Value="none"`,
		`CapabilityInstallation`,
		`ExistingSystemSshd`,
	} {
		if !strings.Contains(string(source), required) {
			return fmt.Errorf("wix/Paperboat.wxs is missing %q", required)
		}
	}
	forbiddenCapability := "Add-" + "WindowsCapability"
	forbiddenDisplayName := "winget install \"openssh " + "preview\""
	if strings.Contains(string(source), forbiddenCapability) || strings.Contains(strings.ToLower(string(source)), forbiddenDisplayName) {
		return fmt.Errorf("WiX source contains forbidden capability or display-name OpenSSH installation")
	}
	for _, project := range []struct {
		path     string
		platform string
		channel  string
	}{
		{path: "wix/Paperboat.amd64.wixproj", platform: "x64", channel: "stable"},
		{path: "wix/Paperboat.arm64.wixproj", platform: "arm64", channel: "beta"},
	} {
		projectBytes, err := read(root, project.path)
		if err != nil {
			return err
		}
		var projectXML struct{ XMLName xml.Name }
		if err := xml.Unmarshal(projectBytes, &projectXML); err != nil {
			return fmt.Errorf("%s is not well-formed XML: %w", project.path, err)
		}
		text := string(projectBytes)
		if projectXML.XMLName.Local != "Project" || !strings.Contains(text, "WixToolset.Sdk/") || !strings.Contains(text, "Platform>"+project.platform+"<") || !strings.Contains(text, "PaperboatChannel>"+project.channel+"<") {
			return fmt.Errorf("%s does not declare its architecture and channel", project.path)
		}
	}
	if policy.OpenSSH.PackageID != "Microsoft.OpenSSH.Preview" {
		return fmt.Errorf("WiX OpenSSH hook is not aligned with metadata")
	}
	return nil
}

func validateWinget(root string) error {
	templates := []struct {
		path          string
		identifier    string
		architectures []string
	}{
		{path: "winget/stable/Pinksaucepasta.Paperboat.yaml", identifier: "Pinksaucepasta.Paperboat"},
		{path: "winget/stable/Pinksaucepasta.Paperboat.locale.en-US.yaml", identifier: "Pinksaucepasta.Paperboat"},
		{path: "winget/stable/Pinksaucepasta.Paperboat.installer.yaml", identifier: "Pinksaucepasta.Paperboat", architectures: []string{"x64"}},
		{path: "winget/beta/Pinksaucepasta.Paperboat.Beta.yaml", identifier: "Pinksaucepasta.Paperboat.Beta"},
		{path: "winget/beta/Pinksaucepasta.Paperboat.Beta.locale.en-US.yaml", identifier: "Pinksaucepasta.Paperboat.Beta"},
		{path: "winget/beta/Pinksaucepasta.Paperboat.Beta.installer.yaml", identifier: "Pinksaucepasta.Paperboat.Beta", architectures: []string{"x64", "arm64"}},
	}
	for _, template := range templates {
		data, err := read(root, template.path)
		if err != nil {
			return err
		}
		text := string(data)
		if !strings.Contains(text, "PackageIdentifier: "+template.identifier) || !versionPlaceholder.Match(data) || !strings.Contains(text, "ManifestVersion: 1.6.0") {
			return fmt.Errorf("%s is missing its identifier, version placeholder, or manifest version", template.path)
		}
		if strings.Contains(text, "InstallerType: msi") && (!strings.Contains(text, "InstallerSha256: \"{{") || !strings.Contains(text, "InstallerUrl: \"{{")) {
			return fmt.Errorf("%s must keep URL and SHA-256 as release placeholders", template.path)
		}
		for _, architecture := range template.architectures {
			if !strings.Contains(text, "Architecture: "+architecture) {
				return fmt.Errorf("%s is missing architecture %s", template.path, architecture)
			}
		}
		if template.path == "winget/stable/Pinksaucepasta.Paperboat.installer.yaml" && strings.Contains(text, "Architecture: arm64") {
			return fmt.Errorf("stable WinGet template cannot expose arm64")
		}
	}
	return nil
}

func validateAssets(root string, policy metadata) error {
	manifestData, err := read(root, "resources/paperboat.manifest")
	if err != nil {
		return err
	}
	if err := windowsmanifest.ValidateManifest(manifestData); err != nil {
		return fmt.Errorf("Windows long-path manifest: %w", err)
	}
	if _, err := read(root, "resources/paperboat.rc"); err != nil {
		return err
	}
	repositoryRoot := filepath.Clean(filepath.Join(root, "..", ".."))
	for _, packageDirectory := range []string{"cmd/pb", "cmd/pb-launcher"} {
		for _, architecture := range []string{"amd64", "arm64"} {
			path := filepath.Join(repositoryRoot, packageDirectory, "windows_manifest_windows_"+architecture+".syso")
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("Windows %s manifest resource: %w", architecture, err)
			}
			if !info.Mode().IsRegular() || info.Size() == 0 {
				return fmt.Errorf("Windows %s manifest resource is empty: %s", architecture, path)
			}
		}
	}
	data, err := read(root, "wix/assets/openssh-provisioning.json")
	if err != nil {
		return err
	}
	var asset map[string]any
	if err := json.Unmarshal(data, &asset); err != nil {
		return fmt.Errorf("OpenSSH hook is not valid JSON: %w", err)
	}
	for key, want := range map[string]string{
		"schema":                  "paperboat.windows.openssh-packaging-hook/v1",
		"package_id":              policy.OpenSSH.PackageID,
		"approved_version":        policy.OpenSSH.ApprovedVersion,
		"installer":               "winget",
		"service":                 "PaperboatSshd",
		"capability_installation": "never",
		"existing_system_sshd":    "preserve",
	} {
		if asset[key] != want {
			return fmt.Errorf("OpenSSH hook field %s is %v, want %s", key, asset[key], want)
		}
	}
	return nil
}

func validateSourceHygiene(root string) error {
	var paths []string
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		paths = append(paths, path)
		return nil
	}); err != nil {
		return fmt.Errorf("walk packaging files: %w", err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		relativePath, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("relativize %s: %w", path, err)
		}
		// The validator contains the detection patterns as executable source;
		// scanning those literals would make the hygiene check self-fail.
		if strings.HasPrefix(filepath.ToSlash(relativePath), "cmd/validate/") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if secretPattern.Match(data) || bytesContain(data, []byte("-----BEGIN")) || bytesContain(data, []byte("1905")) {
			return fmt.Errorf("possible secret material in %s", path)
		}
	}
	return nil
}

func read(root, relative string) ([]byte, error) {
	path := filepath.Join(root, filepath.FromSlash(relative))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", relative, err)
	}
	return data, nil
}

func bytesContain(data, needle []byte) bool {
	return strings.Contains(string(data), string(needle))
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func sameComponents(got, want []component) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func sameServices(got, want []service) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func sameTargets(got, want []target) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
