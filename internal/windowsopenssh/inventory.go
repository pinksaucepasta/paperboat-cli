package windowsopenssh

import (
	"context"
	"path/filepath"
	"strings"
)

// InstallationClass is the disposition of SSH state found before Paperboat acts.
// Inventory is read-only; no classification authorizes changes to the system sshd service.
type InstallationClass string

const (
	InstallationMissing           InstallationClass = "missing"
	InstallationPaperboatApproved InstallationClass = "paperboat_approved_winget"
	InstallationWindowsCapability InstallationClass = "windows_capability"
	InstallationDifferentWinget   InstallationClass = "different_winget_version"
	InstallationThirdParty        InstallationClass = "third_party"
	InstallationUntrusted         InstallationClass = "untrusted"
	InstallationConflicting       InstallationClass = "conflicting"
)

type BinaryRecord struct {
	Path           string `json:"path"`
	Exists         bool   `json:"exists"`
	Regular        bool   `json:"regular"`
	ReparsePoint   bool   `json:"reparse_point"`
	SignatureValid bool   `json:"signature_valid"`
	Publisher      string `json:"publisher"`
	Version        string `json:"version"`
	Architecture   string `json:"architecture"`
}

type ServiceRecord struct {
	Name      string `json:"name"`
	Exists    bool   `json:"exists"`
	State     string `json:"state"`
	ProcessID uint32 `json:"process_id"`
	PathName  string `json:"path_name"`
}

type InventoryRecord struct {
	WingetRegistered  bool          `json:"winget_registered"`
	WingetVersion     string        `json:"winget_version"`
	CapabilityPresent bool          `json:"capability_present"`
	SystemSSHD        BinaryRecord  `json:"system_sshd"`
	ProgramFilesSSHD  BinaryRecord  `json:"program_files_sshd"`
	SystemService     ServiceRecord `json:"system_service"`
	PaperboatService  ServiceRecord `json:"paperboat_service"`
}

type InstallationInventory struct {
	Class             InstallationClass `json:"class"`
	Record            InventoryRecord   `json:"record"`
	SystemSSHDManaged bool              `json:"system_sshd_managed"`
}

// Inventory reports installed OpenSSH state without changing services, firewall rules,
// binaries, keys, or configuration.
func Inventory(ctx context.Context, config Config) (InstallationInventory, error) {
	if err := validate(config); err != nil {
		return InstallationInventory{}, err
	}
	if config.Platform != "windows" {
		return InstallationInventory{}, ErrInstallerUnavailable
	}
	record, err := collectInventory(ctx, config)
	if err != nil {
		return InstallationInventory{}, err
	}
	return ClassifyInventory(record, config), nil
}

func ClassifyInventory(record InventoryRecord, config Config) InstallationInventory {
	result := InstallationInventory{Record: record, SystemSSHDManaged: record.SystemService.Exists}
	if paperboatServiceConflicts(record.PaperboatService, config) {
		result.Class = InstallationConflicting
		return result
	}
	program := record.ProgramFilesSSHD
	if program.Exists {
		if !trustedBinary(program, config) {
			result.Class = InstallationUntrusted
			return result
		}
		if record.WingetRegistered {
			if versionMatches(record.WingetVersion, config.ApprovedVersion) && versionMatches(program.Version, config.ApprovedVersion) {
				result.Class = InstallationPaperboatApproved
			} else {
				result.Class = InstallationDifferentWinget
			}
			return result
		}
		result.Class = InstallationThirdParty
		return result
	}
	if record.WingetRegistered {
		result.Class = InstallationConflicting
		return result
	}
	if record.CapabilityPresent || record.SystemSSHD.Exists {
		result.Class = InstallationWindowsCapability
		return result
	}
	result.Class = InstallationMissing
	return result
}

func trustedBinary(record BinaryRecord, config Config) bool {
	architectureOK := config.Architecture == "" || record.Architecture == config.Architecture
	return record.Exists && record.Regular && !record.ReparsePoint && record.SignatureValid && architectureOK &&
		strings.Contains(strings.ToLower(record.Publisher), strings.ToLower(config.ExpectedPublisher)) &&
		filepath.IsAbs(record.Path)
}

func versionMatches(found, expected string) bool {
	found = strings.TrimSpace(found)
	expected = strings.TrimSpace(expected)
	return found != "" && expected != "" && (found == expected || strings.HasPrefix(found, expected+"."))
}

func paperboatServiceConflicts(service ServiceRecord, config Config) bool {
	if !service.Exists {
		return false
	}
	expected := strings.ToLower(filepath.Clean(filepath.Join(config.InstallRoot, "sshd.exe")))
	command := strings.ToLower(service.PathName)
	configPath := strings.ToLower(filepath.Clean(filepath.Join(config.StateRoot, "sshd_config")))
	legacy := strings.Contains(command, " -d -f ")
	wrapper := strings.Contains(command, " __windows-sshd-service ") && strings.Contains(command, " --sshd ") && strings.Contains(command, " --config ")
	return !strings.Contains(command, expected) || !strings.Contains(command, configPath) || (!legacy && !wrapper)
}
