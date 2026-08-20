package windowsopenssh

import (
	_ "embed"
	"encoding/json"
	"slices"
	"strings"
)

//go:embed compatibility.json
var compatibilityJSON []byte

type Compatibility struct {
	Schema              string   `json:"schema"`
	PackageID           string   `json:"package_id"`
	ApprovedVersion     string   `json:"approved_version"`
	MinimumVersion      string   `json:"minimum_version"`
	MaximumVersion      string   `json:"maximum_version"`
	Architectures       []string `json:"architectures"`
	ExpectedPublisher   string   `json:"expected_publisher"`
	ExpectedBinaryNames []string `json:"expected_binary_names"`
	ExpectedInstallRoot string   `json:"expected_install_root"`
	TestedWindowsBuilds []string `json:"tested_windows_builds"`
	ConfigurationSchema string   `json:"configuration_schema"`
}

var compatibility = mustCompatibility()

var (
	PackageID       = compatibility.PackageID
	ApprovedVersion = compatibility.ApprovedVersion
	ConfigSchema    = compatibility.ConfigurationSchema
)

func CompatibilityMetadata() Compatibility {
	result := compatibility
	result.Architectures = slices.Clone(result.Architectures)
	result.ExpectedBinaryNames = slices.Clone(result.ExpectedBinaryNames)
	result.TestedWindowsBuilds = slices.Clone(result.TestedWindowsBuilds)
	return result
}

func mustCompatibility() Compatibility {
	var value Compatibility
	if json.Unmarshal(compatibilityJSON, &value) != nil || value.Schema == "" || value.PackageID != "Microsoft.OpenSSH.Preview" || value.ApprovedVersion == "" || value.MinimumVersion == "" || value.MaximumVersion == "" || value.ApprovedVersion != value.MinimumVersion || value.ApprovedVersion != value.MaximumVersion || value.ExpectedPublisher == "" || value.ConfigurationSchema != value.Schema || !slices.Contains(value.Architectures, "amd64") || !slices.Contains(value.Architectures, "arm64") || len(value.ExpectedBinaryNames) == 0 || strings.TrimSpace(value.ExpectedInstallRoot) == "" || len(value.TestedWindowsBuilds) == 0 {
		panic("invalid embedded Windows OpenSSH compatibility metadata")
	}
	return value
}
