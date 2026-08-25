//go:build windows

// Package windowsenvironment owns the small amount of process-environment
// integration required by the machine-wide Paperboat installation.
package windowsenvironment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	machineEnvironmentKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
	pathValueName         = "Path"
	maxWindowsEnvironment = 32767
)

// EnsureMachinePath registers directory in the machine PATH. The installer is
// elevated when this is called, so the registration is available to every
// subsequently created console, service, and OpenSSH session. Existing PATH
// bytes and the registry value type are preserved.
func EnsureMachinePath(directory string) error {
	directory, err := validateDirectory(directory)
	if err != nil {
		return err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, machineEnvironmentKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open machine environment: %w", err)
	}
	defer key.Close()
	current, valueType, err := readPathValue(key)
	if err != nil {
		return err
	}
	updated, changed := appendPathEntry(current, directory)
	if !changed {
		return nil
	}
	if len(updated) > maxWindowsEnvironment {
		return errors.New("machine PATH exceeds Windows environment size limit")
	}
	if err := setPathValue(key, valueType, updated); err != nil {
		return fmt.Errorf("write machine environment: %w", err)
	}
	return nil
}

// RemoveMachinePath removes every exact Paperboat entry from the machine PATH
// while leaving all unrelated entries and the original registry type intact.
// It is used by the privileged uninstall path so uninstall does not leave a
// stale command location behind.
func RemoveMachinePath(directory string) error {
	directory, err := validateDirectory(directory)
	if err != nil {
		return err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, machineEnvironmentKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open machine environment: %w", err)
	}
	defer key.Close()
	current, valueType, err := readPathValue(key)
	if err != nil {
		return err
	}
	updated, changed := removePathEntry(current, directory)
	if !changed {
		return nil
	}
	if err := setPathValue(key, valueType, updated); err != nil {
		return fmt.Errorf("write machine environment: %w", err)
	}
	return nil
}

// WithCommandDirectory returns an environment suitable for a child process
// launched by Paperboat's Windows service. services.exe can retain the
// pre-install environment until reboot; explicitly carrying the installed
// command directory into the sshd child makes the same installation contract
// hold immediately after install and after an in-place upgrade.
func WithCommandDirectory(environment []string, directory string) []string {
	directory, err := validateDirectory(directory)
	if err != nil {
		return append([]string(nil), environment...)
	}
	result := append([]string(nil), environment...)
	for index, item := range result {
		key, value, ok := strings.Cut(item, "=")
		if !ok || !strings.EqualFold(key, pathValueName) {
			continue
		}
		updated, _ := appendPathEntry(value, directory)
		result[index] = key + "=" + updated
		return result
	}
	return append(result, pathValueName+"="+directory)
}

func validateDirectory(directory string) (string, error) {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || strings.ContainsAny(directory, "\x00\r\n;") {
		return "", errors.New("invalid Windows command directory")
	}
	return directory, nil
}

func readPathValue(key registry.Key) (string, uint32, error) {
	value, valueType, err := key.GetStringValue(pathValueName)
	if errors.Is(err, registry.ErrNotExist) {
		return "", registry.SZ, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("read machine PATH: %w", err)
	}
	return value, valueType, nil
}

func setPathValue(key registry.Key, valueType uint32, value string) error {
	switch valueType {
	case registry.EXPAND_SZ:
		return key.SetExpandStringValue(pathValueName, value)
	case registry.SZ:
		return key.SetStringValue(pathValueName, value)
	default:
		return fmt.Errorf("machine PATH has unsupported registry type %d", valueType)
	}
}

func appendPathEntry(value, directory string) (string, bool) {
	for _, entry := range strings.Split(value, ";") {
		if samePathEntry(entry, directory) {
			return value, false
		}
	}
	if value == "" || strings.HasSuffix(value, ";") {
		return value + directory, true
	}
	return value + ";" + directory, true
}

func removePathEntry(value, directory string) (string, bool) {
	entries := strings.Split(value, ";")
	filtered := entries[:0]
	changed := false
	for _, entry := range entries {
		if samePathEntry(entry, directory) {
			changed = true
			continue
		}
		filtered = append(filtered, entry)
	}
	if !changed {
		return value, false
	}
	return strings.Join(filtered, ";"), true
}

func samePathEntry(first, second string) bool {
	first = strings.TrimSpace(strings.Trim(first, `"`))
	second = strings.TrimSpace(strings.Trim(second, `"`))
	if first == "" || second == "" {
		return false
	}
	return strings.EqualFold(filepath.Clean(first), filepath.Clean(second))
}

// Environment returns the current process environment with directory added to
// PATH. It is intentionally small and testable; callers that need registry
// persistence should use EnsureMachinePath instead.
func Environment(directory string) []string {
	return WithCommandDirectory(os.Environ(), directory)
}
