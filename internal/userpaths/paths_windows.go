package userpaths

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var ErrInvalid = errors.New("canonical user path is invalid")

func Config(name string) (string, error) {
	return below(windowsBase("XDG_CONFIG_HOME", "LOCALAPPDATA", ""), name)
}
func Cache(name string) (string, error) {
	return below(windowsBase("XDG_CACHE_HOME", "LOCALAPPDATA", "cache"), name)
}
func Data(name string) (string, error) {
	return below(windowsBase("XDG_DATA_HOME", "LOCALAPPDATA", ""), name)
}
func State(name string) (string, error) {
	return below(windowsBase("XDG_STATE_HOME", "LOCALAPPDATA", ""), name)
}
func Runtime(name string) (string, error) {
	return below(windowsBase("XDG_RUNTIME_DIR", "LOCALAPPDATA", ""), name)
}

func Downloads() (string, error) {
	if value := os.Getenv("XDG_DOWNLOAD_DIR"); value != "" {
		return canonical(value)
	}
	home, err := Home()
	if err != nil {
		return "", err
	}
	return canonical(filepath.Join(home, "Downloads"))
}

func Home() (string, error) { return canonical(os.Getenv("USERPROFILE")) }

func windowsBase(override, fallback, suffix string) string {
	if value := os.Getenv(override); value != "" {
		return value
	}
	base := os.Getenv(fallback)
	if suffix != "" {
		base = filepath.Join(base, suffix)
	}
	return base
}

func below(base, name string) (string, error) {
	name = filepath.FromSlash(name)
	if name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name || name == "." || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
		return "", ErrInvalid
	}
	base, err := canonical(base)
	if err != nil {
		return "", err
	}
	path := filepath.Join(base, name)
	if path == base {
		return "", ErrInvalid
	}
	return path, nil
}

func canonical(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ErrInvalid
	}
	return path, nil
}
