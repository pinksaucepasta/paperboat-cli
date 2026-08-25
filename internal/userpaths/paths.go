//go:build !windows

package userpaths

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/adrg/xdg"
)

var ErrInvalid = errors.New("canonical user path is invalid")

func Config(name string) (string, error)  { return below(xdg.ConfigHome, name) }
func Cache(name string) (string, error)   { return below(xdg.CacheHome, name) }
func Data(name string) (string, error)    { return below(xdg.DataHome, name) }
func State(name string) (string, error)   { return below(xdg.StateHome, name) }
func Runtime(name string) (string, error) { return below(xdg.RuntimeDir, name) }
func Downloads() (string, error)          { return canonical(xdg.UserDirs.Download) }
func Home() (string, error)               { return canonical(xdg.Home) }

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
