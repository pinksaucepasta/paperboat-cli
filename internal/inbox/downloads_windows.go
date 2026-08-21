//go:build windows

package inbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func DownloadsDir() (string, error) {
	path, err := windows.KnownFolderPath(windows.FOLDERID_Downloads, windows.KF_FLAG_DEFAULT)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		home, homeErr := os.UserHomeDir()
		fallback := filepath.Join(home, "Downloads")
		if homeErr == nil && filepath.IsAbs(fallback) && filepath.Clean(fallback) == fallback {
			return fallback, nil
		}
		if err == nil {
			err = errors.New("Windows Downloads known folder is invalid")
		}
		return "", err
	}
	return path, nil
}
