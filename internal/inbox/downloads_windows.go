//go:build windows

package inbox

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func DownloadsDir() (string, error) {
	path, err := windows.KnownFolderPath(windows.FOLDERID_Downloads, windows.KF_FLAG_DEFAULT)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		if err == nil {
			err = errors.New("Windows Downloads known folder is invalid")
		}
		return "", err
	}
	return path, nil
}
