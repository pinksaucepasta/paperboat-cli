package inbox

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func DownloadsDir() (string, error) {
	path, err := windows.KnownFolderPath(windows.FOLDERID_Downloads, windows.KF_FLAG_DEFAULT)
	if err == nil && filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	home, homeErr := os.UserHomeDir()
	if homeErr != nil {
		return "", homeErr
	}
	return filepath.Join(home, "Downloads"), nil
}
