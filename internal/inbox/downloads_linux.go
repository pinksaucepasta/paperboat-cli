package inbox

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func DownloadsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		configHome = filepath.Join(home, ".config")
	}
	file, err := os.Open(filepath.Join(configHome, "user-dirs.dirs"))
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			key, value, ok := strings.Cut(scanner.Text(), "=")
			if strings.TrimSpace(key) != "XDG_DOWNLOAD_DIR" || !ok {
				continue
			}
			decoded, decodeErr := strconv.Unquote(strings.TrimSpace(value))
			if decodeErr == nil {
				decoded = strings.ReplaceAll(decoded, "$HOME", home)
				if filepath.IsAbs(decoded) {
					return filepath.Clean(decoded), nil
				}
			}
		}
	}
	return filepath.Join(home, "Downloads"), nil
}
