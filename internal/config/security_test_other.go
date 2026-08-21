//go:build !windows

package config

import (
	"io/fs"
	"os"
	"strings"
)

func credentialPermissionError(err error) bool { return strings.Contains(err.Error(), "0600") }

func configTestFilePrivate(_ string, info fs.FileInfo) bool {
	return info != nil && info.Mode().Perm() == 0o600
}

func configTestPathsEqual(body, want string) bool {
	return strings.Contains(body, want)
}

func writeTestCredential(path, value string) error {
	return os.WriteFile(path, []byte(value), 0o644)
}
