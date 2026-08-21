//go:build windows

package config

import (
	"io/fs"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func configTestFilePrivate(path string, _ fs.FileInfo) bool {
	return credentialFilePrivate(path)
}

func credentialPermissionError(err error) bool {
	return strings.Contains(err.Error(), "protected owner-only ACL")
}

func configTestPathsEqual(body, want string) bool {
	longWant := windowsTestLongPath(want)
	return strings.Contains(body, want) || strings.Contains(body, strings.ReplaceAll(longWant, `\`, `\\`))
}

func windowsTestLongPath(path string) string {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return path
	}
	buffer := make([]uint16, windows.MAX_PATH)
	for {
		n, err := windows.GetLongPathName(p, &buffer[0], uint32(len(buffer)))
		if err != nil || n == 0 {
			return path
		}
		if n < uint32(len(buffer)) {
			return windows.UTF16ToString(buffer[:n])
		}
		buffer = make([]uint16, n+1)
	}
}

func writeTestCredential(path, value string) error {
	plain := append([]byte{1}, []byte(value)...)
	protected, err := dpapiTransform(plain, true)
	clear(plain)
	if err != nil {
		return err
	}
	defer clear(protected)
	return os.WriteFile(path, protected, 0o644)
}
