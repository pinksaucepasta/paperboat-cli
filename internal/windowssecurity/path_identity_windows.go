//go:build windows

package windowssecurity

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// HandlePathMatches reports whether handle refers to the existing filesystem
// object named by expected. Windows may return a long path for a handle opened
// through an 8.3 short path, so both sides are compared in canonical long DOS
// form. Any failure is treated as a mismatch.
func HandlePathMatches(handle windows.Handle, expected string) bool {
	actual, err := finalPathByHandle(handle)
	if err != nil {
		return false
	}
	want, err := canonicalExistingPath(expected)
	if err != nil {
		return false
	}
	return normalizeCanonicalPath(actual) == want
}

func finalPathByHandle(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 256)
	for {
		n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buffer)) {
			return windows.UTF16ToString(buffer[:n]), nil
		}
		if n == 0 || n >= 32768 {
			return "", errors.New("final path is too long")
		}
		buffer = make([]uint16, n+1)
	}
}

func canonicalExistingPath(path string) (string, error) {
	if path == "" || strings.ContainsRune(path, '\x00') || !filepath.IsAbs(path) {
		return "", errors.New("path is not absolute")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	pointer, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, 256)
	for {
		n, err := windows.GetLongPathName(pointer, &buffer[0], uint32(len(buffer)))
		if err != nil {
			return "", err
		}
		if n < uint32(len(buffer)) {
			return normalizeCanonicalPath(windows.UTF16ToString(buffer[:n])), nil
		}
		if n == 0 || n >= 32768 {
			return "", errors.New("canonical path is too long")
		}
		buffer = make([]uint16, n+1)
	}
}

func normalizeCanonicalPath(path string) string {
	path = filepath.Clean(path)
	if strings.HasPrefix(path, `\\?\UNC\`) {
		path = `\\` + strings.TrimPrefix(path, `\\?\UNC\`)
	} else if strings.HasPrefix(path, `\\?\`) {
		path = strings.TrimPrefix(path, `\\?\`)
	}
	path = strings.TrimRight(path, `\`)
	if len(path) == 2 && path[1] == ':' {
		path += `\`
	}
	return strings.ToLower(path)
}
