package bootstrap

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ReadEnrollmentTokenFile reads a one-time dashboard enrollment token without
// placing it in argv or environment. The caller removes it after the pairing
// request has been accepted by paperboat-server.
func ReadEnrollmentTokenFile(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ErrInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !secureEnrollmentTokenFile(path, info) {
		return "", ErrInvalid
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return "", ErrInvalid
	}
	defer clearBytes(body)
	token := strings.TrimSpace(string(body))
	if len(token) < 32 || len(token) > 256 || strings.ContainsAny(token, "\x00\r\n") {
		return "", ErrInvalid
	}
	return token, nil
}

func ConsumeEnrollmentTokenFile(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalid
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
