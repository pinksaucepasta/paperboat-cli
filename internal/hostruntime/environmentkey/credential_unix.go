//go:build darwin || linux

package environmentkey

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SystemdCredentialSource reads the fixed credential supplied by systemd.
// The runtime never accepts a caller-selected path or a raw-file fallback.
type SystemdCredentialSource struct {
	Generation uint64
	MachineID  string
}

func (s SystemdCredentialSource) Load(context.Context) (Material, error) {
	if s.Generation == 0 || !validIdentity(s.MachineID) {
		return Material{}, ErrInvalid
	}
	directory := os.Getenv("CREDENTIALS_DIRECTORY")
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || strings.ContainsAny(directory, "\x00\r\n") {
		return Material{}, ErrUnavailable
	}
	path := filepath.Join(directory, CredentialName)
	file, err := os.Open(path)
	if err != nil {
		return Material{}, errors.Join(ErrUnavailable, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 4096 {
		return Material{}, ErrInvalid
	}
	body, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(body) > 4096 {
		clear(body)
		return Material{}, errors.Join(ErrInvalid, err)
	}
	record, private, err := parseCredentialRecord(body)
	clear(body)
	if err != nil || record.MachineID != s.MachineID || record.Generation != s.Generation {
		clear(private)
		return Material{}, ErrInvalid
	}
	result := Material{Generation: record.Generation}
	copy(result.Private[:], private)
	clear(private)
	if _, err := result.Public(); err != nil {
		result.Destroy()
		return Material{}, err
	}
	return result, nil
}
