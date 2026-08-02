package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Registration struct {
	Version                int       `json:"version"`
	ServerURL              string    `json:"server_url"`
	MachineID              string    `json:"machine_id"`
	EnvironmentID          string    `json:"environment_id"`
	PublicKeyID            string    `json:"public_key_id"`
	PublicIdentityKey      string    `json:"public_identity_key"`
	InboxPath              string    `json:"inbox_path"`
	InstallationGeneration int64     `json:"installation_generation"`
	SetupMode              string    `json:"setup_mode"`
	SetupRoles             []string  `json:"setup_roles"`
	UpdatedAt              time.Time `json:"updated_at"`
}

func (s *Store) SaveRegistration(value Registration) error {
	if value.SetupMode == "" {
		value.SetupMode = setupModeFromRoles(value.SetupRoles)
	}
	if strings.TrimSpace(value.ServerURL) == "" || strings.TrimSpace(value.MachineID) == "" ||
		strings.TrimSpace(value.EnvironmentID) == "" || value.PublicKeyID != s.key.ID ||
		strings.TrimSpace(value.PublicIdentityKey) == "" || !filepath.IsAbs(value.InboxPath) || value.InstallationGeneration < 1 ||
		!validSetupMode(value.SetupMode) || value.UpdatedAt.IsZero() {
		return ErrInvalidStore
	}
	value.Version = 1
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	path := filepath.Join(s.config.StateRoot, "machine-registration.json")
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalidStore
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(s.config.StateRoot, ".machine-registration-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(s.config.StateRoot)
}

func validSetupMode(mode string) bool {
	return mode == "receive" || mode == "session" || mode == "host"
}

func setupModeFromRoles(roles []string) string {
	for _, role := range roles {
		if role == "host" {
			return "host"
		}
	}
	return "session"
}

func (s *Store) Registration() (Registration, error) {
	path := filepath.Join(s.config.StateRoot, "machine-registration.json")
	info, err := os.Lstat(path)
	if err != nil {
		return Registration{}, err
	}
	if !secureIdentityFile(info, true) {
		return Registration{}, ErrInvalidStore
	}
	encoded, err := os.ReadFile(path)
	if err != nil || len(encoded) > 8192 {
		return Registration{}, ErrInvalidStore
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var value Registration
	if err := decoder.Decode(&value); err != nil {
		return Registration{}, ErrInvalidStore
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF || value.Version != 1 ||
		value.PublicKeyID != s.key.ID || strings.TrimSpace(value.MachineID) == "" ||
		strings.TrimSpace(value.ServerURL) == "" || !filepath.IsAbs(value.InboxPath) || value.InstallationGeneration < 1 {
		return Registration{}, ErrInvalidStore
	}
	if value.SetupMode == "" {
		value.SetupMode = setupModeFromRoles(value.SetupRoles)
	}
	if !validSetupMode(value.SetupMode) {
		return Registration{}, ErrInvalidStore
	}
	return value, nil
}
