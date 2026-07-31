package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type MachineControl struct {
	Version                int       `json:"version"`
	MachineID              string    `json:"machine_id"`
	EnvironmentID          string    `json:"environment_id"`
	InstallationGeneration int64     `json:"installation_generation"`
	Credential             string    `json:"credential"`
	ExpiresAt              time.Time `json:"expires_at"`
	KeyID                  string    `json:"key_id"`
}

func (s *Store) SaveMachineControl(value MachineControl) error {
	registration, err := s.Registration()
	if err != nil || value.MachineID != registration.MachineID || value.EnvironmentID != registration.EnvironmentID || value.InstallationGeneration != registration.InstallationGeneration || value.KeyID != s.key.ID || len(value.Credential) < 32 || value.ExpiresAt.IsZero() {
		return ErrInvalidStore
	}
	value.Version = 1
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.writePrivateDocument("machine-control.json", ".machine-control-*", encoded)
}

func (s *Store) MachineControl(now time.Time, expiryGrace time.Duration) (MachineControl, error) {
	path := filepath.Join(s.config.StateRoot, "machine-control.json")
	info, err := os.Lstat(path)
	if err != nil || !secureIdentityFile(info, true) || info.Size() > 32<<10 {
		return MachineControl{}, ErrInvalidStore
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return MachineControl{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var value MachineControl
	if err := decoder.Decode(&value); err != nil {
		return MachineControl{}, ErrInvalidStore
	}
	var extra any
	registration, registrationErr := s.Registration()
	if decoder.Decode(&extra) != io.EOF || registrationErr != nil || value.Version != 1 || value.KeyID != s.key.ID || value.MachineID != registration.MachineID || value.EnvironmentID != registration.EnvironmentID || value.InstallationGeneration != registration.InstallationGeneration || len(value.Credential) < 32 || value.ExpiresAt.Add(expiryGrace).Before(now.UTC()) {
		return MachineControl{}, ErrInvalidStore
	}
	return value, nil
}

func (s *Store) MachineProof(operationID, method, path string, body []byte, now time.Time) ([]byte, error) {
	registration, err := s.Registration()
	if err != nil || len(operationID) < 8 || len(operationID) > 128 || strings.ToUpper(method) != http.MethodPost || !strings.HasPrefix(path, "/v1/") || len(body) > 1<<20 {
		return nil, ErrInvalidStore
	}
	now = now.UTC()
	bodyHash := sha256.Sum256(body)
	payload, err := json.Marshal(struct {
		MachineID              string    `json:"machine_id"`
		EnvironmentID          string    `json:"environment_id"`
		InstallationGeneration int64     `json:"installation_generation"`
		OperationID            string    `json:"operation_id"`
		Method                 string    `json:"method"`
		Path                   string    `json:"path"`
		BodySHA256             string    `json:"body_sha256"`
		IssuedAt               time.Time `json:"issued_at"`
		ExpiresAt              time.Time `json:"expires_at"`
	}{registration.MachineID, registration.EnvironmentID, registration.InstallationGeneration, operationID, http.MethodPost, path, base64.RawURLEncoding.EncodeToString(bodyHash[:]), now, now.Add(time.Minute)})
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Algorithm string `json:"alg"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}{"EdDSA", base64.RawURLEncoding.EncodeToString(payload), base64.RawURLEncoding.EncodeToString(s.key.Sign(payload))})
}

func (s *Store) writePrivateDocument(name, pattern string, encoded []byte) error {
	path := filepath.Join(s.config.StateRoot, name)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalidStore
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(s.config.StateRoot, pattern)
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
