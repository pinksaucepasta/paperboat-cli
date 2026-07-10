package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNoCredentials is the transitional missing-papercode-token error. Phase 3
// replaces this source with the Paperboat credential-store profile.
var ErrNoCredentials = errors.New("no papercode credentials found")

// Credential is the transitional read-only papercode auth view retained until
// the Phase 3 Paperboat credential-store implementation replaces it.
type Credential struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type,omitempty"`
	UserID      string `json:"user_id,omitempty"`
}

// AuthSource yields the current reusable credential.
type AuthSource interface {
	Credential() (Credential, error)
}

// papercodeAuthFile mirrors the subset of papercode's stored auth we read. The
// exact papercode format is owned by that repo; when it firms up, only this
// mapping changes — the AuthSource contract stays stable.
type papercodeAuthFile struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	UserID      string `json:"user_id"`
}

// FileAuthSource reads papercode credentials from a JSON file. Path is
// config-driven; DefaultPapercodeAuthPath is used when unset.
type FileAuthSource struct {
	Path string
}

// DefaultPapercodeAuthPath returns the platform default location of papercode's
// credential file (~/.config/papercode/auth.json on Unix).
func DefaultPapercodeAuthPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "papercode", "auth.json"), nil
}

// Credential implements AuthSource.
func (s FileAuthSource) Credential() (Credential, error) {
	path := s.Path
	if path == "" {
		p, err := DefaultPapercodeAuthPath()
		if err != nil {
			return Credential{}, err
		}
		path = p
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Credential{}, ErrNoCredentials
	}
	if err != nil {
		return Credential{}, fmt.Errorf("read papercode auth %s: %w", path, err)
	}

	var f papercodeAuthFile
	if err := json.Unmarshal(data, &f); err != nil {
		return Credential{}, fmt.Errorf("parse papercode auth %s: %w", path, err)
	}
	if f.AccessToken == "" {
		return Credential{}, ErrNoCredentials
	}
	return Credential{
		AccessToken: f.AccessToken,
		TokenType:   f.TokenType,
		UserID:      f.UserID,
	}, nil
}

// AuthSourceFor builds the AuthSource for a loaded Config, honoring the
// configured papercode path override.
func AuthSourceFor(cfg *Config) AuthSource {
	return FileAuthSource{Path: cfg.PapercodeConfigPath}
}
