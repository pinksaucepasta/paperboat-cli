// Package config loads the paperboat-cli local configuration and reuses the
// user's existing papercode credentials. Everything that could reasonably
// change is data-driven here — nothing about endpoints, limits, agents, or
// machine sizes is hardcoded in command logic. See AGENTS.md ("No hardcoding").
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// EnvConfigPath overrides the config file location when set.
const EnvConfigPath = "PAPERBOAT_CONFIG"

// UploadConfig controls the local image-paste bridge. All fields are tunable so
// behavior can change without rebuilding the binary.
type UploadConfig struct {
	// Endpoint is the papercode-server upload endpoint (on the VM, reached
	// through agentunnel). Empty means the local dev stub is used.
	Endpoint string `json:"endpoint,omitempty"`
	// WatchDirs are directories terminals write temp images into on paste.
	// Absolute paths, or "~"-prefixed for the home dir.
	WatchDirs []string `json:"watch_dirs,omitempty"`
	// MaxImageBytes caps a single image. Defaults to 10 MiB (papercode limit).
	MaxImageBytes int64 `json:"max_image_bytes,omitempty"`
	// MaxDataURLChars caps the encoded data URL length (papercode limit).
	MaxDataURLChars int `json:"max_data_url_chars,omitempty"`
	// MaxAttachments caps images per paste (papercode limit).
	MaxAttachments int `json:"max_attachments,omitempty"`
	// AllowedMimePrefixes gates which files are treated as images.
	AllowedMimePrefixes []string `json:"allowed_mime_prefixes,omitempty"`
}

// Defaults mirror papercode's UploadChatImageAttachment limits in
// packages/contracts/src/orchestration.ts. They are applied only when a field
// is left unset, so a config file can always override them.
const (
	DefaultMaxImageBytes   = 10 * 1024 * 1024
	DefaultMaxDataURLChars = 14_000_000
	DefaultMaxAttachments  = 8
)

// Config is the on-disk CLI configuration.
type Config struct {
	// ServerURL is the paperboat-server base URL. Empty means local dev stub.
	ServerURL string `json:"server_url,omitempty"`
	// PapercodeConfigPath points at papercode's stored credentials to reuse.
	// Empty means "use the platform default location".
	PapercodeConfigPath string `json:"papercode_config_path,omitempty"`
	// DefaultAgent / DefaultSize are used when the user does not pass a flag.
	// Empty means "whatever the project has configured server-side".
	DefaultAgent string `json:"default_agent,omitempty"`
	DefaultSize  string `json:"default_size,omitempty"`
	// Upload configures the image-paste bridge.
	Upload UploadConfig `json:"upload,omitempty"`

	// path is where this config was loaded from (or would be written to).
	path string `json:"-"`
}

// Path returns the resolved config file location.
func (c *Config) Path() string { return c.path }

// DefaultPath resolves the config path from the env override or the user's
// config dir (~/.config/paperboat/config.json on Unix).
func DefaultPath() (string, error) {
	if p := os.Getenv(EnvConfigPath); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "paperboat", "config.json"), nil
}

// Load reads the config at path (or DefaultPath when path is empty). A missing
// file is not an error — a zero-value config with defaults is returned so the
// CLI works out of the box.
func Load(path string) (*Config, error) {
	if path == "" {
		p, err := DefaultPath()
		if err != nil {
			return nil, err
		}
		path = p
	}

	cfg := &Config{path: path}
	data, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		// No file yet: fall through with defaults applied below.
	case err != nil:
		return nil, fmt.Errorf("read config %s: %w", path, err)
	default:
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
		cfg.path = path
	}

	cfg.applyDefaults()
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Upload.MaxImageBytes == 0 {
		c.Upload.MaxImageBytes = DefaultMaxImageBytes
	}
	if c.Upload.MaxDataURLChars == 0 {
		c.Upload.MaxDataURLChars = DefaultMaxDataURLChars
	}
	if c.Upload.MaxAttachments == 0 {
		c.Upload.MaxAttachments = DefaultMaxAttachments
	}
	if len(c.Upload.AllowedMimePrefixes) == 0 {
		c.Upload.AllowedMimePrefixes = []string{"image/"}
	}
}

// Save writes the config to its path, creating parent dirs as needed.
func (c *Config) Save() error {
	if c.path == "" {
		p, err := DefaultPath()
		if err != nil {
			return err
		}
		c.path = p
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(c.path, data, 0o600); err != nil {
		return fmt.Errorf("write config %s: %w", c.path, err)
	}
	return nil
}
