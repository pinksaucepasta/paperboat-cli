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
	// Connect tunes the pre-connect broker + readiness polling.
	Connect ConnectConfig `json:"connect,omitempty"`
	// SSH configures the agentunnel SSH transport.
	SSH SSHConfig `json:"ssh,omitempty"`

	// path is where this config was loaded from (or would be written to).
	path string `json:"-"`
}

// ConnectConfig tunes how the CLI waits for an idle machine to resume and its
// agentunnel tunnel to come up after cli-connect. Both are data-driven so the
// wait behavior can change without a rebuild.
type ConnectConfig struct {
	// ReadyTimeoutSeconds caps how long to poll for the tunnel to become
	// connectable before giving up. Defaults to DefaultReadyTimeoutSeconds.
	ReadyTimeoutSeconds int `json:"ready_timeout_seconds,omitempty"`
	// PollIntervalSeconds is the gap between readiness polls. Defaults to
	// DefaultPollIntervalSeconds.
	PollIntervalSeconds int `json:"poll_interval_seconds,omitempty"`
}

// SSHConfig configures the client side of the agentunnel SSH transport. The CLI
// authenticates with the user's existing local SSH credentials (agent + key
// files) exactly like `ssh paperboat@host` — paperboat-server never hands out
// keys. Everything here is optional; sane SSH defaults apply when unset.
type SSHConfig struct {
	// IdentityFile is an explicit private key path to offer. Empty means use the
	// SSH agent and the user's default keys.
	IdentityFile string `json:"identity_file,omitempty"`
	// KnownHostsFile overrides the host-key database. Empty uses
	// ~/.ssh/known_hosts.
	KnownHostsFile string `json:"known_hosts_file,omitempty"`
	// InsecureSkipHostKeyCheck disables host-key verification. Off by default;
	// only for local/dev tunnels where the host key is not yet pinned.
	InsecureSkipHostKeyCheck bool `json:"insecure_skip_host_key_check,omitempty"`
}

// Connect polling defaults. Chosen to cover a cold Fly machine resume without
// hanging indefinitely; overridable per install.
const (
	DefaultReadyTimeoutSeconds = 180
	DefaultPollIntervalSeconds = 3
)

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
	if c.Connect.ReadyTimeoutSeconds == 0 {
		c.Connect.ReadyTimeoutSeconds = DefaultReadyTimeoutSeconds
	}
	if c.Connect.PollIntervalSeconds == 0 {
		c.Connect.PollIntervalSeconds = DefaultPollIntervalSeconds
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
