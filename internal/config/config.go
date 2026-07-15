// Package config loads paperboat-cli configuration and credential profiles. Everything that could reasonably
// change is data-driven here — nothing about endpoints, limits, agents, or
// machine catalogs are hardcoded in command logic. See AGENTS.md ("No hardcoding").
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// EnvConfigPath overrides the config file location when set.
const EnvConfigPath = "PAPERBOAT_CONFIG"

// UploadConfig controls the local image-paste bridge. All fields are tunable so
// behavior can change without rebuilding the binary.
type UploadConfig struct {
	// Endpoint is the papercode-server upload endpoint (on the VM, reached
	// through agentunnel). Production uploads use the brokered descriptor.
	Endpoint string `json:"endpoint,omitempty"`
	// WatchDirs are directories terminals write temp images into on paste.
	// Absolute paths, or "~"-prefixed for the home dir.
	WatchDirs []string `json:"watch_dirs,omitempty"`
	// TempFilePatterns optionally restrict terminal-created image names. Patterns
	// use filepath glob syntax and may match a basename or normalized full path.
	TempFilePatterns []string `json:"temp_file_patterns,omitempty"`
	// MaxImageBytes caps a single image. Defaults to 10 MiB (papercode limit).
	MaxImageBytes int64 `json:"max_image_bytes,omitempty"`
	// MaxDataURLChars caps the encoded data URL length (papercode limit).
	MaxDataURLChars int `json:"max_data_url_chars,omitempty"`
	// MaxAttachments caps images per paste (papercode limit).
	MaxAttachments int `json:"max_attachments,omitempty"`
	// MaxQueuedInputBytes bounds local input held behind an image upload.
	MaxQueuedInputBytes int `json:"max_queued_input_bytes,omitempty"`
	// AllowedMimePrefixes gates which files are treated as images.
	AllowedMimePrefixes []string `json:"allowed_mime_prefixes,omitempty"`
}

// Defaults mirror papercode's UploadChatImageAttachment limits in
// packages/contracts/src/orchestration.ts. They are applied only when a field
// is left unset, so a config file can always override them.
const (
	DefaultMaxImageBytes       = 10 * 1024 * 1024
	DefaultMaxDataURLChars     = 14_000_000
	DefaultMaxAttachments      = 8
	DefaultMaxQueuedInputBytes = 1024 * 1024
)

// Config is the on-disk CLI configuration.
type Config struct {
	// ServerURL is the paperboat-server base URL. It is required for production commands.
	ServerURL string `json:"server_url,omitempty"`
	// PapercodeConfigPath is retained only to detect the obsolete auth setup.
	PapercodeConfigPath string     `json:"papercode_config_path,omitempty"`
	Auth                AuthConfig `json:"auth,omitempty"`
	// Upload configures the image-paste bridge.
	Upload UploadConfig `json:"upload,omitempty"`
	// Connect tunes the pre-connect broker + readiness polling.
	Connect ConnectConfig `json:"connect,omitempty"`
	// SSH configures the agentunnel SSH transport.
	SSH SSHConfig `json:"ssh,omitempty"`
	// Observability controls the local metadata-only event log.
	Observability ObservabilityConfig `json:"observability,omitempty"`

	// path is where this config was loaded from (or would be written to).
	path                  string `json:"-"`
	dialRetriesConfigured bool
}

type ObservabilityConfig struct {
	// EventLogPath overrides the default telemetry.jsonl next to config.json.
	EventLogPath string `json:"event_log_path,omitempty"`
	// DisableEventLog explicitly disables local metadata events.
	DisableEventLog bool `json:"disable_event_log,omitempty"`
	// MaxEventLogBytes bounds the local JSONL file before it is truncated.
	MaxEventLogBytes int64 `json:"max_event_log_bytes,omitempty"`
}

type AuthConfig struct {
	// AllowFileFallback opts into plaintext 0600 token files for headless systems.
	AllowFileFallback bool `json:"allow_file_fallback,omitempty"`
	// ProfileDir overrides the shared profile directory (primarily for managed/headless installs).
	ProfileDir string `json:"profile_dir,omitempty"`
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
	// AllowedRouteHosts restricts descriptor endpoint hosts. Empty preserves
	// server-authored routing while a managed install can pin its relay hosts.
	AllowedRouteHosts     []string `json:"allowed_route_hosts,omitempty"`
	DialRetries           int      `json:"dial_retries"`
	DialRetrySeconds      int      `json:"dial_retry_seconds,omitempty"`
	AcceptedTerminalKinds []string `json:"accepted_terminal_kinds,omitempty"`
	// TerminalOutputQueueChunks bounds buffered remote output events.
	TerminalOutputQueueChunks int `json:"terminal_output_queue_chunks,omitempty"`
	// TerminalOutputBatchMilliseconds coalesces animation bursts before local rendering.
	TerminalOutputBatchMilliseconds int `json:"terminal_output_batch_milliseconds,omitempty"`
	// TerminalOutputBufferBytes controls each local terminal output read.
	TerminalOutputBufferBytes int `json:"terminal_output_buffer_bytes,omitempty"`
	// ForwardTerminalEnv lists local environment variables forwarded to the
	// remote PTY on attach so it inherits the client terminal's capabilities
	// (color depth, terminal program, locale). Unset variables are skipped.
	// Defaults to DefaultForwardTerminalEnv.
	ForwardTerminalEnv []string `json:"forward_terminal_env,omitempty"`
	// InputPartialFlushMilliseconds bounds how long input bytes that could
	// begin a bracketed-paste start marker (e.g. a bare ESC keypress) are
	// withheld before being forwarded to the remote terminal. Negative
	// disables the flush.
	InputPartialFlushMilliseconds int `json:"input_partial_flush_milliseconds,omitempty"`
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

const (
	DefaultReadyTimeoutSeconds             = 180
	DefaultPollIntervalSeconds             = 3
	DefaultDialRetries                     = 6
	DefaultDialRetrySeconds                = 2
	DefaultTelemetryMaxBytes               = 5 * 1024 * 1024
	DefaultTerminalOutputQueueChunks       = 256
	DefaultTerminalOutputBatchMilliseconds = 1
	DefaultTerminalOutputBufferBytes       = 128 * 1024
	DefaultInputPartialFlushMilliseconds   = 25
)

// DefaultForwardTerminalEnv covers the variables TUIs use to pick color depth
// and rendering features (truecolor detection, terminal identity, locale).
var DefaultForwardTerminalEnv = []string{
	"TERM",
	"COLORTERM",
	"TERM_PROGRAM",
	"TERM_PROGRAM_VERSION",
	"LANG",
	"LC_ALL",
	"LC_CTYPE",
}

// Path returns the resolved config file location.
func (c *Config) Path() string { return c.path }

func (c *Config) TelemetryPath() string {
	if c.Observability.DisableEventLog {
		return ""
	}
	if c.Observability.EventLogPath != "" {
		if filepath.IsAbs(c.Observability.EventLogPath) {
			return c.Observability.EventLogPath
		}
		return filepath.Join(filepath.Dir(c.path), c.Observability.EventLogPath)
	}
	return filepath.Join(filepath.Dir(c.path), "telemetry.jsonl")
}

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
// file is not an error; commands report any required missing policy fields.
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
		var raw struct {
			Connect map[string]json.RawMessage `json:"connect"`
		}
		if json.Unmarshal(data, &raw) == nil {
			_, cfg.dialRetriesConfigured = raw.Connect["dial_retries"]
		}
	}

	cfg.applyDefaults()
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Observability.MaxEventLogBytes == 0 {
		c.Observability.MaxEventLogBytes = DefaultTelemetryMaxBytes
	}
	if c.Upload.MaxImageBytes == 0 {
		c.Upload.MaxImageBytes = DefaultMaxImageBytes
	}
	if c.Upload.MaxDataURLChars == 0 {
		c.Upload.MaxDataURLChars = DefaultMaxDataURLChars
	}
	if c.Upload.MaxAttachments == 0 {
		c.Upload.MaxAttachments = DefaultMaxAttachments
	}
	if c.Upload.MaxQueuedInputBytes == 0 {
		c.Upload.MaxQueuedInputBytes = DefaultMaxQueuedInputBytes
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
	if c.Connect.DialRetries == 0 && !c.dialRetriesConfigured {
		c.Connect.DialRetries = DefaultDialRetries
	}
	if c.Connect.DialRetrySeconds == 0 {
		c.Connect.DialRetrySeconds = DefaultDialRetrySeconds
	}
	if len(c.Connect.AcceptedTerminalKinds) == 0 {
		c.Connect.AcceptedTerminalKinds = []string{"papercode_websocket"}
	}
	if c.Connect.TerminalOutputQueueChunks <= 0 {
		c.Connect.TerminalOutputQueueChunks = DefaultTerminalOutputQueueChunks
	}
	if c.Connect.TerminalOutputBatchMilliseconds <= 0 {
		c.Connect.TerminalOutputBatchMilliseconds = DefaultTerminalOutputBatchMilliseconds
	}
	if c.Connect.TerminalOutputBufferBytes <= 0 {
		c.Connect.TerminalOutputBufferBytes = DefaultTerminalOutputBufferBytes
	}
	if len(c.Connect.ForwardTerminalEnv) == 0 {
		c.Connect.ForwardTerminalEnv = append([]string(nil), DefaultForwardTerminalEnv...)
	}
	if c.Connect.InputPartialFlushMilliseconds == 0 {
		c.Connect.InputPartialFlushMilliseconds = DefaultInputPartialFlushMilliseconds
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
	// A torn config file can strand the CLI without its server configuration.
	// Write beside the target then atomically replace it.
	tmp, err := os.CreateTemp(filepath.Dir(c.path), ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create config temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("restrict config temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write config %s: %w", c.path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync config %s: %w", c.path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close config %s: %w", c.path, err)
	}
	if err := os.Rename(tmpPath, c.path); err != nil {
		return fmt.Errorf("replace config %s: %w", c.path, err)
	}
	return os.Chmod(c.path, 0o600)
}

// NormalizeServerURL accepts the public Paperboat API URL. HTTP is restricted
// to loopback for local development; other targets must use HTTPS.
func NormalizeServerURL(value string) (string, error) {
	raw := strings.TrimSpace(value)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid Paperboat server URL %q", value)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return "", errorsNewServerURL()
	}
	host := u.Hostname()
	if host == "" {
		return "", errorsNewServerURL()
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
			return "", fmt.Errorf("Paperboat server URL must use HTTPS unless the host is loopback")
		}
	} else if u.Scheme != "https" {
		return "", fmt.Errorf("Paperboat server URL must use HTTPS")
	}
	u.Path = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func errorsNewServerURL() error { return fmt.Errorf("invalid Paperboat server URL") }
