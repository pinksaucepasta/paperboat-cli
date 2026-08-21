// Package config loads paperboat configuration and credential profiles. Everything that could reasonably
// change is data-driven here — nothing about endpoints, limits, agents, or
// machine catalogs are hardcoded in command logic. See AGENTS.md ("No hardcoding").
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
	"github.com/pinksaucepasta/paperboat/internal/userpaths"
)

// EnvConfigPath overrides the config file location when set.
const EnvConfigPath = "PAPERBOAT_CONFIG"

// FilePasteConfig controls local file-paste detection. All fields are tunable so
// behavior can change without rebuilding the binary.
type FilePasteConfig struct {
	// WatchDirs are directories terminals write temporary files into on paste.
	// Absolute paths, or "~"-prefixed for the home dir.
	WatchDirs []string `json:"watch_dirs,omitempty"`
	// TempFilePatterns optionally restrict terminal-created file names. Patterns
	// use filepath glob syntax and may match a basename or normalized full path.
	TempFilePatterns []string `json:"temp_file_patterns,omitempty"`
	// MaxQueuedInputBytes bounds local input held behind a file transfer.
	MaxQueuedInputBytes int `json:"max_queued_input_bytes,omitempty"`
}

const DefaultMaxQueuedInputBytes = 1024 * 1024

const MaxFavorites = 5

var ErrFavoriteLimit = errors.New("favorite limit reached")

type Favorite struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Config is the on-disk CLI configuration.
type Config struct {
	// ServerURL is the paperboat-server base URL. It is required for production commands.
	ServerURL string `json:"server_url,omitempty"`
	// LastEnvironmentID is the last successfully connected stable project or
	// user machine ID. Names are never persisted because they may become
	// ambiguous or change ownership.
	LastEnvironmentID string     `json:"last_environment_id,omitempty"`
	Favorites         []Favorite `json:"favorites,omitempty"`
	Auth              AuthConfig `json:"auth,omitempty"`
	// FilePaste configures generic file-paste detection.
	FilePaste FilePasteConfig `json:"file_paste,omitempty"`
	// Connect tunes the pre-connect broker + readiness polling.
	Connect ConnectConfig `json:"connect,omitempty"`
	// Observability controls the local metadata-only event log.
	Observability ObservabilityConfig `json:"observability,omitempty"`
	// StatusBar controls the local terminal status line during interactive sessions.
	StatusBar StatusBarConfig `json:"status_bar,omitempty"`

	// path is where this config was loaded from (or would be written to).
	path                  string `json:"-"`
	dialRetriesConfigured bool
}

// StatusBarConfig controls the optional local status line. It has no effect on
// the remote terminal byte stream.
type StatusBarConfig struct {
	// Mode is auto, on, or off. Auto enables only on compatible interactive terminals.
	Mode string `json:"mode,omitempty"`
	// Fullscreen controls whether the bar hides while a remote application owns
	// the terminal's alternate screen. Hide is the safe default.
	Fullscreen string `json:"fullscreen,omitempty"`
	// Theme is terminal, dark, light, or mono. Terminal inherits the user's
	// configured terminal foreground and background colors.
	Theme string `json:"theme,omitempty"`
	// Privacy hides environment, session, credits, and storage values.
	Privacy bool `json:"privacy,omitempty"`
	// TerminalTitle publishes environment/session context in the terminal title.
	TerminalTitle bool `json:"terminal_title,omitempty"`
	// Colors optionally override semantic colors supplied by the selected theme.
	Colors StatusBarColors `json:"colors,omitempty"`
	// NoticeSeconds controls how long non-error event notices remain visible.
	NoticeSeconds int `json:"notice_seconds,omitempty"`
	// Left, Center, and Right select ordered widgets for each status-bar region.
	// Supported widgets: project, session, connection, activity, config_sync,
	// credits, and storage. An explicit empty list hides that region.
	Left   []string `json:"left"`
	Center []string `json:"center"`
	Right  []string `json:"right"`
}

// StatusBarColors contains validated ANSI color names or #RRGGBB true-color values.
// Empty values inherit from the selected theme.
type StatusBarColors struct {
	Foreground string `json:"foreground,omitempty"`
	Background string `json:"background,omitempty"`
	Accent     string `json:"accent,omitempty"`
	Warning    string `json:"warning,omitempty"`
	Error      string `json:"error,omitempty"`
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
	// AllowFileFallback records use of owner-only 0600 token files when the OS
	// credential service is unavailable, as is common on headless Linux.
	AllowFileFallback bool `json:"allow_file_fallback,omitempty"`
	// ProfileDir overrides the shared profile directory (primarily for managed/headless installs).
	ProfileDir string `json:"profile_dir,omitempty"`
}

// ConnectConfig tunes how the CLI waits for an idle machine and its helper route.
type ConnectConfig struct {
	// TerminalTransport selects auto, quic, or wss. Auto uses direct QUIC,
	// relay QUIC, then WSS; quic excludes WSS.
	TerminalTransport string `json:"terminal_transport,omitempty"`
	// ReadyTimeoutSeconds caps how long to poll for the tunnel to become
	// connectable before giving up. Defaults to DefaultReadyTimeoutSeconds.
	ReadyTimeoutSeconds int `json:"ready_timeout_seconds,omitempty"`
	// PollIntervalSeconds is the gap between readiness polls. Defaults to
	// DefaultPollIntervalSeconds.
	PollIntervalSeconds int `json:"poll_interval_seconds,omitempty"`
	// AllowedRouteHosts restricts descriptor endpoint hosts. Empty preserves
	// server-authored routing while a managed install can pin its relay hosts.
	AllowedRouteHosts []string `json:"allowed_route_hosts,omitempty"`
	DialRetries       int      `json:"dial_retries"`
	DialRetrySeconds  int      `json:"dial_retry_seconds,omitempty"`
	// TerminalOutputQueueChunks bounds buffered remote output events.
	TerminalOutputQueueChunks int `json:"terminal_output_queue_chunks,omitempty"`
	// TerminalOutputBatchMilliseconds coalesces animation bursts before local rendering.
	TerminalOutputBatchMilliseconds int `json:"terminal_output_batch_milliseconds,omitempty"`
	// TerminalOutputBufferBytes controls each local terminal output read.
	TerminalOutputBufferBytes int `json:"terminal_output_buffer_bytes,omitempty"`
	// InputPartialFlushMilliseconds bounds how long input bytes that could
	// begin a bracketed-paste start marker (e.g. a bare ESC keypress) are
	// withheld before being forwarded to the remote terminal. Negative
	// disables the flush.
	InputPartialFlushMilliseconds int `json:"input_partial_flush_milliseconds,omitempty"`
}

const (
	DefaultReadyTimeoutSeconds             = 180
	DefaultPollIntervalSeconds             = 3
	DefaultDialRetries                     = 6
	DefaultDialRetrySeconds                = 2
	DefaultTelemetryMaxBytes               = 5 * 1024 * 1024
	DefaultTerminalOutputQueueChunks       = 256
	DefaultTerminalOutputBatchMilliseconds = 0
	DefaultTerminalOutputBufferBytes       = 128 * 1024
	DefaultInputPartialFlushMilliseconds   = 1
	DefaultTerminalTransport               = "a"
	PeerRelayPreferenceMilliseconds        = 1000
	PeerWSSStartMilliseconds               = 1000
	PeerConnectTimeoutMilliseconds         = 20000
	DefaultStatusBarMode                   = "auto"
	DefaultStatusBarFullscreen             = "hide"
	DefaultStatusBarTheme                  = "terminal"
	DefaultStatusBarNoticeSeconds          = 5
)

var (
	DefaultStatusBarLeft   = []string{"project", "session"}
	DefaultStatusBarCenter = []string{"activity"}
	DefaultStatusBarRight  = []string{"credits", "connection"}
)

// DefaultStatusBarConfig returns an independent copy of the product defaults.
func DefaultStatusBarConfig() StatusBarConfig {
	return StatusBarConfig{
		Mode:          DefaultStatusBarMode,
		Fullscreen:    DefaultStatusBarFullscreen,
		Theme:         DefaultStatusBarTheme,
		NoticeSeconds: DefaultStatusBarNoticeSeconds,
		Left:          append([]string(nil), DefaultStatusBarLeft...),
		Center:        append([]string(nil), DefaultStatusBarCenter...),
		Right:         append([]string(nil), DefaultStatusBarRight...),
	}
}

// TerminalEnv is the complete supported PTY capability environment.
var TerminalEnv = []string{
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
	path, err := userpaths.Config("paperboat/config.json")
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return path, nil
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
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if strings.TrimSpace(c.ServerURL) == "" {
		c.ServerURL = strings.TrimSpace(buildinfo.DefaultServerURL)
	}
	if strings.TrimSpace(c.Connect.TerminalTransport) == "" {
		c.Connect.TerminalTransport = DefaultTerminalTransport
	}
	c.Connect.TerminalTransport = strings.ToLower(strings.TrimSpace(c.Connect.TerminalTransport))
	if c.Observability.MaxEventLogBytes == 0 {
		c.Observability.MaxEventLogBytes = DefaultTelemetryMaxBytes
	}
	if c.FilePaste.MaxQueuedInputBytes == 0 {
		c.FilePaste.MaxQueuedInputBytes = DefaultMaxQueuedInputBytes
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
	if c.Connect.TerminalOutputQueueChunks <= 0 {
		c.Connect.TerminalOutputQueueChunks = DefaultTerminalOutputQueueChunks
	}
	if c.Connect.TerminalOutputBufferBytes <= 0 {
		c.Connect.TerminalOutputBufferBytes = DefaultTerminalOutputBufferBytes
	}
	if c.Connect.InputPartialFlushMilliseconds == 0 {
		c.Connect.InputPartialFlushMilliseconds = DefaultInputPartialFlushMilliseconds
	}
	if c.StatusBar.Mode == "" {
		c.StatusBar.Mode = DefaultStatusBarMode
	}
	if c.StatusBar.Fullscreen == "" {
		c.StatusBar.Fullscreen = DefaultStatusBarFullscreen
	}
	if c.StatusBar.Theme == "" {
		c.StatusBar.Theme = DefaultStatusBarTheme
	}
	if c.StatusBar.NoticeSeconds == 0 {
		c.StatusBar.NoticeSeconds = DefaultStatusBarNoticeSeconds
	}
	if c.StatusBar.Left == nil {
		c.StatusBar.Left = append([]string(nil), DefaultStatusBarLeft...)
	}
	if c.StatusBar.Center == nil {
		c.StatusBar.Center = append([]string(nil), DefaultStatusBarCenter...)
	}
	if c.StatusBar.Right == nil {
		c.StatusBar.Right = append([]string(nil), DefaultStatusBarRight...)
	}
	c.StatusBar.Mode = strings.ToLower(strings.TrimSpace(c.StatusBar.Mode))
	c.StatusBar.Fullscreen = strings.ToLower(strings.TrimSpace(c.StatusBar.Fullscreen))
	c.StatusBar.Theme = strings.ToLower(strings.TrimSpace(c.StatusBar.Theme))
	c.StatusBar.Left = normalizeStatusWidgets(c.StatusBar.Left)
	c.StatusBar.Center = normalizeStatusWidgets(c.StatusBar.Center)
	c.StatusBar.Right = normalizeStatusWidgets(c.StatusBar.Right)
	c.StatusBar.Colors.Foreground = strings.ToLower(strings.TrimSpace(c.StatusBar.Colors.Foreground))
	c.StatusBar.Colors.Background = strings.ToLower(strings.TrimSpace(c.StatusBar.Colors.Background))
	c.StatusBar.Colors.Accent = strings.ToLower(strings.TrimSpace(c.StatusBar.Colors.Accent))
	c.StatusBar.Colors.Warning = strings.ToLower(strings.TrimSpace(c.StatusBar.Colors.Warning))
	c.StatusBar.Colors.Error = strings.ToLower(strings.TrimSpace(c.StatusBar.Colors.Error))
}

func normalizeStatusWidgets(values []string) []string {
	for index := range values {
		values[index] = strings.ToLower(strings.TrimSpace(values[index]))
	}
	return values
}

// Validate checks the complete effective configuration. Callers that mutate a
// loaded Config can use it before presenting success.
func (c *Config) Validate() error {
	if len(c.Favorites) > MaxFavorites {
		return fmt.Errorf("favorites cannot contain more than %d items", MaxFavorites)
	}
	seenFavorites := make(map[string]struct{}, len(c.Favorites))
	for _, favorite := range c.Favorites {
		if favorite.Kind != "machine" && favorite.Kind != "session" && favorite.Kind != "preview" {
			return fmt.Errorf("favorites contains unsupported kind %q", favorite.Kind)
		}
		if strings.TrimSpace(favorite.ID) == "" {
			return fmt.Errorf("favorites contains an empty id")
		}
		key := favorite.Kind + ":" + favorite.ID
		if _, exists := seenFavorites[key]; exists {
			return fmt.Errorf("favorites contains duplicate %q", key)
		}
		seenFavorites[key] = struct{}{}
	}
	switch c.Connect.TerminalTransport {
	case "a", "d", "q", "w", "r":
	default:
		return fmt.Errorf("connect.terminal_transport must be a, d, q, w, or r")
	}
	if c.Connect.TerminalOutputBatchMilliseconds < 0 {
		return fmt.Errorf("connect.terminal_output_batch_milliseconds cannot be negative")
	}
	if c.Connect.InputPartialFlushMilliseconds < 0 {
		return fmt.Errorf("connect.input_partial_flush_milliseconds cannot be negative")
	}
	switch strings.ToLower(strings.TrimSpace(c.StatusBar.Mode)) {
	case "auto", "on", "off":
	default:
		return fmt.Errorf("status_bar.mode must be auto, on, or off")
	}
	switch strings.ToLower(strings.TrimSpace(c.StatusBar.Fullscreen)) {
	case "hide", "show":
	default:
		return fmt.Errorf("status_bar.fullscreen must be hide or show")
	}
	switch strings.ToLower(strings.TrimSpace(c.StatusBar.Theme)) {
	case "terminal", "dark", "light", "mono":
	default:
		return fmt.Errorf("status_bar.theme must be terminal, dark, light, or mono")
	}
	if c.StatusBar.NoticeSeconds < 1 || c.StatusBar.NoticeSeconds > 60 {
		return fmt.Errorf("status_bar.notice_seconds must be between 1 and 60")
	}
	for field, value := range map[string]string{
		"foreground": c.StatusBar.Colors.Foreground,
		"background": c.StatusBar.Colors.Background,
		"accent":     c.StatusBar.Colors.Accent,
		"warning":    c.StatusBar.Colors.Warning,
		"error":      c.StatusBar.Colors.Error,
	} {
		if !validStatusColor(value) {
			return fmt.Errorf("status_bar.colors.%s must be an ANSI color name or #RRGGBB", field)
		}
	}
	seen := make(map[string]string, len(c.StatusBar.Left)+len(c.StatusBar.Center)+len(c.StatusBar.Right))
	for region, widgets := range map[string][]string{"left": c.StatusBar.Left, "center": c.StatusBar.Center, "right": c.StatusBar.Right} {
		for _, widget := range widgets {
			widget = strings.ToLower(strings.TrimSpace(widget))
			switch widget {
			case "project", "session", "connection", "activity", "config_sync", "credits", "storage":
			default:
				return fmt.Errorf("status_bar.%s has unsupported widget %q", region, widget)
			}
			if firstRegion, ok := seen[widget]; ok {
				return fmt.Errorf("status_bar.%s repeats widget %q already used in status_bar.%s", region, widget, firstRegion)
			}
			seen[widget] = region
		}
	}
	return nil
}

func (c *Config) IsFavorite(kind, id string) bool {
	for _, favorite := range c.Favorites {
		if favorite.Kind == kind && favorite.ID == id {
			return true
		}
	}
	return false
}

func (c *Config) SetFavorite(kind, id string, favorite bool) error {
	for index, item := range c.Favorites {
		if item.Kind != kind || item.ID != id {
			continue
		}
		if !favorite {
			c.Favorites = append(c.Favorites[:index], c.Favorites[index+1:]...)
		}
		return nil
	}
	if !favorite {
		return nil
	}
	if len(c.Favorites) >= MaxFavorites {
		return ErrFavoriteLimit
	}
	c.Favorites = append(c.Favorites, Favorite{Kind: kind, ID: id})
	return nil
}

func validStatusColor(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "default" {
		return true
	}
	if len(value) == 7 && value[0] == '#' {
		for _, r := range value[1:] {
			if !strings.ContainsRune("0123456789abcdef", r) {
				return false
			}
		}
		return true
	}
	_, ok := map[string]struct{}{
		"black": {}, "red": {}, "green": {}, "yellow": {}, "blue": {}, "magenta": {}, "cyan": {}, "white": {},
		"bright_black": {}, "bright_red": {}, "bright_green": {}, "bright_yellow": {}, "bright_blue": {},
		"bright_magenta": {}, "bright_cyan": {}, "bright_white": {},
	}[value]
	return ok
}

// Save writes the config to its path, creating parent dirs as needed.
func (c *Config) Save() error {
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return err
	}
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
	if err := atomicfile.Write(c.path, data, atomicfile.CurrentOwnerOptions(0o600)); err != nil {
		return fmt.Errorf("replace config %s: %w", c.path, err)
	}
	return nil
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
