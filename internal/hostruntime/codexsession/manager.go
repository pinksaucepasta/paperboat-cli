package codexsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/envinject"
	"github.com/pinksaucepasta/paperboat/internal/processlaunch"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

var (
	ErrInvalid          = errors.New("invalid codex session request")
	ErrNotFound         = errors.New("codex session not found")
	ErrLimitReached     = errors.New("codex session limit reached")
	ErrWorkspaceEscape  = errors.New("path escapes workspace")
	ErrCodexUnavailable = errors.New("codex is unavailable")
)

const descriptorSchema = "paperboat.codex-runtime-session/v1"

type Command interface {
	Start() error
	Wait() error
	Signal(os.Signal) error
	Kill() error
}

type Config struct {
	StateRoot          string
	WorkspaceRoot      string
	Environment        []string
	ManagedEnvironment func() ([]string, error)
	CodexPath          string
	MaxSessions        int
	StopGrace          time.Duration
	ReadinessTimeout   time.Duration
	Now                func() time.Time
	Command            func(context.Context, string, ...string) Command
	Preflight          func(context.Context) (string, error)
}

type Manager struct {
	config   Config
	mu       sync.Mutex
	sessions map[string]*managed
}

type managed struct {
	descriptor Descriptor
	command    Command
	done       chan struct{}
	waitErr    error
}

type Descriptor struct {
	Schema         string    `json:"schema"`
	ID             string    `json:"id"`
	Path           string    `json:"path"`
	SocketPath     string    `json:"socket_path"`
	CodexVersion   string    `json:"codex_version"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
	PID            int       `json:"pid,omitempty"`
}

type DirectoryPage struct {
	Path        string   `json:"path"`
	Directories []string `json:"directories"`
	NextCursor  string   `json:"next_cursor,omitempty"`
}

func New(config Config) (*Manager, error) {
	if config.MaxSessions == 0 {
		config.MaxSessions = 4
	}
	if config.StopGrace == 0 {
		config.StopGrace = 5 * time.Second
	}
	if config.ReadinessTimeout == 0 {
		config.ReadinessTimeout = 15 * time.Second
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.CodexPath == "" {
		config.CodexPath = "codex"
	}
	if config.Command == nil {
		config.Command = func(ctx context.Context, name string, args ...string) Command {
			environment, err := resolvedEnvironment(config)
			if err != nil {
				return failedCommand{err: err}
			}
			cmd := exec.CommandContext(ctx, name, args...)
			processlaunch.ConfigureBackground(cmd)
			cmd.Env = environment
			return &execCommand{Cmd: cmd}
		}
	}
	if config.Preflight == nil {
		config.Preflight = func(ctx context.Context) (string, error) {
			environment, err := resolvedEnvironment(config)
			if err != nil {
				return "", err
			}
			return codexPreflight(ctx, config.CodexPath, environment)
		}
	}
	if !canonicalAbsolute(config.StateRoot) || !canonicalAbsolute(config.WorkspaceRoot) || config.MaxSessions < 1 || config.StopGrace <= 0 || config.ReadinessTimeout <= 0 {
		return nil, ErrInvalid
	}
	resolvedWorkspace, err := filepath.EvalSymlinks(config.WorkspaceRoot)
	if err != nil {
		return nil, err
	}
	config.WorkspaceRoot = resolvedWorkspace
	if err := os.MkdirAll(config.StateRoot, 0o700); err != nil {
		return nil, err
	}
	m := &Manager{config: config, sessions: make(map[string]*managed)}
	if err := m.recover(); err != nil {
		return nil, err
	}
	return m, nil
}

type execCommand struct{ *exec.Cmd }

func (c *execCommand) Signal(signal os.Signal) error { return c.Process.Signal(signal) }
func (c *execCommand) Kill() error                   { return c.Process.Kill() }

type failedCommand struct{ err error }

func (c failedCommand) Start() error           { return c.err }
func (c failedCommand) Wait() error            { return c.err }
func (c failedCommand) Signal(os.Signal) error { return c.err }
func (c failedCommand) Kill() error            { return c.err }

func resolvedEnvironment(config Config) ([]string, error) {
	if config.ManagedEnvironment == nil {
		return append([]string(nil), config.Environment...), nil
	}
	managed, err := config.ManagedEnvironment()
	if err != nil {
		return nil, err
	}
	return envinject.Merge(config.Environment, managed)
}

func (m *Manager) Prepare(ctx context.Context, id, requestedPath string, leaseExpiresAt time.Time) (Descriptor, error) {
	if !validID(id) || !leaseExpiresAt.After(m.config.Now()) {
		return Descriptor{}, ErrInvalid
	}
	path, err := m.ResolvePath(requestedPath)
	if err != nil {
		return Descriptor{}, err
	}
	preflightCtx, preflightCancel := context.WithTimeout(ctx, 10*time.Second)
	remoteVersion, err := m.config.Preflight(preflightCtx)
	preflightCancel()
	if err != nil {
		return Descriptor{}, errors.Join(ErrCodexUnavailable, err)
	}
	m.mu.Lock()
	if existing := m.sessions[id]; existing != nil {
		d := existing.descriptor
		m.mu.Unlock()
		if d.Path != path {
			return Descriptor{}, ErrInvalid
		}
		return d, nil
	}
	if len(m.sessions) >= m.config.MaxSessions {
		m.mu.Unlock()
		return Descriptor{}, ErrLimitReached
	}
	directory := filepath.Join(m.config.StateRoot, id)
	if err := os.Mkdir(directory, 0o700); err != nil {
		m.mu.Unlock()
		return Descriptor{}, err
	}
	endpoint, listen, err := codexAppServerEndpoint(directory)
	if err != nil {
		m.mu.Unlock()
		_ = os.RemoveAll(directory)
		return Descriptor{}, errors.Join(ErrInvalid, err)
	}
	processCtx, cancel := context.WithCancel(context.Background())
	command := m.config.Command(processCtx, m.config.CodexPath, "app-server", "--listen", listen)
	if cmd, ok := command.(*execCommand); ok {
		cmd.Dir = path
		// The managed environment is write-only. The app server and child
		// commands can echo their environment, so Paperboat must not persist or
		// forward their stdout or stderr through its own logs.
		cmd.Stdout = nil
		cmd.Stderr = nil
	}
	if err := command.Start(); err != nil {
		cancel()
		m.mu.Unlock()
		_ = os.RemoveAll(directory)
		return Descriptor{}, errors.Join(ErrCodexUnavailable, err)
	}
	d := Descriptor{Schema: descriptorSchema, ID: id, Path: path, SocketPath: endpoint, CodexVersion: remoteVersion, LeaseExpiresAt: leaseExpiresAt.UTC()}
	if cmd, ok := command.(*execCommand); ok && cmd.Process != nil {
		d.PID = cmd.Process.Pid
	}
	s := &managed{descriptor: d, command: command, done: make(chan struct{})}
	m.sessions[id] = s
	m.mu.Unlock()
	go func() { s.waitErr = command.Wait(); cancel(); close(s.done) }()
	if err := waitCodexAppServer(ctx, endpoint, m.config.ReadinessTimeout); err != nil {
		_ = m.Stop(context.Background(), id)
		return Descriptor{}, errors.Join(ErrCodexUnavailable, err)
	}
	m.mu.Lock()
	if current := m.sessions[id]; current != nil {
		current.descriptor = d
	}
	m.mu.Unlock()
	if err := writeDescriptor(directory, d); err != nil {
		_ = m.Stop(context.Background(), id)
		return Descriptor{}, err
	}
	return d, nil
}

func (m *Manager) Renew(id string, expires time.Time) error {
	if !validID(id) || !expires.After(m.config.Now()) {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	if s == nil {
		return ErrNotFound
	}
	s.descriptor.LeaseExpiresAt = expires.UTC()
	return writeDescriptor(filepath.Join(m.config.StateRoot, id), s.descriptor)
}

func (m *Manager) Stop(ctx context.Context, id string) error {
	m.mu.Lock()
	s := m.sessions[id]
	if s == nil {
		m.mu.Unlock()
		return ErrNotFound
	}
	delete(m.sessions, id)
	m.mu.Unlock()
	_ = stopCodexCommand(s.command)
	timer := time.NewTimer(m.config.StopGrace)
	defer timer.Stop()
	select {
	case <-s.done:
	case <-ctx.Done():
		_ = s.command.Kill()
		<-s.done
		return ctx.Err()
	case <-timer.C:
		_ = s.command.Kill()
		<-s.done
	}
	return os.RemoveAll(filepath.Join(m.config.StateRoot, id))
}

func (m *Manager) Socket(id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	if s == nil {
		return "", ErrNotFound
	}
	return s.descriptor.SocketPath, nil
}

func (m *Manager) ResolvePath(requested string) (string, error) {
	if requested == "" || requested == "~" {
		requested = m.config.WorkspaceRoot
	} else if !filepath.IsAbs(requested) {
		requested = filepath.Join(m.config.WorkspaceRoot, requested)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(requested))
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", ErrInvalid
	}
	rel, err := filepath.Rel(m.config.WorkspaceRoot, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", ErrWorkspaceEscape
	}
	return resolved, nil
}

func (m *Manager) Directories(path, cursor string, limit int) (DirectoryPage, error) {
	resolved, err := m.ResolvePath(path)
	if err != nil {
		return DirectoryPage{}, err
	}
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	entries, err := os.ReadDir(resolved)
	if err != nil {
		return DirectoryPage{}, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		child, resolveErr := filepath.EvalSymlinks(filepath.Join(resolved, entry.Name()))
		if resolveErr != nil {
			continue
		}
		if _, resolveErr = m.ResolvePath(child); resolveErr == nil {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	start := sort.SearchStrings(names, cursor)
	if cursor != "" && start < len(names) && names[start] == cursor {
		start++
	}
	end := start + limit
	if end > len(names) {
		end = len(names)
	}
	next := ""
	if end < len(names) && end > start {
		next = names[end-1]
	}
	return DirectoryPage{Path: resolved, Directories: append([]string(nil), names[start:end]...), NextCursor: next}, nil
}

func (m *Manager) CleanupExpired(ctx context.Context) error {
	m.mu.Lock()
	ids := make([]string, 0)
	now := m.config.Now()
	for id, s := range m.sessions {
		if !s.descriptor.LeaseExpiresAt.After(now) {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	var result error
	for _, id := range ids {
		result = errors.Join(result, m.Stop(ctx, id))
	}
	return result
}

func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	var result error
	for _, id := range ids {
		result = errors.Join(result, m.Stop(ctx, id))
	}
	return result
}

func (m *Manager) recover() error {
	entries, err := os.ReadDir(m.config.StateRoot)
	if err != nil {
		return err
	}
	now := m.config.Now()
	for _, entry := range entries {
		if !entry.IsDir() || !validID(entry.Name()) {
			continue
		}
		directory := filepath.Join(m.config.StateRoot, entry.Name())
		body, readErr := os.ReadFile(filepath.Join(directory, "descriptor.json"))
		var d Descriptor
		if readErr != nil || json.Unmarshal(body, &d) != nil || d.Schema != descriptorSchema || !d.LeaseExpiresAt.After(now) {
			_ = terminateCodexPID(d.PID)
			_ = os.RemoveAll(directory)
			continue
		}
		_ = terminateCodexPID(d.PID)
		_ = os.RemoveAll(directory)
	}
	return nil
}
func validID(s string) bool {
	if len(s) < 8 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
func canonicalAbsolute(s string) bool { return filepath.IsAbs(s) && filepath.Clean(s) == s }
func writeDescriptor(dir string, d Descriptor) error {
	body, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, "descriptor.json"), body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}
func codexVersion(ctx context.Context, path string, env []string) (string, error) {
	cmd := exec.CommandContext(ctx, path, "--version")
	processlaunch.ConfigureBackground(cmd)
	cmd.Env = env
	body, err := cmd.Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(body))
	if len(fields) != 2 {
		return "", fmt.Errorf("malformed codex version")
	}
	return fields[1], nil
}
func codexPreflight(ctx context.Context, path string, env []string) (string, error) {
	version, err := codexVersion(ctx, path, env)
	if err != nil {
		return "", err
	}
	command := exec.CommandContext(ctx, path, "login", "status")
	processlaunch.ConfigureBackground(command)
	command.Env = env
	if _, loginErr := command.CombinedOutput(); loginErr != nil {
		// The managed environment is write-only. A child command can echo its
		// own environment on failure, so none of its output may enter an error
		// that is returned or logged by the host runtime.
		return "", errors.New("Codex authentication is unavailable")
	}
	return version, nil
}
