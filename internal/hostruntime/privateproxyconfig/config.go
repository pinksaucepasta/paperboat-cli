// Package privateproxyconfig owns the reversible host proxy configuration used
// to route Paperboat private HTTP names through hostd.
package privateproxyconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

var (
	ErrUnsupported  = errors.New("private proxy configuration is unsupported")
	ErrConflict     = errors.New("proxy configuration is no longer owned by Paperboat")
	ErrUntrustedPAC = errors.New("PAC URL is not a trusted Paperboat loopback URL")
)

// Adapter snapshots and restores the exact platform-owned proxy fields.
// Snapshot values must be JSON and are opaque to Manager.
type Adapter interface {
	Name() string
	Snapshot(context.Context) (json.RawMessage, error)
	Install(context.Context, string) error
	Owns(context.Context, string) (bool, error)
	Matches(context.Context, json.RawMessage) (bool, error)
	Restore(context.Context, json.RawMessage) error
}

type Manager struct {
	journalPath string
	adapter     Adapter
	mu          sync.Mutex
}

func New(journalPath string, adapter Adapter) (*Manager, error) {
	if !filepath.IsAbs(journalPath) || adapter == nil || adapter.Name() == "" {
		return nil, errors.New("private proxy configuration requires an absolute journal path and adapter")
	}
	return &Manager{journalPath: filepath.Clean(journalPath), adapter: adapter}, nil
}

type journal struct {
	Version int             `json:"version"`
	Adapter string          `json:"adapter"`
	PACURL  string          `json:"pac_url"`
	Phase   string          `json:"phase"`
	Prior   json.RawMessage `json:"prior"`
}

// Install records recoverable pre-state before changing the operating system.
func (m *Manager) Install(ctx context.Context, pacURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := validatePACURL(pacURL); err != nil {
		return err
	}
	if existing, err := m.read(); err == nil {
		if existing.Adapter != m.adapter.Name() || existing.PACURL != pacURL {
			return ErrConflict
		}
		owned, err := m.adapter.Owns(ctx, pacURL)
		if err != nil {
			return err
		}
		if owned {
			return nil
		}
		// A prepared journal may mean the process died before or during apply.
		if existing.Phase == "prepared" {
			matches, matchErr := m.adapter.Matches(ctx, existing.Prior)
			if matchErr != nil {
				return matchErr
			}
			if matches {
				if err := m.removeJournal(); err != nil {
					return err
				}
			} else {
				if err := m.adapter.Restore(ctx, existing.Prior); err != nil {
					return fmt.Errorf("recover prior proxy state: %w", err)
				}
				if err := m.removeJournal(); err != nil {
					return err
				}
			}
		} else {
			return ErrConflict
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	prior, err := m.adapter.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("snapshot proxy state: %w", err)
	}
	j := journal{Version: 1, Adapter: m.adapter.Name(), PACURL: pacURL, Phase: "prepared", Prior: prior}
	if err := m.write(j); err != nil {
		return err
	}
	if err := m.adapter.Install(ctx, pacURL); err != nil {
		restoreErr := m.adapter.Restore(ctx, prior)
		if restoreErr == nil {
			_ = m.removeJournal()
		}
		return errors.Join(fmt.Errorf("install private proxy: %w", err), restoreErr)
	}
	j.Phase = "applied"
	if err := m.write(j); err != nil {
		return fmt.Errorf("mark private proxy applied: %w", err)
	}
	return nil
}

// Remove restores the exact pre-install state. It never overwrites a setting
// changed by the user or another program after Paperboat installed its PAC.
func (m *Manager) Remove(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, err := m.read()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if j.Adapter != m.adapter.Name() {
		return ErrConflict
	}
	owned, err := m.adapter.Owns(ctx, j.PACURL)
	if err != nil {
		return err
	}
	if !owned {
		matches, matchErr := m.adapter.Matches(ctx, j.Prior)
		if matchErr != nil {
			return matchErr
		}
		if matches && j.Phase == "prepared" {
			return m.removeJournal()
		}
		return ErrConflict
	}
	if err := m.adapter.Restore(ctx, j.Prior); err != nil {
		return fmt.Errorf("restore prior proxy state: %w", err)
	}
	return m.removeJournal()
}

// Recover rolls back an interrupted install. Call it before the first Install.
func (m *Manager) Recover(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, err := m.read()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if j.Adapter != m.adapter.Name() {
		return ErrConflict
	}
	owned, err := m.adapter.Owns(ctx, j.PACURL)
	if err != nil {
		return err
	}
	if !owned {
		matches, matchErr := m.adapter.Matches(ctx, j.Prior)
		if matchErr != nil {
			return matchErr
		}
		if matches && j.Phase == "prepared" {
			return m.removeJournal()
		}
		return ErrConflict
	}
	if err := m.adapter.Restore(ctx, j.Prior); err != nil {
		return fmt.Errorf("recover prior proxy state: %w", err)
	}
	return m.removeJournal()
}

func validatePACURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return ErrUntrustedPAC
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || u.Port() == "" || u.Path == "" || u.Path == "/" {
		return ErrUntrustedPAC
	}
	return nil
}

func (m *Manager) write(j journal) error {
	body, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return atomicfile.Write(m.journalPath, append(body, '\n'), atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}
func (m *Manager) read() (journal, error) {
	info, err := os.Lstat(m.journalPath)
	if err != nil {
		return journal{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return journal{}, errors.New("private proxy journal must be a regular 0600 file")
	}
	body, err := os.ReadFile(m.journalPath)
	if err != nil {
		return journal{}, err
	}
	var j journal
	if json.Unmarshal(body, &j) != nil || j.Version != 1 || j.Adapter == "" || j.PACURL == "" || (j.Phase != "prepared" && j.Phase != "applied") || len(j.Prior) == 0 {
		return journal{}, errors.New("invalid private proxy journal")
	}
	return j, nil
}
func (m *Manager) removeJournal() error {
	if err := os.Remove(m.journalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	d, err := os.Open(filepath.Dir(m.journalPath))
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
