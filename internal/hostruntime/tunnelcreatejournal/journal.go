package tunnelcreatejournal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

const (
	Schema           = "paperboat.tunnel-create-workflow/v1"
	maximumDomains   = 32
	maximumJournal   = 64 << 10
	workflowDirName  = "tunnel-create"
	workflowRootName = "workflows"
)

var (
	ErrInvalid         = errors.New("invalid tunnel create workflow journal")
	ErrRequestMismatch = errors.New("tunnel create retry does not match the interrupted request")
	ErrLocked          = errors.New("tunnel create workflow is already active")
)

type Stage string

const (
	StagePrepared       Stage = "prepared"
	StageTunnelCreated  Stage = "tunnel_created"
	StageConnectorReady Stage = "connector_ready"
	StageDomainsReady   Stage = "domains_ready"
)

type Domain struct {
	Key   string `json:"key"`
	ID    string `json:"id,omitempty"`
	Stage Stage  `json:"stage"`
}

type Journal struct {
	Schema        string     `json:"schema"`
	HostID        string     `json:"host_id"`
	RequestDigest string     `json:"request_digest"`
	TunnelKey     string     `json:"tunnel_key"`
	TunnelID      string     `json:"tunnel_id,omitempty"`
	OperationID   string     `json:"operation_id,omitempty"`
	Stage         Stage      `json:"stage"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Domains       []Domain   `json:"domains"`
}

type Config struct {
	StateRoot     string
	HostID        string
	NameDigest    string
	RequestDigest string
	DomainCount   int
	ExpiresAt     *time.Time
	NewKey        func() (string, error)
}

type Session struct {
	mu        sync.Mutex
	path      string
	directory string
	lock      *processLock
	journal   Journal
	completed bool
	closed    bool
}

func Begin(ctx context.Context, config Config) (*Session, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, context.Canceled
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	directory := filepath.Join(config.StateRoot, workflowRootName, workflowDirName)
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, fmt.Errorf("prepare tunnel create workflow directory: %w", err)
	}
	identity := sha256.Sum256([]byte(config.HostID + "\x00" + config.NameDigest))
	path := filepath.Join(directory, hex.EncodeToString(identity[:])+".json")
	lock, err := acquireProcessLock(path + ".lock")
	if err != nil {
		return nil, err
	}
	session := &Session{path: path, directory: directory, lock: lock}
	closeWith := func(cause error) (*Session, error) {
		_ = session.Close()
		return nil, cause
	}
	if err := ctx.Err(); err != nil {
		return closeWith(err)
	}
	body, err := readPrivateFile(path, maximumJournal)
	switch {
	case err == nil:
		journal, decodeErr := decodeJournal(body)
		if decodeErr != nil {
			return closeWith(decodeErr)
		}
		if journal.HostID != config.HostID || journal.RequestDigest != config.RequestDigest || len(journal.Domains) != config.DomainCount {
			return closeWith(ErrRequestMismatch)
		}
		session.journal = journal
		return session, nil
	case !errors.Is(err, os.ErrNotExist):
		return closeWith(fmt.Errorf("read tunnel create workflow: %w", err))
	}
	tunnelKey, err := config.NewKey()
	if err != nil || !validToken(tunnelKey) {
		return closeWith(errors.Join(ErrInvalid, err))
	}
	domains := make([]Domain, config.DomainCount)
	for i := range domains {
		key, keyErr := config.NewKey()
		if keyErr != nil || !validToken(key) {
			return closeWith(errors.Join(ErrInvalid, keyErr))
		}
		domains[i] = Domain{Key: key, Stage: StagePrepared}
	}
	session.journal = Journal{Schema: Schema, HostID: config.HostID, RequestDigest: config.RequestDigest, TunnelKey: tunnelKey, Stage: StagePrepared, ExpiresAt: cloneTime(config.ExpiresAt), Domains: domains}
	if err := session.persistLocked(); err != nil {
		return closeWith(err)
	}
	return session, nil
}

func (s *Session) Snapshot() Journal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneJournal(s.journal)
}

func (s *Session) RecordTunnel(ctx context.Context, tunnelID, operationID string) error {
	return s.update(ctx, func(journal *Journal) error {
		if !validToken(tunnelID) || !validToken(operationID) {
			return ErrInvalid
		}
		if journal.TunnelID != "" && (journal.TunnelID != tunnelID || journal.OperationID != operationID) {
			return ErrRequestMismatch
		}
		journal.TunnelID, journal.OperationID = tunnelID, operationID
		if journal.Stage == StagePrepared {
			journal.Stage = StageTunnelCreated
		}
		return nil
	})
}

func (s *Session) RecordConnectorReady(ctx context.Context) error {
	return s.update(ctx, func(journal *Journal) error {
		if journal.TunnelID == "" || journal.Stage == StagePrepared {
			return ErrInvalid
		}
		if journal.Stage == StageTunnelCreated {
			journal.Stage = StageConnectorReady
		}
		return nil
	})
}

func (s *Session) RecordDomain(ctx context.Context, index int, domainID string) error {
	return s.update(ctx, func(journal *Journal) error {
		if journal.Stage != StageConnectorReady && journal.Stage != StageDomainsReady || index < 0 || index >= len(journal.Domains) || !validToken(domainID) {
			return ErrInvalid
		}
		if journal.Domains[index].ID != "" && journal.Domains[index].ID != domainID {
			return ErrRequestMismatch
		}
		journal.Domains[index].ID = domainID
		journal.Domains[index].Stage = StageDomainsReady
		allReady := true
		for _, domain := range journal.Domains {
			allReady = allReady && domain.ID != ""
		}
		if allReady {
			journal.Stage = StageDomainsReady
		}
		return nil
	})
}

func (s *Session) Complete(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrInvalid
	}
	if ctx == nil || ctx.Err() != nil {
		if ctx == nil {
			return context.Canceled
		}
		return ctx.Err()
	}
	if s.completed {
		return nil
	}
	if !canComplete(s.journal) {
		return ErrInvalid
	}
	if err := removePrivateFile(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncDirectory(s.directory); err != nil {
		return err
	}
	s.completed = true
	return nil
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.lock.Close()
}

func (s *Session) update(ctx context.Context, mutate func(*Journal) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.completed || ctx == nil || ctx.Err() != nil {
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrInvalid
	}
	next := cloneJournal(s.journal)
	if err := mutate(&next); err != nil {
		return err
	}
	if err := validateJournal(next); err != nil {
		return err
	}
	previous := s.journal
	s.journal = next
	if err := s.persistLocked(); err != nil {
		s.journal = previous
		return err
	}
	return nil
}

func (s *Session) persistLocked() error {
	if err := validateJournal(s.journal); err != nil {
		return err
	}
	body, err := json.Marshal(s.journal)
	if err != nil || len(body) > maximumJournal {
		return errors.Join(ErrInvalid, err)
	}
	return atomicfile.Write(s.path, append(body, '\n'), atomicfile.CurrentOwnerOptions(0o600))
}

func decodeJournal(body []byte) (Journal, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var journal Journal
	if err := decoder.Decode(&journal); err != nil {
		return Journal{}, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || validateJournal(journal) != nil {
		return Journal{}, ErrInvalid
	}
	return journal, nil
}

func validateConfig(config Config) error {
	if !filepath.IsAbs(config.StateRoot) || filepath.Clean(config.StateRoot) != config.StateRoot || !validToken(config.HostID) || !validDigest(config.NameDigest) || !validDigest(config.RequestDigest) || config.DomainCount < 0 || config.DomainCount > maximumDomains || config.NewKey == nil {
		return ErrInvalid
	}
	if config.ExpiresAt != nil && (config.ExpiresAt.IsZero() || config.ExpiresAt.Location() != time.UTC) {
		return ErrInvalid
	}
	return nil
}

func validateJournal(journal Journal) error {
	if journal.Schema != Schema || !validToken(journal.HostID) || !validDigest(journal.RequestDigest) || !validToken(journal.TunnelKey) || len(journal.Domains) > maximumDomains || !validStage(journal.Stage) {
		return ErrInvalid
	}
	if journal.ExpiresAt != nil && (journal.ExpiresAt.IsZero() || journal.ExpiresAt.Location() != time.UTC) {
		return ErrInvalid
	}
	if (journal.TunnelID == "") != (journal.OperationID == "") || journal.TunnelID != "" && (!validToken(journal.TunnelID) || !validToken(journal.OperationID)) {
		return ErrInvalid
	}
	if journal.Stage == StagePrepared && journal.TunnelID != "" || journal.Stage != StagePrepared && journal.TunnelID == "" {
		return ErrInvalid
	}
	readyDomains := 0
	for _, domain := range journal.Domains {
		if !validToken(domain.Key) || domain.ID != "" && !validToken(domain.ID) || !validStage(domain.Stage) {
			return ErrInvalid
		}
		if domain.ID == "" && domain.Stage != StagePrepared || domain.ID != "" && domain.Stage != StageDomainsReady {
			return ErrInvalid
		}
		if domain.ID != "" {
			readyDomains++
		}
	}
	switch journal.Stage {
	case StagePrepared, StageTunnelCreated:
		// Domain creation cannot begin until the connector is ready. A journal
		// at either pre-connector stage must therefore contain no domain IDs.
		if readyDomains != 0 {
			return ErrInvalid
		}
	case StageConnectorReady:
		// Domain IDs are recorded one at a time. Partial progress is durable
		// and is the expected restart/retry state for multi-domain creates.
	case StageDomainsReady:
		if len(journal.Domains) == 0 || readyDomains != len(journal.Domains) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func canComplete(journal Journal) bool {
	// A prepared journal represents an attempt that has not changed durable
	// control-plane state yet. It is safe to remove after a deterministic
	// request rejection such as a name conflict. Once a tunnel ID exists, the
	// journal must only be completed after the connector and every requested
	// domain have reached their recorded terminal creation stages.
	if journal.TunnelID == "" {
		return journal.Stage == StagePrepared
	}
	if journal.Stage == StagePrepared || journal.Stage == StageTunnelCreated {
		return false
	}
	if len(journal.Domains) == 0 {
		return journal.Stage == StageConnectorReady
	}
	return journal.Stage == StageDomainsReady
}

func validStage(stage Stage) bool {
	return stage == StagePrepared || stage == StageTunnelCreated || stage == StageConnectorReady || stage == StageDomainsReady
}

func validToken(value string) bool {
	if len(value) < 3 || len(value) > 256 || value != strings.TrimSpace(value) || strings.ContainsAny(value, " /\\?#%") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || character > 0x7e {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func cloneJournal(journal Journal) Journal {
	journal.ExpiresAt = cloneTime(journal.ExpiresAt)
	journal.Domains = append([]Domain(nil), journal.Domains...)
	return journal
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}
