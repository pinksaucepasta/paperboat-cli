package hoststate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
)

const (
	primaryFile = "state.json"
	backupFile  = "state.backup.json"
	stagingFile = "state.next.json"
	lockFile    = "state.lock"
)

var (
	ErrLocked       = errors.New("host state is locked by another process")
	ErrConflict     = errors.New("host state revision conflict")
	ErrCorrupt      = errors.New("host state is corrupt")
	ErrIncompatible = errors.New("host state schema is newer than this runtime")
	ErrClosed       = errors.New("host state store is closed")
	ErrUncertain    = errors.New("host state commit outcome is uncertain")
)

type Phase string

const (
	PhaseCommitStaged             Phase = "commit_staged"
	PhaseCommitBackupSynced       Phase = "commit_backup_synced"
	PhaseCommitPrimarySynced      Phase = "commit_primary_synced"
	PhaseCommitCleanupSynced      Phase = "commit_cleanup_synced"
	PhaseMigrationSourcePreserved Phase = "migration_source_preserved"
	PhaseMigrationStaged          Phase = "migration_staged"
	PhaseMigrationPrimarySynced   Phase = "migration_primary_synced"
	PhaseMigrationBackupSynced    Phase = "migration_backup_synced"
	PhaseMigrationCleanupSynced   Phase = "migration_cleanup_synced"
	PhaseRecoveryCorruptionSaved  Phase = "recovery_corruption_preserved"
	PhaseRecoveryBackupRestored   Phase = "recovery_backup_restored"
	PhaseRecoveryIncompleteSaved  Phase = "recovery_incomplete_preserved"
)

type FailureHook func(Phase) error

type Config struct {
	Root        string
	Clock       func() time.Time
	FailureHook FailureHook
}

type StartupStatus struct {
	Degraded       bool     `json:"degraded"`
	Code           string   `json:"code"`
	Source         string   `json:"source"`
	PreservedPaths []string `json:"preserved_paths,omitempty"`
}

type CommitError struct {
	Phase   Phase
	Changed bool
	Err     error
}

func (e *CommitError) Error() string {
	outcome := "unchanged"
	if e.Changed {
		outcome = "uncertain"
	}
	return fmt.Sprintf("host state commit failed at %s (%s): %v", e.Phase, outcome, e.Err)
}

func (e *CommitError) Unwrap() error {
	if e.Changed {
		return errors.Join(ErrUncertain, e.Err)
	}
	return e.Err
}

type document struct {
	Schema        string    `json:"schema"`
	SchemaVersion int       `json:"schema_version"`
	Revision      uint64    `json:"revision"`
	WrittenAt     time.Time `json:"written_at"`
	State         State     `json:"state"`
	Checksum      string    `json:"checksum"`
}

type unsignedDocument struct {
	Schema        string    `json:"schema"`
	SchemaVersion int       `json:"schema_version"`
	Revision      uint64    `json:"revision"`
	WrittenAt     time.Time `json:"written_at"`
	State         State     `json:"state"`
}

// legacyDocumentV0 is the only bounded development-state migration. It
// predates checksums but already contained reference-only State values.
type legacyDocumentV0 struct {
	Schema        string    `json:"schema"`
	SchemaVersion int       `json:"schema_version"`
	Revision      uint64    `json:"revision"`
	WrittenAt     time.Time `json:"written_at"`
	State         State     `json:"state"`
}

type Store struct {
	mu        sync.RWMutex
	root      string
	primary   string
	backup    string
	staging   string
	lock      *processLock
	now       func() time.Time
	hook      FailureHook
	document  document
	status    StartupStatus
	closed    bool
	uncertain bool
}

func Open(config Config) (_ *Store, status StartupStatus, resultErr error) {
	status = StartupStatus{Code: "ready", Source: "primary"}
	root := filepath.Clean(config.Root)
	if !filepath.IsAbs(root) || root != config.Root {
		return nil, status, ErrInvalidState
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if err := ensurePrivateDirectory(root); err != nil {
		return nil, status, err
	}
	lock, err := acquireProcessLock(filepath.Join(root, lockFile))
	if err != nil {
		return nil, status, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, lock.Close())
		}
	}()
	store := &Store{
		root: root, primary: filepath.Join(root, primaryFile),
		backup: filepath.Join(root, backupFile), staging: filepath.Join(root, stagingFile),
		lock: lock, now: config.Clock, hook: config.FailureHook, status: status,
	}
	if err := store.recoverIncomplete(&status); err != nil {
		return nil, status, err
	}
	primary := store.readCandidate(store.primary)
	backup := store.readCandidate(store.backup)

	if errors.Is(primary.err, ErrIncompatible) {
		return nil, status, primary.err
	}
	if primary.legacy != nil {
		if errors.Is(backup.err, ErrIncompatible) {
			return nil, status, backup.err
		}
		if backup.exists && backup.raw == nil {
			status.Degraded, status.Code, status.Source = true, "backup_unreadable", "none"
			return nil, status, ErrCorrupt
		}
		if backup.err == nil && backup.exists && backup.legacy == nil {
			status.Degraded, status.Code, status.Source = true, "legacy_primary_with_current_backup", "none"
			return nil, status, ErrCorrupt
		}
		if backup.err != nil && backup.exists {
			preserved, preserveErr := store.preserve("corrupt-backup", backup.raw, PhaseRecoveryCorruptionSaved)
			if preserveErr != nil {
				return nil, status, preserveErr
			}
			status.Degraded, status.Code = true, "backup_corrupt_before_migration"
			status.PreservedPaths = append(status.PreservedPaths, preserved)
		}
		if err := store.migrate(primary.raw, *primary.legacy, &status); err != nil {
			return nil, status, err
		}
		store.status = status
		return store, status, nil
	}
	if primary.err == nil && primary.exists {
		if errors.Is(backup.err, ErrIncompatible) {
			return nil, status, backup.err
		}
		store.document = primary.document
		backupNeedsRepair := backup.err != nil || !backup.exists || backup.legacy != nil
		if backup.err != nil && backup.exists {
			preserved, preserveErr := store.preserve("corrupt-backup", backup.raw, PhaseRecoveryCorruptionSaved)
			if preserveErr != nil {
				return nil, status, preserveErr
			}
			status.PreservedPaths = append(status.PreservedPaths, preserved)
			status.Degraded, status.Code = true, "backup_corrupt_repaired"
		}
		if backup.legacy != nil {
			preserved, preserveErr := store.preserve("legacy-backup", backup.raw, PhaseRecoveryCorruptionSaved)
			if preserveErr != nil {
				return nil, status, preserveErr
			}
			status.PreservedPaths = append(status.PreservedPaths, preserved)
			status.Degraded, status.Code = true, "backup_legacy_repaired"
		}
		if backup.err == nil && backup.exists && backup.legacy == nil {
			switch {
			case backup.document.Revision > primary.document.Revision:
				status.Degraded, status.Code, status.Source = true, "backup_revision_ahead", "none"
				return nil, status, ErrCorrupt
			case backup.document.Revision == primary.document.Revision && backup.document.Checksum != primary.document.Checksum:
				status.Degraded, status.Code, status.Source = true, "primary_backup_diverged", "none"
				return nil, status, ErrCorrupt
			case backup.document.Revision < primary.document.Revision && primary.document.Revision-backup.document.Revision > 1:
				preserved, preserveErr := store.preserve("stale-backup", backup.raw, PhaseRecoveryCorruptionSaved)
				if preserveErr != nil {
					return nil, status, preserveErr
				}
				status.PreservedPaths = append(status.PreservedPaths, preserved)
				status.Degraded, status.Code = true, "backup_stale_repaired"
				backupNeedsRepair = true
			}
		}
		if !backup.exists {
			status.Degraded, status.Code = true, "backup_missing_repaired"
		}
		if backupNeedsRepair {
			if err := store.writeDurable(store.backup, primary.raw); err != nil {
				return nil, status, err
			}
		}
		store.status = status
		return store, status, nil
	}

	if primary.exists && primary.raw == nil {
		status.Degraded, status.Code, status.Source = true, "primary_unreadable", "none"
		return nil, status, ErrCorrupt
	}
	if primary.exists {
		preserved, preserveErr := store.preserve("corrupt-primary", primary.raw, PhaseRecoveryCorruptionSaved)
		if preserveErr != nil {
			return nil, status, preserveErr
		}
		status.PreservedPaths = append(status.PreservedPaths, preserved)
	}
	if errors.Is(backup.err, ErrIncompatible) {
		return nil, status, backup.err
	}
	if backup.legacy != nil {
		status.Degraded, status.Code, status.Source = true, "primary_recovered_from_legacy_backup", "backup"
		if err := store.migrate(backup.raw, *backup.legacy, &status); err != nil {
			return nil, status, err
		}
		store.status = status
		return store, status, nil
	}
	if backup.err == nil && backup.exists {
		if err := store.writeDurable(store.primary, backup.raw); err != nil {
			return nil, status, err
		}
		if err := store.runHook(PhaseRecoveryBackupRestored); err != nil {
			return nil, status, err
		}
		status.Degraded, status.Source = true, "backup"
		if primary.exists {
			status.Code = "primary_corrupt_recovered_from_backup"
		} else {
			status.Code = "primary_missing_recovered_from_backup"
		}
		store.document, store.status = backup.document, status
		return store, status, nil
	}
	if backup.exists && backup.raw == nil {
		status.Degraded, status.Code, status.Source = true, "backup_unreadable", "none"
		return nil, status, ErrCorrupt
	}
	if backup.exists {
		preserved, preserveErr := store.preserve("corrupt-backup", backup.raw, PhaseRecoveryCorruptionSaved)
		if preserveErr != nil {
			return nil, status, preserveErr
		}
		status.PreservedPaths = append(status.PreservedPaths, preserved)
		status.Degraded, status.Code, status.Source = true, "primary_and_backup_unusable", "none"
		return nil, status, ErrCorrupt
	}
	if primary.exists {
		status.Degraded, status.Code, status.Source = true, "primary_corrupt_without_backup", "none"
		return nil, status, ErrCorrupt
	}

	doc, raw, err := sealDocument(State{}, 1, config.Clock())
	if err != nil {
		return nil, status, err
	}
	if err := store.publishInitial(raw); err != nil {
		return nil, status, err
	}
	status.Code, status.Source = "initialized", "initial"
	store.document, store.status = doc, status
	return store, status, nil
}

func (s *Store) Snapshot() (State, uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return State{}, 0, ErrClosed
	}
	if s.uncertain {
		return State{}, 0, ErrUncertain
	}
	return cloneState(s.document.State), s.document.Revision, nil
}

func (s *Store) StartupStatus() StartupStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	status := s.status
	status.PreservedPaths = append([]string(nil), status.PreservedPaths...)
	return status
}

func (s *Store) Commit(expectedRevision uint64, next State) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrClosed
	}
	if s.uncertain {
		return 0, ErrUncertain
	}
	if expectedRevision != s.document.Revision {
		return 0, ErrConflict
	}
	next = normalizeState(next)
	if err := next.Validate(); err != nil {
		return 0, err
	}
	writtenAt := s.now().UTC()
	if writtenAt.Before(s.document.WrittenAt) {
		writtenAt = s.document.WrittenAt
	}
	doc, raw, err := sealDocument(next, expectedRevision+1, writtenAt)
	if err != nil {
		return 0, err
	}
	if err := s.writeDurable(s.staging, raw); err != nil {
		return 0, &CommitError{Phase: PhaseCommitStaged, Err: err}
	}
	if err := s.runHook(PhaseCommitStaged); err != nil {
		return 0, &CommitError{Phase: PhaseCommitStaged, Err: err}
	}
	currentRaw, err := encodeDocument(s.document)
	if err != nil {
		return 0, &CommitError{Phase: PhaseCommitBackupSynced, Err: err}
	}
	if err := s.writeDurable(s.backup, currentRaw); err != nil {
		return 0, &CommitError{Phase: PhaseCommitBackupSynced, Err: err}
	}
	if err := s.runHook(PhaseCommitBackupSynced); err != nil {
		return 0, &CommitError{Phase: PhaseCommitBackupSynced, Err: err}
	}
	if err := s.writeDurable(s.primary, raw); err != nil {
		changed := atomicWriteMayHaveChanged(err)
		s.uncertain = changed
		return 0, &CommitError{Phase: PhaseCommitPrimarySynced, Changed: changed, Err: err}
	}
	if err := s.runHook(PhaseCommitPrimarySynced); err != nil {
		s.uncertain = true
		return 0, &CommitError{Phase: PhaseCommitPrimarySynced, Changed: true, Err: err}
	}
	if err := s.removeStaging(); err != nil {
		s.uncertain = true
		return 0, &CommitError{Phase: PhaseCommitCleanupSynced, Changed: true, Err: err}
	}
	if err := s.runHook(PhaseCommitCleanupSynced); err != nil {
		s.uncertain = true
		return 0, &CommitError{Phase: PhaseCommitCleanupSynced, Changed: true, Err: err}
	}
	s.document = doc
	return doc.Revision, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.lock.Close()
}

type candidate struct {
	exists   bool
	raw      []byte
	document document
	legacy   *legacyDocumentV0
	err      error
}

func (s *Store) readCandidate(name string) candidate {
	raw, err := readPrivateFile(name, MaxStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return candidate{}
	}
	if err != nil {
		return candidate{exists: true, err: fmt.Errorf("%w: %s: %v", ErrCorrupt, name, err)}
	}
	doc, legacy, err := decodeAnyDocument(raw)
	return candidate{exists: true, raw: raw, document: doc, legacy: legacy, err: err}
}

func (s *Store) publishInitial(raw []byte) error {
	if err := s.writeDurable(s.staging, raw); err != nil {
		return &CommitError{Phase: PhaseCommitStaged, Err: err}
	}
	if err := s.runHook(PhaseCommitStaged); err != nil {
		return &CommitError{Phase: PhaseCommitStaged, Err: err}
	}
	if err := s.writeDurable(s.primary, raw); err != nil {
		return &CommitError{Phase: PhaseCommitPrimarySynced, Changed: atomicWriteMayHaveChanged(err), Err: err}
	}
	if err := s.runHook(PhaseCommitPrimarySynced); err != nil {
		return &CommitError{Phase: PhaseCommitPrimarySynced, Changed: true, Err: err}
	}
	if err := s.writeDurable(s.backup, raw); err != nil {
		return &CommitError{Phase: PhaseCommitBackupSynced, Changed: true, Err: err}
	}
	if err := s.runHook(PhaseCommitBackupSynced); err != nil {
		return &CommitError{Phase: PhaseCommitBackupSynced, Changed: true, Err: err}
	}
	if err := s.removeStaging(); err != nil {
		return &CommitError{Phase: PhaseCommitCleanupSynced, Changed: true, Err: err}
	}
	if err := s.runHook(PhaseCommitCleanupSynced); err != nil {
		return &CommitError{Phase: PhaseCommitCleanupSynced, Changed: true, Err: err}
	}
	return nil
}

func (s *Store) migrate(source []byte, legacy legacyDocumentV0, status *StartupStatus) error {
	if err := legacy.State.Validate(); err != nil {
		return fmt.Errorf("%w: legacy state: %v", ErrCorrupt, err)
	}
	preserved, err := s.preserve("migration-v0", source, PhaseMigrationSourcePreserved)
	if err != nil {
		return err
	}
	status.PreservedPaths = append(status.PreservedPaths, preserved)
	revision := legacy.Revision
	if revision == 0 {
		revision = 1
	}
	writtenAt := s.now().UTC()
	if writtenAt.Before(legacy.WrittenAt) {
		writtenAt = legacy.WrittenAt.UTC()
	}
	doc, raw, err := sealDocument(legacy.State, revision, writtenAt)
	if err != nil {
		return err
	}
	if err := s.writeDurable(s.staging, raw); err != nil {
		return &CommitError{Phase: PhaseMigrationStaged, Err: err}
	}
	if err := s.runHook(PhaseMigrationStaged); err != nil {
		return &CommitError{Phase: PhaseMigrationStaged, Err: err}
	}
	if err := s.writeDurable(s.primary, raw); err != nil {
		return &CommitError{Phase: PhaseMigrationPrimarySynced, Changed: atomicWriteMayHaveChanged(err), Err: err}
	}
	if err := s.runHook(PhaseMigrationPrimarySynced); err != nil {
		return &CommitError{Phase: PhaseMigrationPrimarySynced, Changed: true, Err: err}
	}
	if err := s.writeDurable(s.backup, raw); err != nil {
		return &CommitError{Phase: PhaseMigrationBackupSynced, Changed: true, Err: err}
	}
	if err := s.runHook(PhaseMigrationBackupSynced); err != nil {
		return &CommitError{Phase: PhaseMigrationBackupSynced, Changed: true, Err: err}
	}
	if err := s.removeStaging(); err != nil {
		return &CommitError{Phase: PhaseMigrationCleanupSynced, Changed: true, Err: err}
	}
	if err := s.runHook(PhaseMigrationCleanupSynced); err != nil {
		return &CommitError{Phase: PhaseMigrationCleanupSynced, Changed: true, Err: err}
	}
	status.Code, status.Source = "migrated_v0_to_v1", "migration"
	s.document = doc
	return nil
}

func (s *Store) recoverIncomplete(status *StartupStatus) error {
	raw, err := readPrivateFile(s.staging, MaxStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: incomplete state: %v", ErrCorrupt, err)
	}
	preserved, err := s.preserve("incomplete-commit", raw, PhaseRecoveryIncompleteSaved)
	if err != nil {
		return err
	}
	if err := os.Remove(s.staging); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncDirectory(s.root); err != nil {
		return err
	}
	status.Degraded, status.Code = true, "incomplete_commit_preserved"
	status.PreservedPaths = append(status.PreservedPaths, preserved)
	return nil
}

func (s *Store) preserve(kind string, raw []byte, phase Phase) (string, error) {
	digest := sha256.Sum256(raw)
	name := filepath.Join(s.root, "state."+kind+"."+hex.EncodeToString(digest[:8])+".preserved.json")
	if existing, err := readPrivateFile(name, MaxStateBytes); err == nil {
		if !bytes.Equal(existing, raw) {
			return "", ErrCorrupt
		}
		if err := s.runHook(phase); err != nil {
			return "", &CommitError{Phase: phase, Err: err}
		}
		return name, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := s.writeDurable(name, raw); err != nil {
		return "", &CommitError{Phase: phase, Err: err}
	}
	if err := s.runHook(phase); err != nil {
		return "", &CommitError{Phase: phase, Err: err}
	}
	return name, nil
}

func (s *Store) writeDurable(name string, raw []byte) error {
	return atomicfile.Write(name, raw, atomicfile.CurrentOwnerOptions(0o600))
}

func (s *Store) removeStaging() error {
	if err := os.Remove(s.staging); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(s.root)
}

func (s *Store) runHook(phase Phase) error {
	if s.hook == nil {
		return nil
	}
	return s.hook(phase)
}

func sealDocument(state State, revision uint64, writtenAt time.Time) (document, []byte, error) {
	state = normalizeState(state)
	if revision == 0 || writtenAt.IsZero() || state.Validate() != nil {
		return document{}, nil, ErrInvalidState
	}
	unsigned := unsignedDocument{Schema: Schema, SchemaVersion: SchemaVersion, Revision: revision, WrittenAt: writtenAt.UTC(), State: state}
	canonical, err := json.Marshal(unsigned)
	if err != nil {
		return document{}, nil, err
	}
	digest := sha256.Sum256(canonical)
	doc := document{Schema: unsigned.Schema, SchemaVersion: unsigned.SchemaVersion, Revision: unsigned.Revision, WrittenAt: unsigned.WrittenAt, State: unsigned.State, Checksum: "sha256:" + hex.EncodeToString(digest[:])}
	raw, err := encodeDocument(doc)
	return doc, raw, err
}

func encodeDocument(doc document) ([]byte, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	if len(raw)+1 > MaxStateBytes {
		return nil, ErrInvalidState
	}
	return append(raw, '\n'), nil
}

func decodeAnyDocument(raw []byte) (document, *legacyDocumentV0, error) {
	if len(raw) == 0 || len(raw) > MaxStateBytes {
		return document{}, nil, ErrCorrupt
	}
	if err := validateSingleJSON(raw); err != nil {
		return document{}, nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	var header struct {
		Schema        string `json:"schema"`
		SchemaVersion int    `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil || header.Schema != Schema {
		return document{}, nil, ErrCorrupt
	}
	if header.SchemaVersion > SchemaVersion {
		return document{}, nil, ErrIncompatible
	}
	if header.SchemaVersion == 0 {
		var legacy legacyDocumentV0
		if err := decodeStrict(raw, &legacy); err != nil || legacy.Schema != Schema || legacy.SchemaVersion != 0 || legacy.State.Validate() != nil {
			return document{}, nil, ErrCorrupt
		}
		return document{}, &legacy, nil
	}
	if header.SchemaVersion != SchemaVersion {
		return document{}, nil, ErrCorrupt
	}
	var doc document
	if err := decodeStrict(raw, &doc); err != nil || doc.Schema != Schema || doc.SchemaVersion != SchemaVersion || doc.Revision == 0 || doc.WrittenAt.IsZero() || doc.State.Validate() != nil {
		return document{}, nil, ErrCorrupt
	}
	unsigned := unsignedDocument{Schema: doc.Schema, SchemaVersion: doc.SchemaVersion, Revision: doc.Revision, WrittenAt: doc.WrittenAt, State: doc.State}
	canonical, err := json.Marshal(unsigned)
	if err != nil {
		return document{}, nil, ErrCorrupt
	}
	digest := sha256.Sum256(canonical)
	if doc.Checksum != "sha256:"+hex.EncodeToString(digest[:]) {
		return document{}, nil, ErrCorrupt
	}
	doc.State = normalizeState(doc.State)
	return doc, nil, nil
}

func decodeStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrCorrupt
	}
	return nil
}

func validateSingleJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if _, err := decodeJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrCorrupt
	}
	return nil
}

func atomicWriteMayHaveChanged(err error) bool {
	var atomicErr *atomicfile.Error
	return errors.As(err, &atomicErr) && atomicErr.Stage == atomicfile.StageSyncDir
}
