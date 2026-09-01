package envinject

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/environmentkey"
)

const (
	ObservationSchema = "paperboat.environment-observation/v2"
	BundleSchema      = "paperboat.environment-bundle/v2"
	cacheSchema       = "paperboat.environment-host-cache/v2"
	highWaterSchema   = "paperboat.environment-host-high-water/v1"

	MaximumVariables        = 128
	MaximumNameBytes        = 128
	MaximumValueBytes       = 32<<10 - 1
	MaximumEnvironmentBytes = 256 << 10
	maximumCacheBytes       = 8 << 20
)

var (
	ErrInvalidSnapshot = errors.New("invalid encrypted environment state")
	ErrNotReady        = errors.New("encrypted environment is not ready")
	ErrRevoked         = errors.New("environment host authorization is revoked")
	ErrObservationLost = errors.New("environment observation counter is unavailable")

	variableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type Cursor struct {
	Generation  uint64 `json:"generation"`
	AuthorityID string `json:"authority_id"`
}

type ManifestCursor struct {
	Version    uint64 `json:"version"`
	KeyEpoch   uint64 `json:"key_epoch"`
	ManifestID string `json:"manifest_id"`
}

type Observation struct {
	Schema             string          `json:"schema"`
	ObservationSeq     uint64          `json:"observation_seq"`
	HostRecipientKeyID string          `json:"host_recipient_key_id"`
	Authority          *Cursor         `json:"authority"`
	Global             *ManifestCursor `json:"global"`
	Machine            *ManifestCursor `json:"machine"`
	State              string          `json:"state"`
	ErrorCode          *string         `json:"error_code"`
	ObservedAt         time.Time       `json:"observed_at"`
}

type ManifestEnvelope struct {
	Version    uint64 `json:"version"`
	KeyEpoch   uint64 `json:"key_epoch"`
	ManifestID string `json:"manifest_id"`
	Envelope   string `json:"envelope"`
}

type AuthorizationBootstrap struct {
	Authority       Cursor           `json:"authority"`
	GlobalManifest  ManifestEnvelope `json:"global_manifest"`
	MachineManifest ManifestEnvelope `json:"machine_manifest"`
}

type Bundle struct {
	Schema             string                  `json:"schema"`
	AuthorityHead      Cursor                  `json:"authority_head"`
	AuthorityDocuments []string                `json:"authority_documents"`
	AuthorityHasMore   bool                    `json:"authority_has_more"`
	RevocationOnly     bool                    `json:"revocation_only"`
	Bootstrap          *AuthorizationBootstrap `json:"authorization_bootstrap"`
	GlobalManifest     *ManifestEnvelope       `json:"global_manifest"`
	MachineManifest    *ManifestEnvelope       `json:"machine_manifest"`
}

// DecodeBundle rejects duplicate and unknown members before any trust or
// ciphertext processing. The caller remains responsible for bounding raw.
func DecodeBundle(raw []byte) (Bundle, error) {
	if len(raw) == 0 || len(raw) > maximumCacheBytes || rejectDuplicateJSON(raw) != nil {
		return Bundle{}, ErrInvalidSnapshot
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || len(members) != 8 {
		return Bundle{}, ErrInvalidSnapshot
	}
	for _, name := range []string{"schema", "authority_head", "authority_documents", "authority_has_more", "revocation_only", "authorization_bootstrap", "global_manifest", "machine_manifest"} {
		if _, ok := members[name]; !ok {
			return Bundle{}, ErrInvalidSnapshot
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, ErrInvalidSnapshot
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || bundle.Schema != BundleSchema {
		return Bundle{}, ErrInvalidSnapshot
	}
	return bundle, nil
}

// DecodeRuntimeResponse extracts the optional encrypted bundle while allowing
// unrelated runtime response fields owned by other subsystems. Duplicate JSON
// members anywhere in the response are rejected before selection.
func DecodeRuntimeResponse(raw []byte) (*Bundle, error) {
	if len(raw) == 0 || len(raw) > maximumCacheBytes || rejectDuplicateJSON(raw) != nil {
		return nil, ErrInvalidSnapshot
	}
	var envelope struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Data == nil {
		return nil, ErrInvalidSnapshot
	}
	bundleRaw, present := envelope.Data["environment_bundle"]
	if !present || bytes.Equal(bundleRaw, []byte("null")) {
		return nil, nil
	}
	bundle, err := DecodeBundle(bundleRaw)
	if err != nil {
		return nil, err
	}
	return &bundle, nil
}

// Cache contains public trust documents, signed ciphertext manifests, and
// anti-rollback metadata only. It must never contain a decrypted value or key.
type Cache struct {
	Schema                 string            `json:"schema"`
	AccountID              string            `json:"account_id"`
	MachineID              string            `json:"machine_id"`
	InstallationGeneration uint64            `json:"installation_generation"`
	HostKeyGeneration      uint64            `json:"host_key_generation"`
	HostRecipientKeyID     string            `json:"host_recipient_key_id"`
	ObservationSeq         uint64            `json:"observation_seq"`
	Authority              *Cursor           `json:"authority"`
	AuthorityDocuments     []string          `json:"authority_documents,omitempty"`
	GlobalManifest         *ManifestEnvelope `json:"global_manifest,omitempty"`
	MachineManifest        *ManifestEnvelope `json:"machine_manifest,omitempty"`
	Revoked                bool              `json:"revoked"`
}

type highWater struct {
	Schema                 string          `json:"schema"`
	AccountID              string          `json:"account_id"`
	MachineID              string          `json:"machine_id"`
	InstallationGeneration uint64          `json:"installation_generation"`
	HostKeyGeneration      uint64          `json:"host_key_generation"`
	HostRecipientKeyID     string          `json:"host_recipient_key_id"`
	CacheHash              string          `json:"cache_hash"`
	ObservationSeq         uint64          `json:"observation_seq"`
	Authority              *Cursor         `json:"authority"`
	Global                 *ManifestCursor `json:"global"`
	Machine                *ManifestCursor `json:"machine"`
}

type highWaterRecord struct {
	Schema  string     `json:"schema"`
	Active  highWater  `json:"active"`
	Pending *highWater `json:"pending"`
}

type authenticatedHighWater struct {
	Record highWaterRecord `json:"record"`
	MAC    string          `json:"mac"`
}

type Verified struct {
	Authority *Cursor
	Global    *ManifestCursor
	Machine   *ManifestCursor
	Variables map[string]string
	Revoked   bool
	Ready     bool
}

// BindingState describes only evidence obtained from a verified runtime
// bundle. A cached authority cursor by itself is not proof that this host is
// still bound because a later authority may have removed it.
type BindingState uint8

const (
	BindingUnknown BindingState = iota
	BindingActive
	BindingInactive
)

// Processor owns all canonical parsing, trust validation, HPKE opening, and
// payload decryption. Store owns ordering, crash-safe persistence, and the
// last-good in-memory swap.
type Processor interface {
	Restore(context.Context, Cache) (Verified, error)
	Apply(context.Context, Cache, Bundle) (Cache, Verified, error)
}

type Config struct {
	Path                     string
	HighWaterPath            string
	IntegrityKey             []byte
	AllowHighWaterInitialize bool
	AccountID                string
	MachineID                string
	InstallationGeneration   uint64
	HostKeyGeneration        uint64
	HostRecipientKeyID       string
	GenesisMarker            environmentkey.GenesisMarker
	Processor                Processor
}

type Store struct {
	mu              sync.RWMutex
	config          Config
	cache           Cache
	verified        Verified
	binding         BindingState
	highWater       highWater
	state           string
	errorCode       string
	writeFailed     bool
	cacheWriter     func(string, Cache) error
	highWaterWriter func(string, []byte, highWaterRecord) error
}

// EnvironmentSource is the narrow new-process injection contract. Provider
// implements it before a host can finish key enrollment, so launches fail
// closed instead of silently starting without configured ENV.
type EnvironmentSource interface {
	Environment() ([]string, error)
}

// Provider permits the peer-identity enrollment worker to attach the ENV
// store without restarting the host service. Attachment is one-way.
type Provider struct {
	mu    sync.RWMutex
	store *Store
}

func (p *Provider) Attach(store *Store) error {
	if p == nil || store == nil {
		return ErrInvalidSnapshot
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.store != nil && p.store != store {
		return ErrInvalidSnapshot
	}
	p.store = store
	return nil
}

func (p *Provider) Environment() ([]string, error) {
	store := p.current()
	if store == nil {
		return nil, ErrNotReady
	}
	return store.Environment()
}

func (p *Provider) NextObservation(observedAt time.Time) (Observation, error) {
	store := p.current()
	if store == nil {
		return Observation{}, ErrNotReady
	}
	return store.NextObservation(observedAt)
}

func (p *Provider) Apply(ctx context.Context, bundle Bundle) error {
	store := p.current()
	if store == nil {
		return ErrNotReady
	}
	return store.Apply(ctx, bundle)
}

func (p *Provider) current() *Store {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.store
}

func Open(ctx context.Context, config Config) (*Store, error) {
	if ctx == nil || !validConfig(config) {
		return nil, ErrInvalidSnapshot
	}
	config.IntegrityKey = append([]byte(nil), config.IntegrityKey...)
	genesisState, genesisErr := config.GenesisMarker.GenesisState()
	if genesisErr != nil {
		return nil, errors.Join(ErrObservationLost, genesisErr)
	}
	store := &Store{config: config, state: "pending", cacheWriter: writeCache, highWaterWriter: writeHighWater, cache: Cache{
		Schema: cacheSchema, AccountID: config.AccountID, MachineID: config.MachineID,
		InstallationGeneration: config.InstallationGeneration, HostKeyGeneration: config.HostKeyGeneration,
		HostRecipientKeyID: config.HostRecipientKeyID,
	}}
	record, highWaterErr := loadHighWater(config.HighWaterPath, config.IntegrityKey)
	cache, err := loadCache(config.Path)
	if errors.Is(err, os.ErrNotExist) {
		if errors.Is(highWaterErr, os.ErrNotExist) {
			if !config.AllowHighWaterInitialize || genesisState != environmentkey.GenesisFresh && genesisState != environmentkey.GenesisPending {
				return nil, ErrObservationLost
			}
			// Persist (or re-validate) the secure marker's in-progress transition
			// before creating the first local high-water record. A crash after that
			// write cannot make a later missing marker look like a fresh
			// installation. A pending marker with neither state file is the
			// recoverable continuation of this exact pre-bootstrap window.
			if prepareErr := config.GenesisMarker.PrepareGenesis(); prepareErr != nil {
				return nil, errors.Join(ErrObservationLost, prepareErr)
			}
			record = initialHighWaterRecord(store.cache)
			if writeErr := store.highWaterWriter(config.HighWaterPath, config.IntegrityKey, record); writeErr != nil {
				return nil, errors.Join(ErrObservationLost, writeErr)
			}
			if commitErr := config.GenesisMarker.CommitGenesis(); commitErr != nil {
				return nil, errors.Join(ErrObservationLost, commitErr)
			}
		} else if highWaterErr != nil || !highWaterEmpty(record.Active) {
			return nil, errors.Join(ErrObservationLost, highWaterErr)
		} else {
			// The high-water file is durable but the process may have stopped
			// between its commit and the secure marker transition.
			switch genesisState {
			case environmentkey.GenesisPending:
				if commitErr := config.GenesisMarker.CommitGenesis(); commitErr != nil {
					return nil, errors.Join(ErrObservationLost, commitErr)
				}
			case environmentkey.GenesisEstablished:
			default:
				return nil, ErrObservationLost
			}
		}
		if record.Pending != nil {
			record.Pending = nil
			if writeErr := store.highWaterWriter(config.HighWaterPath, config.IntegrityKey, record); writeErr != nil {
				return nil, writeErr
			}
		}
		store.highWater = record.Active
		return store, nil
	}
	if err != nil || highWaterErr != nil || genesisState != environmentkey.GenesisEstablished || !sameIdentity(store.cache, cache) || !highWaterMatchesIdentity(record.Active, cache) {
		return nil, errors.Join(ErrInvalidSnapshot, err)
	}
	highWater := record.Active
	if cacheMatchesHighWater(cache, record.Active) {
		if record.Pending != nil {
			record.Pending = nil
			if writeErr := store.highWaterWriter(config.HighWaterPath, config.IntegrityKey, record); writeErr != nil {
				return nil, writeErr
			}
		}
	} else if record.Pending != nil && highWaterMatchesIdentity(*record.Pending, cache) && cacheMatchesHighWater(cache, *record.Pending) {
		highWater = cloneHighWater(*record.Pending)
		record.Active, record.Pending = highWater, nil
		if writeErr := store.highWaterWriter(config.HighWaterPath, config.IntegrityKey, record); writeErr != nil {
			return nil, writeErr
		}
	} else {
		return nil, ErrInvalidSnapshot
	}
	verified, err := config.Processor.Restore(ctx, cache)
	if err != nil || !validVerified(cache, verified) {
		return nil, errors.Join(ErrInvalidSnapshot, err)
	}
	store.cache, store.verified = cache, cloneVerified(verified)
	store.highWater = highWater
	if verified.Revoked {
		store.binding = BindingInactive
		store.state = "failed"
		store.errorCode = "authorization_revoked"
	} else if verified.Ready {
		store.binding = BindingActive
		store.state = "applied"
	}
	return store, nil
}

// NextObservation increments and persists the counter before returning the
// observation. A failed persistence never reuses or sends the next sequence.
func (s *Store) NextObservation(observedAt time.Time) (Observation, error) {
	if s == nil || observedAt.IsZero() {
		return Observation{}, ErrInvalidSnapshot
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeFailed {
		return Observation{}, ErrObservationLost
	}
	if s.cache.ObservationSeq >= math.MaxInt64 {
		return Observation{}, ErrObservationLost
	}
	next := s.cache
	next.ObservationSeq++
	nextHighWater := advanceHighWater(s.highWater, next)
	if err := s.highWaterWriter(s.config.HighWaterPath, s.config.IntegrityKey, transitionHighWaterRecord(s.highWater, nextHighWater)); err != nil {
		s.writeFailed = true
		return Observation{}, errors.Join(ErrObservationLost, err)
	}
	if err := s.cacheWriter(s.config.Path, next); err != nil {
		// Keep the authenticated pending intent. The cache writer may have
		// replaced the file before reporting a sync/close error. On restart,
		// Open either clears this intent with the old cache or promotes it to
		// the new cache. Continuing in this process would risk overwriting a
		// durable newer cache with stale memory.
		s.writeFailed = true
		return Observation{}, errors.Join(ErrObservationLost, err)
	}
	if err := s.highWaterWriter(s.config.HighWaterPath, s.config.IntegrityKey, finalHighWaterRecord(nextHighWater)); err != nil {
		s.writeFailed = true
		return Observation{}, errors.Join(ErrObservationLost, err)
	}
	s.cache = next
	s.highWater = nextHighWater
	return s.observationLocked(observedAt.UTC()), nil
}

func (s *Store) observationLocked(observedAt time.Time) Observation {
	state, errorCode := s.state, s.errorCode
	var code *string
	if state == "failed" && errorCode != "" {
		value := errorCode
		code = &value
	}
	return Observation{
		Schema: ObservationSchema, ObservationSeq: s.cache.ObservationSeq,
		HostRecipientKeyID: s.cache.HostRecipientKeyID, Authority: cloneCursor(s.verified.Authority),
		Global: cloneManifestCursor(s.verified.Global), Machine: cloneManifestCursor(s.verified.Machine),
		State: state, ErrorCode: code, ObservedAt: observedAt,
	}
}

// Apply verifies an entire response before persisting ciphertext and then
// atomically replaces the in-memory last-good environment.
func (s *Store) Apply(ctx context.Context, bundle Bundle) error {
	if s == nil || ctx == nil || bundle.Schema != BundleSchema {
		return ErrInvalidSnapshot
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeFailed {
		return ErrObservationLost
	}
	next, verified, err := s.config.Processor.Apply(ctx, cloneCache(s.cache), bundle)
	if err != nil || !sameIdentity(s.cache, next) || next.ObservationSeq != s.cache.ObservationSeq || cacheBehindHighWater(next, s.highWater) || !validVerified(next, verified) {
		s.state, s.errorCode = "failed", "integrity_failed"
		return errors.Join(ErrInvalidSnapshot, err)
	}
	nextHighWater := advanceHighWater(s.highWater, next)
	if err := s.highWaterWriter(s.config.HighWaterPath, s.config.IntegrityKey, transitionHighWaterRecord(s.highWater, nextHighWater)); err != nil {
		s.writeFailed = true
		s.state, s.errorCode = "failed", "cache_failed"
		return errors.Join(ErrObservationLost, err)
	}
	if err := s.cacheWriter(s.config.Path, next); err != nil {
		// Do not roll back the intent. See NextObservation: preserving it is
		// what lets restart reconcile either side of an uncertain atomic write.
		s.writeFailed = true
		s.state, s.errorCode = "failed", "cache_failed"
		return errors.Join(ErrObservationLost, err)
	}
	if err := s.highWaterWriter(s.config.HighWaterPath, s.config.IntegrityKey, finalHighWaterRecord(nextHighWater)); err != nil {
		s.writeFailed = true
		s.state, s.errorCode = "failed", "cache_failed"
		return errors.Join(ErrObservationLost, err)
	}
	s.cache = cloneCache(next)
	s.highWater = nextHighWater
	s.verified = cloneVerified(verified)
	if verified.Revoked {
		s.binding = BindingInactive
		s.state, s.errorCode = "failed", "authorization_revoked"
	} else if verified.Ready {
		s.binding = BindingActive
		s.state, s.errorCode = "applied", ""
	} else {
		// A non-revocation authority page is accepted only after the
		// processor has verified the exact host binding. Preserve that
		// evidence while scope manifests are delivered on a later poll.
		if len(bundle.AuthorityDocuments) > 0 && !bundle.RevocationOnly && verified.Authority != nil {
			s.binding = BindingActive
		}
		s.state, s.errorCode = "pending", ""
	}
	return nil
}

// BindingState returns the latest authenticated binding evidence. Unknown is
// returned until a fresh authority/bundle has been verified or a ready cache
// has been restored; local authority cursors are intentionally insufficient.
func (s *Store) BindingState() BindingState {
	if s == nil {
		return BindingUnknown
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.binding
}

func (p *Provider) BindingState() BindingState {
	store := p.current()
	if store == nil {
		return BindingUnknown
	}
	return store.BindingState()
}

// Environment returns a fresh copy only for a newly created process.
func (s *Store) Environment() ([]string, error) {
	if s == nil {
		return nil, ErrNotReady
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.verified.Revoked {
		return nil, ErrRevoked
	}
	if !s.verified.Ready {
		return nil, ErrNotReady
	}
	keys := sortedKeys(s.verified.Variables)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+s.verified.Variables[key])
	}
	return result, nil
}

func Merge(base, managed []string) ([]string, error) {
	values := make(map[string]string, len(base)+len(managed))
	canonicalNames := make(map[string]string, len(base)+len(managed))
	for _, entry := range base {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || !portableName(name) || strings.ContainsRune(value, '\x00') || !utf8.ValidString(value) {
			return nil, ErrInvalidSnapshot
		}
		folded := strings.ToUpper(name)
		if prior := canonicalNames[folded]; prior != "" && prior != name {
			return nil, ErrInvalidSnapshot
		}
		canonicalNames[folded] = name
		values[name] = value
	}
	managedNames := make(map[string]struct{}, len(managed))
	for _, entry := range managed {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || !ValidName(name) || len(value) > MaximumValueBytes || strings.ContainsRune(value, '\x00') || !utf8.ValidString(value) {
			return nil, ErrInvalidSnapshot
		}
		outputName := name
		folded := strings.ToUpper(name)
		if _, duplicate := managedNames[folded]; duplicate {
			return nil, ErrInvalidSnapshot
		}
		managedNames[folded] = struct{}{}
		if existing := canonicalNames[folded]; existing != "" {
			outputName = existing
		}
		canonicalNames[folded] = outputName
		values[outputName] = value
	}
	keys := sortedKeys(values)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result, nil
}

func ValidName(name string) bool {
	upper := strings.ToUpper(name)
	if !portableName(name) || strings.HasPrefix(upper, "PAPERBOAT_") || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") {
		return false
	}
	switch upper {
	case "NODE_OPTIONS", "PYTHONPATH", "PYTHONHOME", "GOTRACEBACK":
		return false
	default:
		return true
	}
}

func ValidateVariables(values map[string]string) error {
	if len(values) > MaximumVariables {
		return ErrInvalidSnapshot
	}
	total := 0
	folded := make(map[string]struct{}, len(values))
	for name, value := range values {
		total += len(name) + len(value)
		canonical := strings.ToUpper(name)
		_, duplicate := folded[canonical]
		if duplicate || !ValidName(name) || !utf8.ValidString(value) || len(value) > MaximumValueBytes || strings.ContainsRune(value, '\x00') || total > MaximumEnvironmentBytes {
			return ErrInvalidSnapshot
		}
		folded[canonical] = struct{}{}
	}
	return nil
}

func validConfig(config Config) bool {
	return filepath.IsAbs(config.Path) && filepath.Clean(config.Path) == config.Path && filepath.IsAbs(config.HighWaterPath) && filepath.Clean(config.HighWaterPath) == config.HighWaterPath && config.Path != config.HighWaterPath && len(config.IntegrityKey) == 32 && config.Processor != nil &&
		validIdentifier(config.AccountID) && validIdentifier(config.MachineID) && config.InstallationGeneration > 0 &&
		config.HostKeyGeneration > 0 && validKeyID(config.HostRecipientKeyID) && config.GenesisMarker != nil
}

func validVerified(cache Cache, value Verified) bool {
	if value.Revoked {
		return !value.Ready && len(value.Variables) == 0 && value.Authority != nil
	}
	if !value.Ready {
		return len(value.Variables) == 0
	}
	return value.Authority != nil && value.Global != nil && value.Machine != nil && ValidateVariables(value.Variables) == nil &&
		cache.GlobalManifest != nil && cache.MachineManifest != nil
}

func sameIdentity(left, right Cache) bool {
	return right.Schema == cacheSchema && left.AccountID == right.AccountID && left.MachineID == right.MachineID &&
		left.InstallationGeneration == right.InstallationGeneration && left.HostKeyGeneration == right.HostKeyGeneration &&
		left.HostRecipientKeyID == right.HostRecipientKeyID
}

func initialHighWater(cache Cache) highWater {
	return highWater{Schema: highWaterSchema, AccountID: cache.AccountID, MachineID: cache.MachineID, InstallationGeneration: cache.InstallationGeneration, HostKeyGeneration: cache.HostKeyGeneration, HostRecipientKeyID: cache.HostRecipientKeyID}
}

func initialHighWaterRecord(cache Cache) highWaterRecord {
	return finalHighWaterRecord(initialHighWater(cache))
}

func finalHighWaterRecord(active highWater) highWaterRecord {
	return highWaterRecord{Schema: highWaterSchema, Active: cloneHighWater(active)}
}

func transitionHighWaterRecord(active, pending highWater) highWaterRecord {
	value := cloneHighWater(pending)
	return highWaterRecord{Schema: highWaterSchema, Active: cloneHighWater(active), Pending: &value}
}

func highWaterMatchesIdentity(value highWater, cache Cache) bool {
	return value.Schema == highWaterSchema && value.AccountID == cache.AccountID && value.MachineID == cache.MachineID &&
		value.InstallationGeneration == cache.InstallationGeneration && value.HostKeyGeneration == cache.HostKeyGeneration && value.HostRecipientKeyID == cache.HostRecipientKeyID
}

func highWaterEmpty(value highWater) bool {
	return value.CacheHash == "" && value.ObservationSeq == 0 && value.Authority == nil && value.Global == nil && value.Machine == nil
}

func cacheMatchesHighWater(cache Cache, value highWater) bool {
	if cache.ObservationSeq != value.ObservationSeq || !cursorEqual(cache.Authority, value.Authority) {
		return false
	}
	if cache.Revoked {
		if cache.GlobalManifest != nil || cache.MachineManifest != nil {
			return false
		}
	} else if manifestBehind(cache.GlobalManifest, value.Global) || manifestBehind(cache.MachineManifest, value.Machine) ||
		manifestBehindCursor(value.Global, cache.GlobalManifest) || manifestBehindCursor(value.Machine, cache.MachineManifest) {
		return false
	}
	return value.CacheHash == cacheHash(cache)
}

func manifestBehindCursor(cache *ManifestCursor, floor *ManifestEnvelope) bool {
	if floor == nil {
		return cache != nil
	}
	return cache == nil || cache.Version < floor.Version || cache.Version == floor.Version && cache.ManifestID != floor.ManifestID
}

func cacheBehindHighWater(cache Cache, value highWater) bool {
	if cache.ObservationSeq < value.ObservationSeq || cursorBehind(cache.Authority, value.Authority) {
		return true
	}
	if cache.Revoked {
		return false
	}
	return manifestBehind(cache.GlobalManifest, value.Global) || manifestBehind(cache.MachineManifest, value.Machine)
}

func cursorBehind(cache, floor *Cursor) bool {
	if floor == nil {
		return false
	}
	return cache == nil || cache.Generation < floor.Generation || cache.Generation == floor.Generation && cache.AuthorityID != floor.AuthorityID
}

func manifestBehind(cache *ManifestEnvelope, floor *ManifestCursor) bool {
	if floor == nil {
		return false
	}
	return cache == nil || cache.Version < floor.Version || cache.Version == floor.Version && cache.ManifestID != floor.ManifestID
}

func advanceHighWater(value highWater, cache Cache) highWater {
	result := cloneHighWater(value)
	result.CacheHash = cacheHash(cache)
	if cache.ObservationSeq > result.ObservationSeq {
		result.ObservationSeq = cache.ObservationSeq
	}
	if cache.Authority != nil && (result.Authority == nil || cache.Authority.Generation > result.Authority.Generation) {
		result.Authority = cloneCursor(cache.Authority)
	} else if cache.Authority != nil && result.Authority != nil && cache.Authority.Generation == result.Authority.Generation && cache.Authority.AuthorityID == result.Authority.AuthorityID {
		result.Authority = cloneCursor(cache.Authority)
	}
	result.Global = advanceManifestCursor(result.Global, cache.GlobalManifest)
	result.Machine = advanceManifestCursor(result.Machine, cache.MachineManifest)
	return result
}

func advanceManifestCursor(current *ManifestCursor, cache *ManifestEnvelope) *ManifestCursor {
	if cache == nil {
		return cloneManifestCursor(current)
	}
	if current == nil || cache.Version > current.Version || cache.Version == current.Version && cache.ManifestID == current.ManifestID {
		return &ManifestCursor{Version: cache.Version, KeyEpoch: cache.KeyEpoch, ManifestID: cache.ManifestID}
	}
	return cloneManifestCursor(current)
}

func cloneHighWater(value highWater) highWater {
	value.Authority = cloneCursor(value.Authority)
	value.Global = cloneManifestCursor(value.Global)
	value.Machine = cloneManifestCursor(value.Machine)
	return value
}

func cacheHash(cache Cache) string {
	body, err := json.Marshal(cache)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(body)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func cursorEqual(left, right *Cursor) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func loadHighWater(path string, key []byte) (highWaterRecord, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return highWaterRecord{}, err
	}
	if !secureStateFile(path, info, 4096) {
		return highWaterRecord{}, ErrInvalidSnapshot
	}
	body, err := os.ReadFile(path)
	if err != nil || rejectDuplicateJSON(body) != nil {
		return highWaterRecord{}, ErrInvalidSnapshot
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var authenticated authenticatedHighWater
	if decoder.Decode(&authenticated) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return highWaterRecord{}, ErrInvalidSnapshot
	}
	expected, err := highWaterMAC(authenticated.Record, key)
	if err != nil {
		return highWaterRecord{}, err
	}
	actual, err := base64.RawURLEncoding.Strict().DecodeString(authenticated.MAC)
	if err != nil || len(actual) != sha256.Size || !hmac.Equal(actual, expected) || authenticated.MAC != base64.RawURLEncoding.EncodeToString(actual) {
		clear(actual)
		clear(expected)
		return highWaterRecord{}, ErrInvalidSnapshot
	}
	clear(actual)
	clear(expected)
	return cloneHighWaterRecord(authenticated.Record), nil
}

func writeHighWater(path string, key []byte, value highWaterRecord) error {
	mac, err := highWaterMAC(value, key)
	if err != nil {
		return err
	}
	authenticated := authenticatedHighWater{Record: cloneHighWaterRecord(value), MAC: base64.RawURLEncoding.EncodeToString(mac)}
	clear(mac)
	body, err := json.Marshal(authenticated)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}

func highWaterMAC(value highWaterRecord, key []byte) ([]byte, error) {
	if len(key) != 32 || !validHighWaterRecord(value) {
		return nil, ErrInvalidSnapshot
	}
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("paperboat-environment-host-high-water-v1\x00"))
	_, _ = mac.Write(body)
	return mac.Sum(nil), nil
}

func validHighWaterRecord(value highWaterRecord) bool {
	if value.Schema != highWaterSchema || !validHighWaterShape(value.Active) {
		return false
	}
	if value.Pending == nil {
		return true
	}
	return validHighWaterShape(*value.Pending) && highWaterMatchesIdentity(*value.Pending, Cache{
		AccountID: value.Active.AccountID, MachineID: value.Active.MachineID, InstallationGeneration: value.Active.InstallationGeneration,
		HostKeyGeneration: value.Active.HostKeyGeneration, HostRecipientKeyID: value.Active.HostRecipientKeyID,
	}) && !highWaterBehind(*value.Pending, value.Active)
}

func highWaterBehind(next, active highWater) bool {
	if next.ObservationSeq < active.ObservationSeq || cursorBehind(next.Authority, active.Authority) {
		return true
	}
	return manifestCursorBehind(next.Global, active.Global) || manifestCursorBehind(next.Machine, active.Machine)
}

func manifestCursorBehind(next, active *ManifestCursor) bool {
	if active == nil {
		return false
	}
	return next == nil || next.Version < active.Version || next.Version == active.Version && next.ManifestID != active.ManifestID
}

func cloneHighWaterRecord(value highWaterRecord) highWaterRecord {
	value.Active = cloneHighWater(value.Active)
	if value.Pending != nil {
		pending := cloneHighWater(*value.Pending)
		value.Pending = &pending
	}
	return value
}

func validHighWaterShape(value highWater) bool {
	if value.Schema != highWaterSchema || value.ObservationSeq > math.MaxInt64 {
		return false
	}
	if value.Authority != nil && !validAuthorityCursor(*value.Authority) {
		return false
	}
	for _, cursor := range []*ManifestCursor{value.Global, value.Machine} {
		if cursor != nil && (cursor.Version == 0 || cursor.Version > math.MaxInt64 || cursor.KeyEpoch == 0 || cursor.KeyEpoch > math.MaxInt64 || !validManifestID(cursor.ManifestID)) {
			return false
		}
	}
	if value.CacheHash != "" {
		digest, err := base64.RawURLEncoding.Strict().DecodeString(value.CacheHash)
		valid := err == nil && len(digest) == sha256.Size && value.CacheHash == base64.RawURLEncoding.EncodeToString(digest)
		clear(digest)
		if !valid {
			return false
		}
	}
	return validIdentifier(value.AccountID) && validIdentifier(value.MachineID) && value.InstallationGeneration > 0 && value.HostKeyGeneration > 0 && validKeyID(value.HostRecipientKeyID)
}

func loadCache(path string) (Cache, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Cache{}, err
	}
	if !secureStateFile(path, info, maximumCacheBytes) {
		return Cache{}, ErrInvalidSnapshot
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return Cache{}, err
	}
	if rejectDuplicateJSON(body) != nil {
		return Cache{}, ErrInvalidSnapshot
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var cache Cache
	if decoder.Decode(&cache) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validCacheShape(cache) {
		return Cache{}, ErrInvalidSnapshot
	}
	return cache, nil
}

func writeCache(path string, cache Cache) error {
	if !validCacheShape(cache) {
		return ErrInvalidSnapshot
	}
	body, err := json.Marshal(cache)
	if err != nil || len(body) > maximumCacheBytes {
		return errors.Join(ErrInvalidSnapshot, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, body, atomicfile.CurrentOwnerOptions(0o600))
}

func validCacheShape(cache Cache) bool {
	return cache.Schema == cacheSchema && validIdentifier(cache.AccountID) && validIdentifier(cache.MachineID) &&
		cache.InstallationGeneration > 0 && cache.HostKeyGeneration > 0 && validKeyID(cache.HostRecipientKeyID) &&
		cache.ObservationSeq <= math.MaxInt64 && len(cache.AuthorityDocuments) <= 512
}

func validIdentifier(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validKeyID(value string) bool {
	if !strings.HasPrefix(value, "envk_") || len(value) != len("envk_")+43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value[len("envk_"):])
	valid := err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value[len("envk_"):]
	clear(decoded)
	return valid
}

func validManifestID(value string) bool {
	_, err := environmente2ee.ParseDocumentID(value)
	return err == nil
}

func portableName(name string) bool {
	return len(name) > 0 && len(name) <= MaximumNameBytes && variableName.MatchString(name)
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func cloneCursor(value *Cursor) *Cursor {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
func cloneManifestCursor(value *ManifestCursor) *ManifestCursor {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
func cloneManifest(value *ManifestEnvelope) *ManifestEnvelope {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
func cloneVerified(value Verified) Verified {
	result := value
	result.Authority = cloneCursor(value.Authority)
	result.Global = cloneManifestCursor(value.Global)
	result.Machine = cloneManifestCursor(value.Machine)
	result.Variables = make(map[string]string, len(value.Variables))
	for key, item := range value.Variables {
		result.Variables[key] = item
	}
	return result
}
func cloneCache(value Cache) Cache {
	result := value
	result.Authority = cloneCursor(value.Authority)
	result.AuthorityDocuments = append([]string(nil), value.AuthorityDocuments...)
	result.GlobalManifest = cloneManifest(value.GlobalManifest)
	result.MachineManifest = cloneManifest(value.MachineManifest)
	return result
}

func rejectDuplicateJSON(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalidSnapshot
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrInvalidSnapshot
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return ErrInvalidSnapshot
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidSnapshot
	}
	return nil
}
