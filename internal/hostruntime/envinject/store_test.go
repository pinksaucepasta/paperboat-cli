package envinject

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/environmentkey"
)

const testKeyID = "envk_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"

type testGenesisMarker struct {
	mu   sync.Mutex
	path string
}

type testGenesisRecord struct {
	State environmentkey.GenesisState `json:"state"`
}

func (m *testGenesisMarker) GenesisState() (environmentkey.GenesisState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.readLocked()
}

func (m *testGenesisMarker) PrepareGenesis() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.readLocked()
	if err != nil {
		return err
	}
	switch state {
	case environmentkey.GenesisFresh:
		return m.writeLocked(environmentkey.GenesisPending)
	case environmentkey.GenesisPending:
		return nil
	case environmentkey.GenesisEstablished:
		return environmentkey.ErrGenesisAlreadyEstablished
	default:
		return environmentkey.ErrGenesisMarkerInvalid
	}
}

func (m *testGenesisMarker) CommitGenesis() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.readLocked()
	if err != nil {
		return err
	}
	switch state {
	case environmentkey.GenesisPending:
		return m.writeLocked(environmentkey.GenesisEstablished)
	case environmentkey.GenesisEstablished:
		return nil
	case environmentkey.GenesisFresh:
		return environmentkey.ErrGenesisNotPrepared
	default:
		return environmentkey.ErrGenesisMarkerInvalid
	}
}

func (m *testGenesisMarker) readLocked() (environmentkey.GenesisState, error) {
	body, err := os.ReadFile(m.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", environmentkey.ErrGenesisMarkerMissing
		}
		return "", err
	}
	var record testGenesisRecord
	if json.Unmarshal(body, &record) != nil {
		return "", environmentkey.ErrGenesisMarkerInvalid
	}
	switch record.State {
	case environmentkey.GenesisFresh, environmentkey.GenesisPending, environmentkey.GenesisEstablished:
		return record.State, nil
	default:
		return "", environmentkey.ErrGenesisMarkerInvalid
	}
}

func (m *testGenesisMarker) writeLocked(state environmentkey.GenesisState) error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return err
	}
	body, err := json.Marshal(testGenesisRecord{State: state})
	if err != nil {
		return err
	}
	return atomicfile.Write(m.path, body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}

func prepareTestGenesisMarker(t *testing.T, marker *testGenesisMarker) {
	t.Helper()
	if _, err := os.Lstat(marker.path); errors.Is(err, os.ErrNotExist) {
		if err := marker.writeLocked(environmentkey.GenesisFresh); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
}

type processor struct {
	secret  string
	fail    bool
	revoked bool
}

func (p *processor) Restore(_ context.Context, cache Cache) (Verified, error) {
	if p.fail {
		return Verified{}, errors.New("integrity")
	}
	return verifiedFromCache(cache, p.secret, p.revoked), nil
}

func (p *processor) Apply(_ context.Context, cache Cache, bundle Bundle) (Cache, Verified, error) {
	if p.fail {
		return Cache{}, Verified{}, errors.New("integrity")
	}
	cache.Authority = &bundle.AuthorityHead
	cache.AuthorityDocuments = append(cache.AuthorityDocuments, bundle.AuthorityDocuments...)
	if bundle.GlobalManifest != nil {
		cache.GlobalManifest = cloneManifest(bundle.GlobalManifest)
	}
	if bundle.MachineManifest != nil {
		cache.MachineManifest = cloneManifest(bundle.MachineManifest)
	}
	cache.Revoked = p.revoked || bundle.RevocationOnly
	return cache, verifiedFromCache(cache, p.secret, cache.Revoked), nil
}

func verifiedFromCache(cache Cache, secret string, revoked bool) Verified {
	result := Verified{Authority: cloneCursor(cache.Authority), Revoked: revoked}
	if revoked {
		return result
	}
	if cache.GlobalManifest != nil && cache.MachineManifest != nil {
		result.Ready = true
		result.Variables = map[string]string{"CANARY": secret}
		result.Global = &ManifestCursor{Version: cache.GlobalManifest.Version, KeyEpoch: cache.GlobalManifest.KeyEpoch, ManifestID: cache.GlobalManifest.ManifestID}
		result.Machine = &ManifestCursor{Version: cache.MachineManifest.Version, KeyEpoch: cache.MachineManifest.KeyEpoch, ManifestID: cache.MachineManifest.ManifestID}
	}
	return result
}

func TestStorePersistsOnlyCiphertextAndRestoresOffline(t *testing.T) {
	canary := "unique-plaintext-canary-never-on-disk"
	path := filepath.Join(t.TempDir(), "environment", "cache.json")
	store := openTestStore(t, path, &processor{secret: canary})
	if _, err := store.NextObservation(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	bundle := validBundle()
	if err := store.Apply(context.Background(), bundle); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Environment(); err != nil || !reflect.DeepEqual(got, []string{"CANARY=" + canary}) {
		t.Fatalf("environment=%q err=%v", got, err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), canary) || !strings.Contains(string(body), "opaque-global-ciphertext") {
		t.Fatalf("cache secret/ciphertext boundary violated: %s", body)
	}
	restored := openTestStore(t, path, &processor{secret: canary})
	if got, err := restored.Environment(); err != nil || !reflect.DeepEqual(got, []string{"CANARY=" + canary}) {
		t.Fatalf("offline environment=%q err=%v", got, err)
	}
	observation, err := restored.NextObservation(time.Now().UTC())
	if err != nil || observation.ObservationSeq != 2 {
		t.Fatalf("observation=%+v err=%v", observation, err)
	}
}

func TestStoreRetainsLastGoodOnIntegrityFailure(t *testing.T) {
	processor := &processor{secret: "last-good"}
	store := openTestStore(t, filepath.Join(t.TempDir(), "cache.json"), processor)
	if err := store.Apply(context.Background(), validBundle()); err != nil {
		t.Fatal(err)
	}
	processor.fail = true
	if err := store.Apply(context.Background(), validBundle()); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("error=%v", err)
	}
	if got, err := store.Environment(); err != nil || !reflect.DeepEqual(got, []string{"CANARY=last-good"}) {
		t.Fatalf("last good=%q err=%v", got, err)
	}
	observation, err := store.NextObservation(time.Now().UTC())
	if err != nil || observation.State != "failed" || observation.ErrorCode == nil || *observation.ErrorCode != "integrity_failed" {
		t.Fatalf("observation=%+v err=%v", observation, err)
	}
}

func TestStoreRejectsRollbackCopiedCiphertextCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment", "cache.json")
	store := openTestStore(t, path, &processor{secret: "in-memory-only"})
	if err := store.Apply(context.Background(), validBundle()); err != nil {
		t.Fatal(err)
	}
	oldCache, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NextObservation(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, oldCache, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), testStoreConfig(path, &processor{secret: "in-memory-only"})); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("rollback copy error=%v", err)
	}
}

func TestStoreDoesNotReinitializeLostDurableHighWater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment", "cache.json")
	store := openTestStore(t, path, &processor{secret: "in-memory-only"})
	if _, err := store.NextObservation(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(store.config.HighWaterPath); err != nil {
		t.Fatal(err)
	}
	config := testStoreConfig(path, &processor{secret: "in-memory-only"})
	config.AllowHighWaterInitialize = false
	if _, err := Open(context.Background(), config); !errors.Is(err, ErrObservationLost) {
		t.Fatalf("lost high-water was reinitialized: %v", err)
	}
}

func TestStoreResumesPendingGenesisWhenNoDurableStateExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment", "cache.json")
	config := testStoreConfig(path, &processor{secret: "pending-genesis"})
	marker := config.GenesisMarker.(*testGenesisMarker)
	prepareTestGenesisMarker(t, marker)
	if err := marker.PrepareGenesis(); err != nil {
		t.Fatal(err)
	}
	if state, err := marker.GenesisState(); err != nil || state != environmentkey.GenesisPending {
		t.Fatalf("prepared marker state=%q error=%v", state, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache unexpectedly exists before recovery: %v", err)
	}
	if _, err := os.Stat(config.HighWaterPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("high-water unexpectedly exists before recovery: %v", err)
	}

	store, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if state, err := marker.GenesisState(); err != nil || state != environmentkey.GenesisEstablished {
		t.Fatalf("recovered marker state=%q error=%v", state, err)
	}
	if _, err := os.Stat(config.HighWaterPath); err != nil {
		t.Fatalf("recovered high-water missing: %v", err)
	}
	if store.highWater.ObservationSeq != 0 || store.highWater.CacheHash != "" {
		t.Fatalf("recovered high-water=%+v", store.highWater)
	}
}

func TestStoreRejectsPendingGenesisWithOnlyCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment", "cache.json")
	config := testStoreConfig(path, &processor{secret: "pending-cache-only"})
	marker := config.GenesisMarker.(*testGenesisMarker)
	prepareTestGenesisMarker(t, marker)
	if err := marker.PrepareGenesis(); err != nil {
		t.Fatal(err)
	}
	if err := writeCache(path, Cache{
		Schema: cacheSchema, AccountID: config.AccountID, MachineID: config.MachineID,
		InstallationGeneration: config.InstallationGeneration, HostKeyGeneration: config.HostKeyGeneration,
		HostRecipientKeyID: config.HostRecipientKeyID,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), config); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("pending marker with cache-only state was accepted: %v", err)
	}
	if state, err := marker.GenesisState(); err != nil || state != environmentkey.GenesisPending {
		t.Fatalf("unsafe recovery changed marker state=%q error=%v", state, err)
	}
}

func TestStoreRejectsReplayAfterAllLocalEnvironmentStateIsDeleted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment", "cache.json")
	processor := &processor{secret: "replay-must-fail"}
	store := openTestStore(t, path, processor)
	if err := store.Apply(context.Background(), validBundle()); err != nil {
		t.Fatal(err)
	}
	oldCache, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// The secure installation marker is outside the ENV cache directory. A
	// captured old cache cannot recreate the missing high-water authority.
	if err := os.RemoveAll(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	config := testStoreConfig(path, processor)
	if _, err := Open(context.Background(), config); !errors.Is(err, ErrObservationLost) {
		t.Fatalf("deleted ENV state was reinitialized: %v", err)
	}

	// Even if an attacker restores the captured ciphertext after deleting the
	// rest of the local state, the established marker still forbids bootstrap.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, oldCache, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), config); !errors.Is(err, ErrInvalidSnapshot) && !errors.Is(err, ErrObservationLost) {
		t.Fatalf("captured cache was accepted after state deletion: %v", err)
	}
}

func TestStoreRejectsEqualVersionManifestForkBelowHighWater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment", "cache.json")
	store := openTestStore(t, path, &processor{secret: "in-memory-only"})
	if err := store.Apply(context.Background(), validBundle()); err != nil {
		t.Fatal(err)
	}
	cache, err := loadCache(path)
	if err != nil {
		t.Fatal(err)
	}
	cache.GlobalManifest.ManifestID = "sha256:" + strings.Repeat("d", 64)
	if err := writeCache(path, cache); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), testStoreConfig(path, &processor{secret: "in-memory-only"})); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("equal-version fork error=%v", err)
	}
}

func TestStoreRecoversAuthenticatedIntentBeforeCacheWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment", "cache.json")
	processor := &processor{secret: "in-memory-only"}
	store := openTestStore(t, path, processor)
	if err := store.Apply(context.Background(), validBundle()); err != nil {
		t.Fatal(err)
	}
	cache, err := loadCache(path)
	if err != nil {
		t.Fatal(err)
	}
	next := cloneCache(cache)
	next.ObservationSeq++
	if err := writeHighWater(store.config.HighWaterPath, store.config.IntegrityKey, transitionHighWaterRecord(store.highWater, advanceHighWater(store.highWater, next))); err != nil {
		t.Fatal(err)
	}
	restored := openTestStore(t, path, processor)
	observation, err := restored.NextObservation(time.Now().UTC())
	if err != nil || observation.ObservationSeq != cache.ObservationSeq+1 {
		t.Fatalf("observation=%+v err=%v", observation, err)
	}
	record, err := loadHighWater(store.config.HighWaterPath, store.config.IntegrityKey)
	if err != nil || record.Pending != nil {
		t.Fatalf("pending intent was not aborted: %+v err=%v", record.Pending, err)
	}
}

func TestStoreRecoversAuthenticatedApplyIntentAfterCacheWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment", "cache.json")
	processor := &processor{secret: "in-memory-only"}
	store := openTestStore(t, path, processor)
	if err := store.Apply(context.Background(), validBundle()); err != nil {
		t.Fatal(err)
	}
	next, _, err := processor.Apply(context.Background(), cloneCache(store.cache), advancedBundle())
	if err != nil {
		t.Fatal(err)
	}
	nextHighWater := advanceHighWater(store.highWater, next)
	if err := writeHighWater(store.config.HighWaterPath, store.config.IntegrityKey, transitionHighWaterRecord(store.highWater, nextHighWater)); err != nil {
		t.Fatal(err)
	}
	if err := writeCache(path, next); err != nil {
		t.Fatal(err)
	}
	restored := openTestStore(t, path, processor)
	if restored.cache.Authority.Generation != 2 || restored.cache.GlobalManifest.Version != 2 || restored.cache.MachineManifest.Version != 2 {
		t.Fatalf("pending cache was not finalized: %+v", restored.cache)
	}
	record, err := loadHighWater(store.config.HighWaterPath, store.config.IntegrityKey)
	if err != nil || record.Pending != nil || !cacheMatchesHighWater(restored.cache, record.Active) {
		t.Fatalf("high-water was not finalized: %+v err=%v", record, err)
	}
}

func TestStoreCacheWriteCommitErrorPreservesIntentAndFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment", "cache.json")
	processor := &processor{secret: "cache-commit-error"}
	store := openTestStore(t, path, processor)
	injected := errors.New("cache sync uncertain")
	store.cacheWriter = func(cachePath string, cache Cache) error {
		if err := writeCache(cachePath, cache); err != nil {
			return err
		}
		return injected
	}

	if err := store.Apply(context.Background(), validBundle()); !errors.Is(err, ErrObservationLost) || !errors.Is(err, injected) {
		t.Fatalf("cache commit error=%v", err)
	}
	if err := store.Apply(context.Background(), validBundle()); !errors.Is(err, ErrObservationLost) {
		t.Fatalf("failed store accepted another apply: %v", err)
	}
	if _, err := store.NextObservation(time.Now().UTC()); !errors.Is(err, ErrObservationLost) {
		t.Fatalf("failed store issued an observation: %v", err)
	}

	// The cache replacement succeeded even though the writer reported an
	// uncertain sync. Restart must promote the authenticated pending intent.
	restored := openTestStore(t, path, processor)
	if got, err := restored.Environment(); err != nil || !reflect.DeepEqual(got, []string{"CANARY=cache-commit-error"}) {
		t.Fatalf("recovered environment=%q error=%v", got, err)
	}
	record, err := loadHighWater(restored.config.HighWaterPath, restored.config.IntegrityKey)
	if err != nil || record.Pending != nil || !cacheMatchesHighWater(restored.cache, record.Active) {
		t.Fatalf("pending intent was not reconciled: %+v error=%v", record, err)
	}
}

func TestStoreHighWaterIntentCommitErrorFailsClosedWithoutConsumingObservation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment", "cache.json")
	processor := &processor{secret: "high-water-intent-error"}
	store := openTestStore(t, path, processor)
	injected := errors.New("high-water intent sync uncertain")
	store.highWaterWriter = func(highWaterPath string, key []byte, record highWaterRecord) error {
		if record.Pending != nil {
			if err := writeHighWater(highWaterPath, key, record); err != nil {
				return err
			}
			return injected
		}
		return writeHighWater(highWaterPath, key, record)
	}

	if err := store.Apply(context.Background(), validBundle()); !errors.Is(err, ErrObservationLost) || !errors.Is(err, injected) {
		t.Fatalf("high-water intent error=%v", err)
	}
	if _, err := store.NextObservation(time.Now().UTC()); !errors.Is(err, ErrObservationLost) {
		t.Fatalf("failed store issued an observation: %v", err)
	}

	// No cache was written. Open aborts the authenticated intent and the next
	// observation starts at zero rather than consuming a sequence in memory.
	restored := openTestStore(t, path, processor)
	observation, err := restored.NextObservation(time.Now().UTC())
	if err != nil || observation.ObservationSeq != 1 {
		t.Fatalf("recovered observation=%+v error=%v", observation, err)
	}
	record, err := loadHighWater(restored.config.HighWaterPath, restored.config.IntegrityKey)
	if err != nil || record.Pending != nil {
		t.Fatalf("intent was not aborted: %+v error=%v", record, err)
	}
}

func TestStoreFinalHighWaterFailureReconcilesCommittedCacheOnRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment", "cache.json")
	processor := &processor{secret: "final-high-water-error"}
	store := openTestStore(t, path, processor)
	injected := errors.New("final high-water sync failed")
	store.highWaterWriter = func(highWaterPath string, key []byte, record highWaterRecord) error {
		if record.Pending == nil && !highWaterEmpty(record.Active) {
			return injected
		}
		return writeHighWater(highWaterPath, key, record)
	}

	if err := store.Apply(context.Background(), validBundle()); !errors.Is(err, ErrObservationLost) || !errors.Is(err, injected) {
		t.Fatalf("final high-water error=%v", err)
	}
	if _, err := store.NextObservation(time.Now().UTC()); !errors.Is(err, ErrObservationLost) {
		t.Fatalf("failed store issued an observation: %v", err)
	}

	// The cache is durable while the finalization write failed, so restart
	// promotes the still-pending intent and restores the last-good values.
	restored := openTestStore(t, path, processor)
	if got, err := restored.Environment(); err != nil || !reflect.DeepEqual(got, []string{"CANARY=final-high-water-error"}) {
		t.Fatalf("recovered environment=%q error=%v", got, err)
	}
	record, err := loadHighWater(restored.config.HighWaterPath, restored.config.IntegrityKey)
	if err != nil || record.Pending != nil || !cacheMatchesHighWater(restored.cache, record.Active) {
		t.Fatalf("pending intent was not finalized: %+v error=%v", record, err)
	}
}

func TestNextObservationCacheCommitErrorNeverReusesSequence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment", "cache.json")
	store := openTestStore(t, path, &processor{secret: "observation-cache-error"})
	injected := errors.New("observation cache sync uncertain")
	store.cacheWriter = func(cachePath string, cache Cache) error {
		if err := writeCache(cachePath, cache); err != nil {
			return err
		}
		return injected
	}

	if _, err := store.NextObservation(time.Now().UTC()); !errors.Is(err, ErrObservationLost) || !errors.Is(err, injected) {
		t.Fatalf("observation cache commit error=%v", err)
	}
	if _, err := store.NextObservation(time.Now().UTC()); !errors.Is(err, ErrObservationLost) {
		t.Fatalf("failed store reused its in-memory sequence: %v", err)
	}

	restored := openTestStore(t, path, &processor{secret: "observation-cache-error"})
	observation, err := restored.NextObservation(time.Now().UTC())
	if err != nil || observation.ObservationSeq != 2 {
		t.Fatalf("recovered observation=%+v error=%v", observation, err)
	}
}

func TestVerifiedRevocationClearsManagedEnvironment(t *testing.T) {
	processor := &processor{secret: "disclosed"}
	store := openTestStore(t, filepath.Join(t.TempDir(), "cache.json"), processor)
	if err := store.Apply(context.Background(), validBundle()); err != nil {
		t.Fatal(err)
	}
	processor.revoked = true
	bundle := validBundle()
	bundle.RevocationOnly = true
	bundle.GlobalManifest, bundle.MachineManifest = nil, nil
	if err := store.Apply(context.Background(), bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Environment(); !errors.Is(err, ErrRevoked) {
		t.Fatalf("error=%v", err)
	}
}

func TestMergeManagedOverridesBaseAndRejectsCaseCollisions(t *testing.T) {
	base := []string{"PATH=/bin", "TOKEN=base", "PAPERBOAT_ENDPOINT=http://local"}
	managed := []string{"EMPTY=", "path=/managed/bin", "TOKEN=managed"}
	got, err := Merge(base, managed)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"EMPTY=", "PAPERBOAT_ENDPOINT=http://local", "PATH=/managed/bin", "TOKEN=managed"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("environment=%q want=%q", got, want)
	}
	if _, err := Merge(nil, []string{"Token=one", "TOKEN=two"}); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("duplicate error=%v", err)
	}
}

func TestProviderFailsClosedUntilEncryptedStoreAttached(t *testing.T) {
	provider := &Provider{}
	if provider.BindingState() != BindingUnknown {
		t.Fatal("unattached provider reported binding evidence")
	}
	if _, err := provider.Environment(); !errors.Is(err, ErrNotReady) {
		t.Fatalf("environment error=%v", err)
	}
	if _, err := provider.NextObservation(time.Now().UTC()); !errors.Is(err, ErrNotReady) {
		t.Fatalf("observation error=%v", err)
	}
	store := openTestStore(t, filepath.Join(t.TempDir(), "cache.json"), &processor{secret: "attached"})
	if err := provider.Attach(store); err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(context.Background(), validBundle()); err != nil {
		t.Fatal(err)
	}
	if provider.BindingState() != BindingActive {
		t.Fatalf("verified bundle binding state=%d, want active", provider.BindingState())
	}
	if values, err := provider.Environment(); err != nil || !reflect.DeepEqual(values, []string{"CANARY=attached"}) {
		t.Fatalf("values=%q error=%v", values, err)
	}
	if err := provider.Attach(openTestStore(t, filepath.Join(t.TempDir(), "other.json"), &processor{})); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("replacement error=%v", err)
	}
}

func TestRuntimeResponseBundleDecoderRejectsAmbiguityAndUnknownBundleFields(t *testing.T) {
	bundle, err := json.Marshal(validBundle())
	if err != nil {
		t.Fatal(err)
	}
	response := []byte(`{"data":{"accepted":true,"environment_bundle":` + string(bundle) + `}}`)
	decoded, err := DecodeRuntimeResponse(response)
	if err != nil || decoded == nil || decoded.Schema != BundleSchema {
		t.Fatalf("bundle=%+v error=%v", decoded, err)
	}
	for _, invalid := range [][]byte{
		[]byte(`{"data":{"environment_bundle":null,"environment_bundle":` + string(bundle) + `}}`),
		[]byte(`{"data":{"environment_bundle":{"schema":"paperboat.environment-bundle/v2","unexpected":true}}}`),
	} {
		if _, err := DecodeRuntimeResponse(invalid); !errors.Is(err, ErrInvalidSnapshot) {
			t.Fatalf("ambiguous response accepted: %s error=%v", invalid, err)
		}
	}
}

func openTestStore(t *testing.T, path string, processor Processor) *Store {
	t.Helper()
	config := testStoreConfig(path, processor)
	prepareTestGenesisMarker(t, config.GenesisMarker.(*testGenesisMarker))
	store, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testStoreConfig(path string, processor Processor) Config {
	return Config{
		Path: path, HighWaterPath: path + ".high-water", IntegrityKey: bytes.Repeat([]byte{0x42}, 32), AllowHighWaterInitialize: true, AccountID: "account_1", MachineID: "machine_1", InstallationGeneration: 3,
		HostKeyGeneration: 3, HostRecipientKeyID: testKeyID, GenesisMarker: &testGenesisMarker{path: testGenesisMarkerPath(path)}, Processor: processor,
	}
}

func testGenesisMarkerPath(path string) string {
	return filepath.Join(filepath.Dir(filepath.Dir(path)), filepath.Base(path)+".paperboat-secure-genesis")
}

func validBundle() Bundle {
	return Bundle{
		Schema: BundleSchema, AuthorityHead: Cursor{Generation: 1, AuthorityID: "sha256:" + strings.Repeat("a", 64)},
		AuthorityDocuments: []string{"opaque-authority"},
		GlobalManifest:     &ManifestEnvelope{Version: 1, KeyEpoch: 1, ManifestID: "sha256:" + strings.Repeat("b", 64), Envelope: "opaque-global-ciphertext"},
		MachineManifest:    &ManifestEnvelope{Version: 1, KeyEpoch: 1, ManifestID: "sha256:" + strings.Repeat("c", 64), Envelope: "opaque-machine-ciphertext"},
	}
}

func advancedBundle() Bundle {
	bundle := validBundle()
	bundle.AuthorityHead = Cursor{Generation: 2, AuthorityID: "sha256:" + strings.Repeat("d", 64)}
	bundle.AuthorityDocuments = []string{"opaque-authority-2"}
	bundle.GlobalManifest = &ManifestEnvelope{Version: 2, KeyEpoch: 1, ManifestID: "sha256:" + strings.Repeat("e", 64), Envelope: "opaque-global-ciphertext-2"}
	bundle.MachineManifest = &ManifestEnvelope{Version: 2, KeyEpoch: 1, ManifestID: "sha256:" + strings.Repeat("f", 64), Envelope: "opaque-machine-ciphertext-2"}
	return bundle
}
