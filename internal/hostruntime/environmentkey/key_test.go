package environmentkey

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

type memoryStore struct {
	mu     sync.Mutex
	commit sync.Mutex
	values map[string]string
	fail   bool
	sets   int
}

func (*memoryStore) EnvironmentSecureStore() {}

func (s *memoryStore) LockEnvironmentHostKey(string, uint64) (func() error, error) {
	s.commit.Lock()
	return func() error {
		s.commit.Unlock()
		return nil
	}, nil
}

var errMemoryMissing = errors.New("missing")

func (s *memoryStore) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("unavailable")
	}
	if s.values == nil {
		s.values = map[string]string{}
	}
	s.values[key] = value
	s.sets++
	return nil
}
func (s *memoryStore) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return "", errors.New("unavailable")
	}
	value, ok := s.values[key]
	if !ok {
		return "", errMemoryMissing
	}
	return value, nil
}
func (s *memoryStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, key)
	return nil
}

func TestKeyringSourceCreatesStableGenerationBoundX25519Key(t *testing.T) {
	store := &memoryStore{}
	source := KeyringSource{Store: store, MachineID: "mch_one", Generation: 7, Random: zeroReader{}, NotFound: func(err error) bool { return errors.Is(err, errMemoryMissing) }}
	first, err := source.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Destroy()
	second, err := source.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Destroy()
	if first != second || first.Generation != 7 {
		t.Fatalf("keys are not stable: first=%v second=%v", first.Generation, second.Generation)
	}
	if public, err := first.Public(); err != nil || public == ([32]byte{}) {
		t.Fatalf("public=%x err=%v", public, err)
	}
	next, err := (KeyringSource{Store: store, MachineID: "mch_one", Generation: 8, Random: zeroReader{offset: 7}, NotFound: func(err error) bool { return errors.Is(err, errMemoryMissing) }}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer next.Destroy()
	if next == first {
		t.Fatal("new installation generation reused recipient key")
	}
}

func TestKeyringSourceConcurrentFirstLoadsKeepOneKey(t *testing.T) {
	store := &memoryStore{}
	const workers = 32
	materials := make(chan Material, workers)
	errorsCh := make(chan error, workers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			source := KeyringSource{
				Store: store, MachineID: "mch_one", Generation: 7,
				Random:   zeroReader{offset: byte(index)},
				NotFound: func(err error) bool { return errors.Is(err, errMemoryMissing) },
			}
			material, err := source.Load(context.Background())
			if err != nil {
				errorsCh <- err
				return
			}
			materials <- material
		}(index)
	}
	close(start)
	wait.Wait()
	close(materials)
	close(errorsCh)
	for err := range errorsCh {
		t.Fatal(err)
	}
	loaded := make([]Material, 0, workers)
	for material := range materials {
		loaded = append(loaded, material)
	}
	defer func() {
		for _, material := range loaded {
			material.Destroy()
		}
	}()
	var first Material
	for _, material := range loaded {
		if first == (Material{}) {
			first = material
			continue
		}
		if material != first {
			t.Fatalf("concurrent loads returned different host keys: first=%x got=%x", first.Private, material.Private)
		}
	}
	if first == (Material{}) {
		t.Fatal("concurrent loads returned no key")
	}
}

func TestKeyringSourceRequiresExistingGenesisMarker(t *testing.T) {
	store := &memoryStore{}
	source := KeyringSource{Store: store, MachineID: "mch_one", Generation: 7, Random: zeroReader{}, NotFound: func(err error) bool { return errors.Is(err, errMemoryMissing) }}
	first, err := source.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first.Destroy()
	if err := store.Delete(source.genesisReference()); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Load(context.Background()); !errors.Is(err, ErrGenesisMarkerMissing) {
		t.Fatalf("missing marker was recreated: %v", err)
	}
	if _, err := store.Get(source.genesisReference()); !errors.Is(err, errMemoryMissing) {
		t.Fatalf("missing marker was unexpectedly restored: %v", err)
	}
}

func TestKeyringSourceDoesNotRegenerateKeyWhenMarkerSurvivesKeyLoss(t *testing.T) {
	store := &memoryStore{}
	source := KeyringSource{Store: store, MachineID: "mch_one", Generation: 7, Random: zeroReader{}, NotFound: func(err error) bool { return errors.Is(err, errMemoryMissing) }}
	material, err := source.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	material.Destroy()
	if err := store.Delete(fmt.Sprintf("environment-host/%s/%d", source.MachineID, source.Generation)); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Load(context.Background()); !errors.Is(err, ErrGenesisMarkerInvalid) {
		t.Fatalf("surviving marker permitted key regeneration: %v", err)
	}
}

func TestKeyringSourceGenesisTransitionsOnlyForward(t *testing.T) {
	store := &memoryStore{}
	source := KeyringSource{Store: store, MachineID: "mch_one", Generation: 7, Random: zeroReader{}, NotFound: func(err error) bool { return errors.Is(err, errMemoryMissing) }}
	material, err := source.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	material.Destroy()
	if state, err := source.GenesisState(); err != nil || state != GenesisFresh {
		t.Fatalf("initial state=%q error=%v", state, err)
	}
	if err := source.PrepareGenesis(); err != nil {
		t.Fatal(err)
	}
	if state, err := source.GenesisState(); err != nil || state != GenesisPending {
		t.Fatalf("prepared state=%q error=%v", state, err)
	}
	if err := source.CommitGenesis(); err != nil {
		t.Fatal(err)
	}
	if err := source.CommitGenesis(); err != nil {
		t.Fatalf("established commit was not idempotent: %v", err)
	}
	if err := source.PrepareGenesis(); !errors.Is(err, ErrGenesisAlreadyEstablished) {
		t.Fatalf("established marker regressed: %v", err)
	}
}

func TestKeyringSourceFailsClosedWithoutSecureStore(t *testing.T) {
	store := &memoryStore{fail: true}
	_, err := (KeyringSource{Store: store, MachineID: "mch_one", Generation: 1, NotFound: func(err error) bool { return errors.Is(err, errMemoryMissing) }}).Load(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error=%v", err)
	}
	if store.sets != 0 {
		t.Fatal("an unavailable read was treated as an absent key and overwritten")
	}
}

type unmarkedStore struct{}

func (unmarkedStore) Set(string, string) error   { return nil }
func (unmarkedStore) Get(string) (string, error) { return "", errMemoryMissing }
func (unmarkedStore) Delete(string) error        { return nil }

func TestKeyringSourceRejectsUnmarkedFileStyleStore(t *testing.T) {
	_, err := (KeyringSource{Store: unmarkedStore{}, MachineID: "mch_one", Generation: 1, NotFound: func(error) bool { return true }}).Load(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unmarked store error=%v", err)
	}
}

func TestStateIntegrityKeyIsStableAndGenerationBound(t *testing.T) {
	material := Material{Generation: 3}
	copy(material.Private[:], bytes.Repeat([]byte{0x31}, privateKeySize))
	first, err := material.StateIntegrityKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := material.StateIntegrityKey()
	if err != nil || first != second {
		t.Fatalf("second derivation mismatch: %v", err)
	}
	material.Generation++
	next, err := material.StateIntegrityKey()
	if err != nil || first == next {
		t.Fatalf("generation did not change state key: %v", err)
	}
}

type zeroReader struct{ offset byte }

func (r zeroReader) Read(value []byte) (int, error) {
	for index := range value {
		value[index] = byte(index) + r.offset + 1
	}
	return len(value), nil
}
