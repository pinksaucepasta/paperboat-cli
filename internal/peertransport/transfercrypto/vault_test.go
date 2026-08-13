package transfercrypto

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type memorySecrets struct {
	mu        sync.Mutex
	items     map[string]string
	deleteErr error
}

func (m *memorySecrets) Set(ref, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[ref] = value
	return nil
}
func (m *memorySecrets) Get(ref string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.items[ref]
	if !ok {
		return "", errors.New("missing")
	}
	return value, nil
}
func (m *memorySecrets) Delete(ref string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.items, ref)
	return nil
}

func TestKeyVaultReportsExpiredKeyDeletionFailure(t *testing.T) {
	deleteErr := errors.New("credential store unavailable")
	store := &memorySecrets{items: make(map[string]string)}
	vault, _ := NewKeyVault(store)
	now := time.Unix(100, 0).UTC()
	vault.now = func() time.Time { return now }
	if err := vault.Save("transfer_04", 1, testMaterial(), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	store.deleteErr = deleteErr
	now = now.Add(2 * time.Hour)
	got, err := vault.Load("transfer_04", 1)
	if !errors.Is(err, ErrKeyUnavailable) || !errors.Is(err, deleteErr) {
		t.Fatalf("err=%v", err)
	}
	if got.Valid() {
		t.Fatal("expired state returned valid key material")
	}
}

func TestKeyVaultBindsGenerationAndExpires(t *testing.T) {
	store := &memorySecrets{items: make(map[string]string)}
	vault, err := NewKeyVault(store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	vault.now = func() time.Time { return now }
	material, err := GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.Save("transfer_01", 3, material, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := vault.Load("transfer_01", 3)
	if err != nil || got != material {
		t.Fatalf("got=%v err=%v", got, err)
	}
	if _, err := vault.Load("transfer_01", 4); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("generation err=%v", err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := vault.Load("transfer_01", 3); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("expiry err=%v", err)
	}
	if _, ok := store.items[keyRef("transfer_01")]; ok {
		t.Fatal("expired transfer key retained")
	}
}

func TestKeyVaultDeleteRemovesMaterial(t *testing.T) {
	store := &memorySecrets{items: make(map[string]string)}
	vault, _ := NewKeyVault(store)
	material, _ := GenerateKeyMaterial()
	if err := vault.Save("transfer_02", 1, material, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := vault.Delete("transfer_02"); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Load("transfer_02", 1); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("load after delete=%v", err)
	}
}

func TestKeyVaultRejectsInvalidInput(t *testing.T) {
	vault, _ := NewKeyVault(&memorySecrets{items: make(map[string]string)})
	if err := vault.Save("../escape", 1, KeyMaterial{}, time.Now().Add(time.Hour)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err=%v", err)
	}
}

func TestKeyVaultRejectsNonCanonicalPersistedState(t *testing.T) {
	const transferID = "transfer_03"
	store := &memorySecrets{items: make(map[string]string)}
	vault, _ := NewKeyVault(store)
	now := time.Unix(100, 0).UTC()
	vault.now = func() time.Time { return now }
	material := testMaterial()
	if err := vault.Save(transferID, 2, material, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	canonical := store.items[keyRef(transferID)]

	var persisted persistedKey
	if err := json.Unmarshal([]byte(canonical), &persisted); err != nil {
		t.Fatal(err)
	}
	paddedBase64 := strings.Replace(canonical, persisted.KeyMaterial, persisted.KeyMaterial+"=", 1)

	tests := map[string]string{
		"unknown field":      strings.TrimSuffix(canonical, "}") + `,"unknown":true}`,
		"duplicate field":    strings.Replace(canonical, `"version":1`, `"version":1,"version":1`, 1),
		"trailing JSON":      canonical + `{}`,
		"leading whitespace": " " + canonical,
		"padded base64":      paddedBase64,
		"non-UTC expiry": strings.Replace(
			canonical,
			persisted.ExpiresAt.Format(time.RFC3339),
			persisted.ExpiresAt.In(time.FixedZone("", -3600)).Format(time.RFC3339),
			1,
		),
		"oversized value": strings.Repeat("x", maxPersistedKeySize+1),
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			store.items[keyRef(transferID)] = value
			got, err := vault.Load(transferID, 2)
			if !errors.Is(err, ErrKeyUnavailable) {
				t.Fatalf("err=%v", err)
			}
			if got.Valid() {
				t.Fatal("malformed state returned valid key material")
			}
		})
	}
}
