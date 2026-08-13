package config

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
)

type peerTestSecretStore struct {
	values    map[string]string
	setCount  int
	failSetAt int
}

func (s *peerTestSecretStore) Set(ref, value string) error {
	s.setCount++
	if s.failSetAt > 0 && s.setCount == s.failSetAt {
		return errors.New("injected peer identity write failure")
	}
	s.values[ref] = value
	return nil
}
func (s *peerTestSecretStore) Get(ref string) (string, error) {
	value, ok := s.values[ref]
	if !ok {
		return "", ErrSecretNotFound
	}
	return value, nil
}
func (s *peerTestSecretStore) Delete(ref string) error {
	delete(s.values, ref)
	return nil
}

func TestPeerIdentityKeysCreateAndReplaySeparateRecords(t *testing.T) {
	root := t.TempDir()
	secrets := &peerTestSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: root, Secrets: secrets}
	first, err := store.PeerIdentityKeys("https://api.example.test", "account_1", "cli_1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.PeerIdentityKeys("https://api.example.test", "account_1", "cli_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.RootPrivate) != ed25519.PrivateKeySize || len(first.QUICPrivate) != ed25519.PrivateKeySize || first.NoisePrivate == [32]byte{} || first.NoisePublic == [32]byte{} || !bytes.Equal(first.RootPrivate, second.RootPrivate) || first.NoisePrivate != second.NoisePrivate || !bytes.Equal(first.QUICPrivate, second.QUICPrivate) {
		t.Fatalf("identity replay mismatch")
	}
	if len(secrets.values) != 3 {
		t.Fatalf("stored records=%d", len(secrets.values))
	}
	for _, value := range secrets.values {
		if bytes.Contains([]byte(value), first.RootPrivate) || bytes.Contains([]byte(value), first.QUICPrivate) {
			t.Fatal("raw private key stored without typed encoding")
		}
	}
}

func TestPeerIdentityKeysRejectsPartialEndpointCustody(t *testing.T) {
	root := t.TempDir()
	secrets := &peerTestSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: root, Secrets: secrets}
	issuer, _ := NormalizeIssuer("https://api.example.test")
	if err := storePeerKey(secrets, peerIdentitySecretRef(issuer, "cli_1", "endpoint-noise"), "endpoint_noise_x25519", bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PeerIdentityKeys(issuer, "account_1", "cli_1"); err == nil {
		t.Fatal("partial endpoint identity accepted")
	}
}

func TestPeerIdentityKeysRollsBackFailedCreation(t *testing.T) {
	root := t.TempDir()
	secrets := &peerTestSecretStore{values: map[string]string{}, failSetAt: 3}
	store := ProfileStore{Path: root, Secrets: secrets}
	identity, err := store.PeerIdentityKeys("https://api.example.test", "account_1", "cli_1")
	if err == nil || identity.RootPrivate != nil || identity.QUICPrivate != nil || identity.NoisePrivate != [32]byte{} || len(secrets.values) != 0 {
		t.Fatalf("identity=%+v values=%d err=%v", identity, len(secrets.values), err)
	}
}

func TestPeerIdentityKeysUsesProfileScopedLock(t *testing.T) {
	root := t.TempDir()
	store := ProfileStore{Path: root, Secrets: FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	if _, err := store.PeerIdentityKeys("https://api.example.test", "bad\naccount", "cli_1"); !errors.Is(err, ErrCredentialStoreUnavailable) {
		t.Fatalf("err=%v", err)
	}
}

func TestPeerCertificateStatePersistsExactReplayAndRejectsReplacement(t *testing.T) {
	root := t.TempDir()
	secrets := &peerTestSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: root, Secrets: secrets}
	raw := bytes.Repeat([]byte{7}, 172)
	first, err := store.SavePeerCertificate("https://api.example.test", "cli_1", raw)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadPeerCertificate("https://api.example.test", "cli_1")
	if err != nil || !bytes.Equal(first.Raw, loaded.Raw) {
		t.Fatalf("loaded=%x err=%v", loaded.Raw, err)
	}
	if _, err := store.SavePeerCertificate("https://api.example.test", "cli_1", bytes.Repeat([]byte{8}, 172)); err == nil {
		t.Fatal("certificate replacement accepted outside rotation")
	}
}

func TestPeerIdentityKeysForExistingRootNeverCreatesRoot(t *testing.T) {
	root := t.TempDir()
	secrets := &peerTestSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: root, Secrets: secrets}
	if _, err := store.PeerIdentityKeysForExistingRoot("https://api.example.test", "account_1", "cli_1"); !errors.Is(err, ErrSecretNotFound) || len(secrets.values) != 0 {
		t.Fatalf("values=%d err=%v", len(secrets.values), err)
	}
}

func TestPeerAccountRootExportImportIsConflictSafe(t *testing.T) {
	issuer := "https://api.example.test"
	accountID := "account_1"
	source := ProfileStore{Path: t.TempDir(), Secrets: &peerTestSecretStore{values: map[string]string{}}}
	identity, err := source.PeerIdentityKeys(issuer, accountID, "cli_1")
	if err != nil {
		t.Fatal(err)
	}
	seed, err := source.ExportPeerAccountRootSeed(issuer, accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	if !bytes.Equal(ed25519.NewKeyFromSeed(seed), identity.RootPrivate) {
		t.Fatal("exported root seed differs")
	}
	target := ProfileStore{Path: t.TempDir(), Secrets: &peerTestSecretStore{values: map[string]string{}}}
	if err := target.ImportPeerAccountRootSeed(issuer, accountID, seed); err != nil {
		t.Fatal(err)
	}
	if err := target.ImportPeerAccountRootSeed(issuer, accountID, seed); err != nil {
		t.Fatalf("idempotent import: %v", err)
	}
	conflict := append([]byte(nil), seed...)
	conflict[0] ^= 1
	defer clear(conflict)
	if err := target.ImportPeerAccountRootSeed(issuer, accountID, conflict); err == nil {
		t.Fatal("conflicting root import accepted")
	}
}

func TestProfileRemovalErasesPeerIdentityCustody(t *testing.T) {
	root := t.TempDir()
	secrets := &peerTestSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: root, Secrets: secrets}
	issuer := "https://api.example.test"
	if _, err := store.PeerIdentityKeys(issuer, "account_1", "cli_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SavePeerCertificate(issuer, "cli_1", bytes.Repeat([]byte{7}, 172)); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(Profile{Issuer: issuer, Account: Account{ID: "account_1"}, CLIClientSessionID: "cli_1"}, Credential{AccessToken: "access", RefreshToken: "refresh"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Remove(issuer); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{peerIdentitySecretRef(issuer, "account_1", "account-root"), peerIdentitySecretRef(issuer, "cli_1", "endpoint-noise"), peerIdentitySecretRef(issuer, "cli_1", "endpoint-quic"), peerIdentitySecretRef(issuer, "cli_1", "endpoint-certificate")} {
		if _, err := secrets.Get(ref); !errors.Is(err, ErrSecretNotFound) {
			t.Fatalf("secret %s remains: %v", ref, err)
		}
	}
}
