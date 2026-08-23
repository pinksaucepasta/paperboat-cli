package config

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type faultSecretStore struct {
	values        map[string]string
	failAccess    bool
	failDeleteRef string
}

type unlockTamperingSecretStore struct {
	root   string
	values map[string]string
}

func (s *unlockTamperingSecretStore) Set(ref, value string) error {
	s.values[ref] = value
	return filepath.WalkDir(s.root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && entry.Name() == "owner.json" && strings.HasSuffix(filepath.Dir(path), ".lock.d") {
			return os.WriteFile(path, []byte("invalid lock owner"), 0o600)
		}
		return nil
	})
}

func (s *unlockTamperingSecretStore) Get(ref string) (string, error) {
	value, ok := s.values[ref]
	if !ok {
		return "", ErrSecretNotFound
	}
	return value, nil
}

func (s *unlockTamperingSecretStore) Delete(ref string) error {
	delete(s.values, ref)
	return nil
}

func (s *faultSecretStore) Set(ref, value string) error {
	if s.failAccess && strings.HasSuffix(ref, "-access") {
		return errors.New("injected access write failure")
	}
	s.values[ref] = value
	return nil
}
func (s *faultSecretStore) Get(ref string) (string, error) {
	value, ok := s.values[ref]
	if !ok {
		return "", os.ErrNotExist
	}
	return value, nil
}
func (s *faultSecretStore) Delete(ref string) error {
	if ref == s.failDeleteRef {
		return errors.New("injected secret deletion failure")
	}
	delete(s.values, ref)
	return nil
}

func TestProfileStoreSeparatesMetadataAndSecrets(t *testing.T) {
	dir := t.TempDir()
	store := ProfileStore{Path: dir, Secrets: FileSecretStore{Dir: filepath.Join(dir, "secrets")}}
	p := Profile{Issuer: "HTTPS://API.Example.COM/", CLIClientSessionID: "cls_1", AccessExpiresAt: time.Now().UTC()}
	if err := store.Save(p, Credential{AccessToken: "access-secret", RefreshToken: "refresh-secret"}); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load("https://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(store.profilePath(loaded.Issuer))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "access-secret") || strings.Contains(string(b), "refresh-secret") {
		t.Fatal("profile metadata contains token values")
	}
	cred, err := store.CredentialFor(loaded.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken != "access-secret" || cred.RefreshToken != "refresh-secret" {
		t.Fatalf("credential = %#v", cred)
	}
}

func TestInitialSaveDoesNotOverwriteProfileCreatedWhileWaiting(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	first := Profile{Issuer: issuer, CLIClientSessionID: "cls_first"}
	if err := store.Save(first, Credential{AccessToken: "access-first", RefreshToken: "refresh-first"}); err != nil {
		t.Fatal(err)
	}
	second := Profile{Issuer: issuer, CLIClientSessionID: "cls_second"}
	if err := store.Save(second, Credential{AccessToken: "access-second", RefreshToken: "refresh-second"}); !errors.Is(err, ErrProfileExists) {
		t.Fatalf("second save err = %v", err)
	}
	loaded, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := store.CredentialFor(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CLIClientSessionID != "cls_first" || cred.AccessToken != "access-first" || cred.RefreshToken != "refresh-first" {
		t.Fatalf("profile = %#v, credential = %#v", loaded, cred)
	}
}

func TestInitialSaveAccessFailureRemovesStoredRefreshSecret(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}, failAccess: true}
	store := ProfileStore{Path: dir, Secrets: secrets}
	p := Profile{Issuer: "https://api.example.com", CLIClientSessionID: "cls_1"}
	if err := store.Save(p, Credential{AccessToken: "access", RefreshToken: "refresh"}); err == nil {
		t.Fatal("expected access write failure")
	}
	if len(secrets.values) != 0 {
		t.Fatalf("orphaned secrets = %#v", secrets.values)
	}
}

func TestProfileMutationReportsSharedLockReleaseFailure(t *testing.T) {
	dir := t.TempDir()
	secrets := &unlockTamperingSecretStore{root: dir, values: make(map[string]string)}
	store := ProfileStore{Path: dir, Secrets: secrets}
	err := store.Save(Profile{Issuer: "https://api.example.com", CLIClientSessionID: "cls_1"}, Credential{AccessToken: "access", RefreshToken: "refresh"})
	if err == nil {
		t.Fatalf("release error=%v", err)
	}
}

func TestInitialSaveMetadataFailureRemovesStoredSecrets(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer, err := NormalizeIssuer("https://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	profilePath := store.profilePath(issuer)
	if err := os.MkdirAll(profilePath, 0o700); err != nil {
		t.Fatal(err)
	}
	p := Profile{Issuer: issuer, CLIClientSessionID: "cls_1"}
	if err := store.Save(p, Credential{AccessToken: "access", RefreshToken: "refresh"}); err == nil {
		t.Fatal("expected metadata write failure")
	}
	if len(secrets.values) != 0 {
		t.Fatalf("orphaned secrets = %#v", secrets.values)
	}
}

func TestInitialSaveRejectsEmptyCredentialWithoutMutation(t *testing.T) {
	for name, credential := range map[string]Credential{
		"access":  {RefreshToken: "refresh"},
		"refresh": {AccessToken: "access"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			secrets := &faultSecretStore{values: map[string]string{}}
			store := ProfileStore{Path: dir, Secrets: secrets}
			err := store.Save(Profile{Issuer: "https://api.example.com", CLIClientSessionID: "cls_1"}, credential)
			if err == nil {
				t.Fatal("expected incomplete credential rejection")
			}
			if len(secrets.values) != 0 {
				t.Fatalf("stored secrets = %#v", secrets.values)
			}
			if _, statErr := os.Stat(store.profilePath("https://api.example.com")); !os.IsNotExist(statErr) {
				t.Fatalf("profile metadata exists after rejection: %v", statErr)
			}
		})
	}
}

func TestCredentialForRejectsPersistedEmptyToken(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, CLIClientSessionID: "cls_1"}, Credential{AccessToken: "access", RefreshToken: "refresh"}); err != nil {
		t.Fatal(err)
	}
	profile, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	secrets.values[profile.RefreshSecretRef] = ""
	if _, err := store.CredentialFor(issuer); err == nil {
		t.Fatal("expected persisted empty token rejection")
	}
}

func TestRepairMissingAccessPreservesActiveUntilCommitAndQueuesOldRefresh(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	old := Profile{Issuer: issuer, CLIClientSessionID: "cls_old", Account: Account{ID: "acct_old"}}
	if err := store.Save(old, Credential{AccessToken: "access-old", RefreshToken: "refresh-old"}); err != nil {
		t.Fatal(err)
	}
	previous, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.Delete(previous.AccessSecretRef); err != nil {
		t.Fatal(err)
	}
	if err := store.Repair(previous.CLIClientSessionID, Profile{Issuer: issuer, CLIClientSessionID: "cls_new", Account: Account{ID: "acct_new"}}, Credential{AccessToken: "access-new", RefreshToken: "refresh-new"}); err != nil {
		t.Fatal(err)
	}
	active, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if active.CLIClientSessionID != "cls_new" || active.Account.ID != "acct_new" {
		t.Fatalf("active profile = %#v", active)
	}
	credential, err := store.CredentialFor(issuer)
	if err != nil || credential.AccessToken != "access-new" || credential.RefreshToken != "refresh-new" {
		t.Fatalf("credential = %#v, err = %v", credential, err)
	}
	records, err := store.PendingRevocations(issuer)
	if err != nil || len(records) != 1 {
		t.Fatalf("pending revocations = %#v, err = %v", records, err)
	}
	if records[0].CLIClientSessionID != "cls_old" {
		t.Fatalf("record = %#v", records[0])
	}
}

func TestRepairMissingOrEmptyRefreshDoesNotInventRevocation(t *testing.T) {
	for _, value := range []string{"missing", "empty"} {
		t.Run(value, func(t *testing.T) {
			dir := t.TempDir()
			secrets := &faultSecretStore{values: map[string]string{}}
			store := ProfileStore{Path: dir, Secrets: secrets}
			issuer := "https://api.example.com"
			if err := store.Save(Profile{Issuer: issuer, CLIClientSessionID: "cls_old"}, Credential{AccessToken: "access-old", RefreshToken: "refresh-old"}); err != nil {
				t.Fatal(err)
			}
			previous, err := store.Load(issuer)
			if err != nil {
				t.Fatal(err)
			}
			if value == "missing" {
				if err := secrets.Delete(previous.RefreshSecretRef); err != nil {
					t.Fatal(err)
				}
			} else {
				secrets.values[previous.RefreshSecretRef] = ""
			}
			if err := store.Repair(previous.CLIClientSessionID, Profile{Issuer: issuer, CLIClientSessionID: "cls_new"}, Credential{AccessToken: "access-new", RefreshToken: "refresh-new"}); err != nil {
				t.Fatal(err)
			}
			active, err := store.Load(issuer)
			if err != nil || active.CLIClientSessionID != "cls_new" {
				t.Fatalf("active = %#v, err = %v", active, err)
			}
			records, err := store.PendingRevocations(issuer)
			if err != nil || len(records) != 0 {
				t.Fatalf("pending revocations = %#v, err = %v", records, err)
			}
		})
	}
}

func TestRepairCommitFailureLeavesCorruptActiveProfileUntouched(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, CLIClientSessionID: "cls_old"}, Credential{AccessToken: "access-old", RefreshToken: "refresh-old"}); err != nil {
		t.Fatal(err)
	}
	previous, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.Delete(previous.AccessSecretRef); err != nil {
		t.Fatal(err)
	}
	store.write = func(string, []byte, os.FileMode) error { return errors.New("injected repair commit failure") }
	if err := store.Repair(previous.CLIClientSessionID, Profile{Issuer: issuer, CLIClientSessionID: "cls_new"}, Credential{AccessToken: "access-new", RefreshToken: "refresh-new"}); err == nil {
		t.Fatal("expected repair commit failure")
	}
	active, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if active.CLIClientSessionID != previous.CLIClientSessionID || active.AccessSecretRef != previous.AccessSecretRef || active.RefreshSecretRef != previous.RefreshSecretRef {
		t.Fatalf("active profile changed after failed repair: %#v", active)
	}
	if _, err := store.CredentialFor(issuer); !errors.Is(err, ErrSecretNotFound) && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential error = %v, want missing active access secret", err)
	}
	if records, err := store.PendingRevocations(issuer); err != nil || len(records) != 1 || records[0].CLIClientSessionID != "cls_new" {
		t.Fatalf("pending revocations = %#v, err = %v", records, err)
	}
	if _, err := os.Stat(store.authTransactionPath(issuer)); !os.IsNotExist(err) {
		t.Fatalf("transaction remains after handled failure: %v", err)
	}
}

func TestRecoverInterruptedTransactionQueuesAbandonedNewSession(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, CLIClientSessionID: "cls_old"}, Credential{AccessToken: "access-old", RefreshToken: "refresh-old"}); err != nil {
		t.Fatal(err)
	}
	previous, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	accessRef, refreshRef, err := newSecretRefs(issuer)
	if err != nil {
		t.Fatal(err)
	}
	next := Profile{Version: ProfileVersion, Issuer: issuer, CLIClientSessionID: "cls_new", AccessSecretRef: accessRef, RefreshSecretRef: refreshRef}
	tx := AuthTransaction{Version: authTransactionVersion, Operation: "switch", Issuer: issuer, Previous: previous, Next: next, State: authTransactionPrepared, CreatedAt: time.Now().UTC()}
	if err := store.writeAuthTransaction(tx); err != nil {
		t.Fatal(err)
	}
	if err := secrets.Set(accessRef, "access-new"); err != nil {
		t.Fatal(err)
	}
	if err := secrets.Set(refreshRef, "refresh-new"); err != nil {
		t.Fatal(err)
	}
	restarted := ProfileStore{Path: dir, Secrets: secrets}
	if err := restarted.Recover(issuer); err != nil {
		t.Fatal(err)
	}
	active, err := restarted.Load(issuer)
	if err != nil || active.CLIClientSessionID != "cls_old" {
		t.Fatalf("active = %#v, err = %v", active, err)
	}
	if _, err := secrets.Get(accessRef); !errors.Is(err, ErrSecretNotFound) && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged access secret remains: %v", err)
	}
	if _, err := secrets.Get(refreshRef); !errors.Is(err, ErrSecretNotFound) && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged refresh secret remains: %v", err)
	}
	records, err := restarted.PendingRevocations(issuer)
	if err != nil || len(records) != 1 {
		t.Fatalf("pending revocations = %#v, err = %v", records, err)
	}
	recovered, err := restarted.PendingRevocationCredential(records[0])
	if err != nil || recovered.RefreshToken != "refresh-new" {
		t.Fatalf("recovered = %#v, err = %v", recovered, err)
	}
	if _, err := os.Stat(restarted.authTransactionPath(issuer)); !os.IsNotExist(err) {
		t.Fatalf("transaction remains after recovery: %v", err)
	}
}

func TestFileSecretStoreRejectsLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := FileSecretStore{Dir: dir}
	p := s.path("bad")
	if err := writeTestCredential(p, "secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("bad"); err == nil || !credentialPermissionError(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestIssuerNamespacing(t *testing.T) {
	a, _ := NormalizeIssuer("https://API.example.com/")
	b, _ := NormalizeIssuer("https://staging.example.com")
	if a != "https://api.example.com" {
		t.Fatalf("normalized = %q", a)
	}
	if profileKey(a) == profileKey(b) {
		t.Fatal("distinct issuers collided")
	}
}

func TestNormalizeIssuerRemovesDefaultPorts(t *testing.T) {
	for input, want := range map[string]string{
		"https://API.example.com:443/":  "https://api.example.com",
		"http://API.example.com:80/":    "http://api.example.com",
		"https://API.example.com:8443/": "https://api.example.com:8443",
		"https://[::1]:443/":            "https://[::1]",
	} {
		got, err := NormalizeIssuer(input)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("NormalizeIssuer(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCredentialOperationsWithholdTokensWhenUnlockFails(t *testing.T) {
	want := errors.New("unlock failed")
	newStore := func(t *testing.T, expiresAt time.Time) (ProfileStore, string) {
		t.Helper()
		dir := t.TempDir()
		store := ProfileStore{Path: dir, Secrets: FileSecretStore{Dir: filepath.Join(dir, "secrets")}}
		issuer := "https://api.example.com"
		if err := store.Save(Profile{Issuer: issuer, CLIClientSessionID: "cls_1", AccessExpiresAt: expiresAt}, Credential{AccessToken: "access-old", RefreshToken: "refresh-old", ExpiresAt: expiresAt}); err != nil {
			t.Fatal(err)
		}
		return store, issuer
	}

	t.Run("cached", func(t *testing.T) {
		store, issuer := newStore(t, time.Now().Add(time.Hour))
		credential, err := store.credentialWithRefresh(issuer, time.Minute, nil, failingCredentialLock{unlock: want})
		if !errors.Is(err, want) || credential != (Credential{}) {
			t.Fatalf("credential=%+v error=%v", credential, err)
		}
	})

	t.Run("refreshed", func(t *testing.T) {
		store, issuer := newStore(t, time.Now().Add(-time.Minute))
		credential, err := store.credentialWithRefresh(issuer, time.Minute, func(Credential) (Credential, string, error) {
			return Credential{AccessToken: "access-new", RefreshToken: "refresh-new", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour)}, "cls_1", nil
		}, failingCredentialLock{unlock: want})
		if !errors.Is(err, want) || credential != (Credential{}) {
			t.Fatalf("credential=%+v error=%v", credential, err)
		}
	})

	t.Run("remove", func(t *testing.T) {
		store, issuer := newStore(t, time.Now().Add(time.Hour))
		credential, err := store.removeCredential(issuer, failingCredentialLock{unlock: want})
		if !errors.Is(err, want) || credential != (Credential{}) {
			t.Fatalf("credential=%+v error=%v", credential, err)
		}
	})
}

func TestRefreshWriteFailurePreservesRotatedRefreshToken(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	expired := time.Now().Add(-time.Minute)
	profile := Profile{Issuer: "https://api.example.com", CLIClientSessionID: "cls_1", AccessExpiresAt: expired}
	if err := store.Save(profile, Credential{AccessToken: "access-old", RefreshToken: "refresh-old", ExpiresAt: expired}); err != nil {
		t.Fatal(err)
	}
	secrets.failAccess = true
	_, err := store.CredentialWithRefresh(profile.Issuer, time.Minute, func(Credential) (Credential, string, error) {
		return Credential{AccessToken: "access-new", RefreshToken: "refresh-new", ExpiresAt: time.Now().Add(time.Hour)}, "cls_1", nil
	})
	if err == nil {
		t.Fatal("expected access-token write failure")
	}
	loaded, err := store.Load(profile.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if got := secrets.values[loaded.RefreshSecretRef]; got != "refresh-new" {
		t.Fatalf("refresh token = %q", got)
	}
	if got := secrets.values[loaded.AccessSecretRef]; got != "access-old" {
		t.Fatalf("access token = %q", got)
	}
}

func TestRefreshProfileCommitFailureKeepsNewTokensAndExpiredMetadata(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	expired := time.Now().Add(-time.Minute).UTC()
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, CLIClientSessionID: "cls_1", AccessExpiresAt: expired}, Credential{AccessToken: "access-old", RefreshToken: "refresh-old", ExpiresAt: expired}); err != nil {
		t.Fatal(err)
	}
	store.write = func(string, []byte, os.FileMode) error { return errors.New("injected profile commit failure") }
	_, err := store.CredentialWithRefresh(issuer, time.Minute, func(Credential) (Credential, string, error) {
		return Credential{AccessToken: "access-new", RefreshToken: "refresh-new", ExpiresAt: time.Now().Add(time.Hour)}, "cls_1", nil
	})
	if err == nil {
		t.Fatal("expected profile commit failure")
	}
	profile, loadErr := store.Load(issuer)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	credential, credentialErr := store.CredentialFor(issuer)
	if credentialErr != nil {
		t.Fatal(credentialErr)
	}
	if credential.AccessToken != "access-new" || credential.RefreshToken != "refresh-new" {
		t.Fatalf("credential = %#v", credential)
	}
	if !profile.AccessExpiresAt.Equal(expired) {
		t.Fatalf("profile expiry = %s, want retry-forcing %s", profile.AccessExpiresAt, expired)
	}
}

func TestRefreshSessionMismatchQuarantinesRotatedCredential(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	expired := time.Now().Add(-time.Minute)
	profile := Profile{Issuer: "https://api.example.com", CLIClientSessionID: "cls_1", AccessExpiresAt: expired}
	if err := store.Save(profile, Credential{AccessToken: "access-old", RefreshToken: "refresh-old", ExpiresAt: expired}); err != nil {
		t.Fatal(err)
	}
	nextExpiry := time.Now().Add(time.Hour)
	_, err := store.CredentialWithRefresh(profile.Issuer, time.Minute, func(Credential) (Credential, string, error) {
		return Credential{AccessToken: "access-new", RefreshToken: "refresh-new", ExpiresAt: nextExpiry}, "cls_unexpected", nil
	})
	if err == nil || !strings.Contains(err.Error(), "changed client session") {
		t.Fatalf("err = %v", err)
	}
	if _, err := store.Load(profile.Issuer); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("profile load err = %v", err)
	}
	records, err := store.PendingRevocations(profile.Issuer)
	if err != nil || len(records) != 1 {
		t.Fatalf("records = %#v, err = %v", records, err)
	}
	recovery, err := store.PendingRevocationCredential(records[0])
	if err != nil {
		t.Fatal(err)
	}
	if records[0].CLIClientSessionID != "cls_unexpected" || recovery.RefreshToken != "refresh-new" {
		t.Fatalf("record = %#v, credential = %#v", records[0], recovery)
	}
}

func TestReplaceWriteFailureRestoresPreviousCredentials(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	old := Profile{Issuer: "https://api.example.com", CLIClientSessionID: "cls_old", AccessExpiresAt: time.Now().Add(time.Hour)}
	if err := store.Save(old, Credential{AccessToken: "access-old", RefreshToken: "refresh-old"}); err != nil {
		t.Fatal(err)
	}
	secrets.failAccess = true
	newProfile := Profile{Issuer: old.Issuer, CLIClientSessionID: "cls_new", AccessExpiresAt: time.Now().Add(time.Hour)}
	if err := store.Replace(newProfile, Credential{AccessToken: "access-new", RefreshToken: "refresh-new"}); err == nil {
		t.Fatal("expected replacement failure")
	}
	secrets.failAccess = false
	loaded, err := store.Load(old.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := store.CredentialFor(old.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CLIClientSessionID != "cls_old" || cred.AccessToken != "access-old" || cred.RefreshToken != "refresh-old" {
		t.Fatalf("profile = %#v, credential = %#v", loaded, cred)
	}
}

func TestReplaceProfileCommitFailureKeepsPreviousCredentialPair(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, CLIClientSessionID: "cls_old"}, Credential{AccessToken: "access-old", RefreshToken: "refresh-old"}); err != nil {
		t.Fatal(err)
	}
	previous, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	store.write = func(string, []byte, os.FileMode) error { return errors.New("injected profile commit failure") }
	if err := store.Replace(Profile{Issuer: issuer, CLIClientSessionID: "cls_new"}, Credential{AccessToken: "access-new", RefreshToken: "refresh-new"}); err == nil {
		t.Fatal("expected replacement profile commit failure")
	}
	active, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.CredentialFor(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if active.CLIClientSessionID != "cls_old" || active.AccessSecretRef != previous.AccessSecretRef || active.RefreshSecretRef != previous.RefreshSecretRef || credential.AccessToken != "access-old" || credential.RefreshToken != "refresh-old" {
		t.Fatalf("active = %#v, credential = %#v", active, credential)
	}
	if len(secrets.values) != 2 {
		t.Fatalf("replacement secrets were not rolled back: %#v", secrets.values)
	}
}

func TestSwitchRejectsChangedExpectedSessionWithoutQueueing(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, CLIClientSessionID: "cls_current"}, Credential{AccessToken: "access-current", RefreshToken: "refresh-current"}); err != nil {
		t.Fatal(err)
	}
	err := store.Switch("cls_stale", Profile{Issuer: issuer, CLIClientSessionID: "cls_new"}, Credential{AccessToken: "access-new", RefreshToken: "refresh-new"})
	if !errors.Is(err, ErrProfileChanged) {
		t.Fatalf("switch err = %v", err)
	}
	cred, err := store.CredentialFor(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if cred.RefreshToken != "refresh-current" {
		t.Fatalf("credential = %#v", cred)
	}
	records, err := store.PendingRevocations(issuer)
	if err != nil || len(records) != 0 {
		t.Fatalf("records = %#v, err = %v", records, err)
	}
}

func TestSwitchProfileCommitFailureKeepsPreviousCredentialAndRevocationState(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, CLIClientSessionID: "cls_old"}, Credential{AccessToken: "access-old", RefreshToken: "refresh-old"}); err != nil {
		t.Fatal(err)
	}
	previous, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	store.write = func(string, []byte, os.FileMode) error { return errors.New("injected profile commit failure") }
	if err := store.Switch("cls_old", Profile{Issuer: issuer, CLIClientSessionID: "cls_new"}, Credential{AccessToken: "access-new", RefreshToken: "refresh-new"}); err == nil {
		t.Fatal("expected switch profile commit failure")
	}
	active, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.CredentialFor(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if active.CLIClientSessionID != "cls_old" || active.AccessSecretRef != previous.AccessSecretRef || active.RefreshSecretRef != previous.RefreshSecretRef || credential.AccessToken != "access-old" || credential.RefreshToken != "refresh-old" {
		t.Fatalf("active = %#v, credential = %#v", active, credential)
	}
	records, err := store.PendingRevocations(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("rolled-back switch retained revocation records: %#v", records)
	}
	if len(secrets.values) != 2 {
		t.Fatalf("switch secrets were not rolled back: %#v", secrets.values)
	}
}

func TestPendingRevocationForActiveSessionRemainsStagedUntilSwitchCommit(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, CLIClientSessionID: "cls_old"}, Credential{AccessToken: "access-old", RefreshToken: "refresh-old"}); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueRevocation(issuer, "cls_old", "refresh-old"); err != nil {
		t.Fatal(err)
	}
	// Simulate a process restart after QueueRevocation and before the profile
	// commit. The staged record must not be exposed to a remote drain.
	restarted := ProfileStore{Path: dir, Secrets: secrets}
	records, err := restarted.PendingRevocations(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("active-session revocation became drainable: %#v", records)
	}
	if _, err := os.Stat(store.pendingRevocationPath(issuer, "cls_old")); err != nil {
		t.Fatalf("staged revocation is not durable: %v", err)
	}
	if err := restarted.Switch("cls_old", Profile{Issuer: issuer, CLIClientSessionID: "cls_new"}, Credential{AccessToken: "access-new", RefreshToken: "refresh-new"}); err != nil {
		t.Fatal(err)
	}
	records, err = restarted.PendingRevocations(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].CLIClientSessionID != "cls_old" {
		t.Fatalf("committed switch revocations = %#v", records)
	}
}

func TestSwitchDefersOldSecretDeletionFailureWithoutFailingCommittedLogin(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, CLIClientSessionID: "cls_old"}, Credential{AccessToken: "access-old", RefreshToken: "refresh-old"}); err != nil {
		t.Fatal(err)
	}
	old, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	secrets.failDeleteRef = old.AccessSecretRef
	if err := store.Switch("cls_old", Profile{Issuer: issuer, CLIClientSessionID: "cls_new"}, Credential{AccessToken: "access-new", RefreshToken: "refresh-new"}); err != nil {
		t.Fatalf("committed switch reported cleanup failure: %v", err)
	}
	active, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.CredentialFor(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if active.CLIClientSessionID != "cls_new" || credential.AccessToken != "access-new" || credential.RefreshToken != "refresh-new" {
		t.Fatalf("active = %#v, credential = %#v", active, credential)
	}
	if len(active.ObsoleteSecretRefs) != 1 || active.ObsoleteSecretRefs[0] != old.AccessSecretRef {
		t.Fatalf("deferred cleanup refs = %#v", active.ObsoleteSecretRefs)
	}
	secrets.failDeleteRef = ""
	if err := store.Switch("cls_new", Profile{Issuer: issuer, CLIClientSessionID: "cls_new"}, Credential{AccessToken: "access-newer", RefreshToken: "refresh-newer"}); err != nil {
		t.Fatal(err)
	}
	active, err = store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if len(active.ObsoleteSecretRefs) != 0 {
		t.Fatalf("deferred cleanup was not retried: %#v", active.ObsoleteSecretRefs)
	}
}

func TestReplaceDefersOldSecretDeletionFailureAfterProfileCommit(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, CLIClientSessionID: "cls_old"}, Credential{AccessToken: "access-old", RefreshToken: "refresh-old"}); err != nil {
		t.Fatal(err)
	}
	old, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	secrets.failDeleteRef = old.RefreshSecretRef
	if err := store.Replace(Profile{Issuer: issuer, CLIClientSessionID: "cls_new"}, Credential{AccessToken: "access-new", RefreshToken: "refresh-new"}); err != nil {
		t.Fatalf("committed replace reported cleanup failure: %v", err)
	}
	active, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.CredentialFor(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if active.CLIClientSessionID != "cls_new" || credential.AccessToken != "access-new" || credential.RefreshToken != "refresh-new" {
		t.Fatalf("active = %#v, credential = %#v", active, credential)
	}
	if len(active.ObsoleteSecretRefs) != 1 || active.ObsoleteSecretRefs[0] != old.RefreshSecretRef {
		t.Fatalf("deferred cleanup refs = %#v", active.ObsoleteSecretRefs)
	}
}

func TestQueueRevocationPersistsSeparateSecretReference(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	if err := store.QueueRevocation("https://api.example.com", "cls_old", "refresh-old"); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueRevocation("https://api.example.com", "cls_new", "refresh-new"); err != nil {
		t.Fatal(err)
	}
	records, err := store.PendingRevocations("https://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d", len(records))
	}
	if records[0].RefreshSecretRef == records[1].RefreshSecretRef {
		t.Fatal("pending sessions share a secret reference")
	}
	for _, record := range records {
		cred, err := store.PendingRevocationCredential(record)
		if err != nil {
			t.Fatal(err)
		}
		if cred.RefreshToken == "" {
			t.Fatal("empty pending refresh token")
		}
	}
}

func TestDiscardPendingRevocationsRemovesValidAndMalformedRecords(t *testing.T) {
	dir := t.TempDir()
	secrets := FileSecretStore{Dir: filepath.Join(dir, "secrets")}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.QueueRevocation(issuer, "cls_valid", "refresh-valid"); err != nil {
		t.Fatal(err)
	}
	pendingDir := filepath.Join(dir, "pending-revocations")
	malformedPath := filepath.Join(pendingDir, profileKey(issuer)+"-malformed.json")
	if err := os.WriteFile(malformedPath, []byte(`{"issuer":"https://api.example.com"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.DiscardPendingRevocations(issuer); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(pendingDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), profileKey(issuer)+"-") {
			t.Fatalf("issuer revocation metadata remains: %s", entry.Name())
		}
	}
	if _, err := secrets.Get(pendingRefreshRef(issuer, "cls_valid")); err == nil {
		t.Fatal("valid pending refresh secret remains")
	}
}

func TestPendingRevocationsIgnoreMalformedForeignNamespace(t *testing.T) {
	dir := t.TempDir()
	store := ProfileStore{Path: dir, Secrets: &faultSecretStore{values: map[string]string{}}}
	issuer := "https://api.example.com"
	if err := store.QueueRevocation(issuer, "cls_1", "refresh"); err != nil {
		t.Fatal(err)
	}
	foreignIssuer, err := NormalizeIssuer("https://staging.example.com")
	if err != nil {
		t.Fatal(err)
	}
	foreignPath := filepath.Join(dir, "pending-revocations", profileKey(foreignIssuer)+"-broken.json")
	if err := os.WriteFile(foreignPath, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	records, err := store.PendingRevocations(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].CLIClientSessionID != "cls_1" {
		t.Fatalf("records = %#v", records)
	}
}

func TestDiscardRevocationRemovesQueuedCopy(t *testing.T) {
	dir := t.TempDir()
	store := ProfileStore{Path: dir, Secrets: &faultSecretStore{values: map[string]string{}}}
	issuer := "https://api.example.com"
	if err := store.QueueRevocation(issuer, "cls_old", "refresh-old"); err != nil {
		t.Fatal(err)
	}
	if err := store.DiscardRevocation(issuer, "cls_old"); err != nil {
		t.Fatal(err)
	}
	records, err := store.PendingRevocations(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("records = %#v", records)
	}
}

func TestQueueActiveRevocationRetriesAfterPartialSecretDeletion(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	p := Profile{Issuer: "https://api.example.com", CLIClientSessionID: "cls_1", AccessExpiresAt: time.Now().Add(time.Hour)}
	if err := store.Save(p, Credential{AccessToken: "access", RefreshToken: "refresh"}); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(p.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	secrets.failDeleteRef = loaded.AccessSecretRef
	if err := store.QueueActiveRevocation(p.Issuer); err == nil {
		t.Fatal("expected partial deletion failure")
	}
	if _, ok := secrets.values[loaded.RefreshSecretRef]; ok {
		t.Fatal("refresh secret should have been deleted")
	}
	secrets.failDeleteRef = ""
	if err := store.QueueActiveRevocation(p.Issuer); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(p.Issuer); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("profile load err = %v", err)
	}
}

func TestCompleteRevocationKeepsMetadataUntilSecretDeletionSucceeds(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	if err := store.QueueRevocation("https://api.example.com", "cls_1", "refresh"); err != nil {
		t.Fatal(err)
	}
	records, err := store.PendingRevocations("https://api.example.com")
	if err != nil || len(records) != 1 {
		t.Fatalf("records = %#v, err = %v", records, err)
	}
	secrets.failDeleteRef = records[0].RefreshSecretRef
	if err := store.CompleteRevocation(records[0]); err == nil {
		t.Fatal("expected secret deletion failure")
	}
	if _, err := os.Stat(store.pendingRevocationPath(records[0].Issuer, records[0].CLIClientSessionID)); err != nil {
		t.Fatalf("pending metadata removed early: %v", err)
	}
	secrets.failDeleteRef = ""
	if err := store.CompleteRevocation(records[0]); err != nil {
		t.Fatal(err)
	}
}

func TestCompleteServerRevokedRecordToleratesAlreadyDeletedSecret(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	if err := store.QueueRevocation("https://api.example.com", "cls_1", "refresh"); err != nil {
		t.Fatal(err)
	}
	records, err := store.PendingRevocations("https://api.example.com")
	if err != nil || len(records) != 1 {
		t.Fatalf("records = %#v, err = %v", records, err)
	}
	record, err := store.MarkRevocationSucceeded(records[0])
	if err != nil {
		t.Fatal(err)
	}
	delete(secrets.values, record.RefreshSecretRef)
	if err := store.CompleteRevocation(record); err != nil {
		t.Fatal(err)
	}
}

func TestSharedLockSerializesAndRecoversDeadOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json.lock")
	first := newSharedLock(path)
	if err := first.Lock(); err != nil {
		t.Fatal(err)
	}
	acquired := make(chan error, 1)
	go func() {
		second := newSharedLock(path)
		err := second.Lock()
		if err == nil {
			err = second.Unlock()
		}
		acquired <- err
	}()
	select {
	case err := <-acquired:
		t.Fatalf("second lock acquired before release: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	if err := first.Unlock(); err != nil {
		t.Fatal(err)
	}
	if err := <-acquired; err != nil {
		t.Fatal(err)
	}

	dead := newSharedLock(path)
	if err := os.MkdirAll(dead.path, 0o700); err != nil {
		t.Fatal(err)
	}
	hostname, _ := os.Hostname()
	owner := `{"pid":999999999,"hostname":` + strconv.Quote(hostname) + `,"created_at":"2026-07-11T00:00:00Z","token":"dead"}`
	if err := os.WriteFile(filepath.Join(dead.path, "owner.json"), []byte(owner), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := dead.Lock(); err != nil {
		t.Fatal(err)
	}
	if err := dead.Unlock(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishCredentialLocation(t *testing.T) {
	root := t.TempDir()
	defaultDir := filepath.Join(root, "paperboat", "credentials")
	customDir := filepath.Join(root, "managed", "credentials")
	if err := publishCredentialLocation(defaultDir, customDir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "paperboat", "credentials-location.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !configTestPathsEqual(string(b), customDir) {
		t.Fatalf("location = %s", b)
	}
}
