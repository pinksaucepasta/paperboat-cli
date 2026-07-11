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
	p := Profile{Issuer: "HTTPS://API.Example.COM/", ClientSessionID: "cls_1", AccessExpiresAt: time.Now().UTC()}
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
	first := Profile{Issuer: issuer, ClientSessionID: "cls_first"}
	if err := store.Save(first, Credential{AccessToken: "access-first", RefreshToken: "refresh-first"}); err != nil {
		t.Fatal(err)
	}
	second := Profile{Issuer: issuer, ClientSessionID: "cls_second"}
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
	if loaded.ClientSessionID != "cls_first" || cred.AccessToken != "access-first" || cred.RefreshToken != "refresh-first" {
		t.Fatalf("profile = %#v, credential = %#v", loaded, cred)
	}
}

func TestInitialSaveAccessFailureRemovesStoredRefreshSecret(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}, failAccess: true}
	store := ProfileStore{Path: dir, Secrets: secrets}
	p := Profile{Issuer: "https://api.example.com", ClientSessionID: "cls_1"}
	if err := store.Save(p, Credential{AccessToken: "access", RefreshToken: "refresh"}); err == nil {
		t.Fatal("expected access write failure")
	}
	if len(secrets.values) != 0 {
		t.Fatalf("orphaned secrets = %#v", secrets.values)
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
	p := Profile{Issuer: issuer, ClientSessionID: "cls_1"}
	if err := store.Save(p, Credential{AccessToken: "access", RefreshToken: "refresh"}); err == nil {
		t.Fatal("expected metadata write failure")
	}
	if len(secrets.values) != 0 {
		t.Fatalf("orphaned secrets = %#v", secrets.values)
	}
}

func TestFileSecretStoreRejectsLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	s := FileSecretStore{Dir: dir}
	p := s.path("bad")
	if err := os.WriteFile(p, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("bad"); err == nil || !strings.Contains(err.Error(), "0600") {
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

func TestRefreshWriteFailurePreservesRotatedRefreshToken(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	expired := time.Now().Add(-time.Minute)
	profile := Profile{Issuer: "https://api.example.com", ClientSessionID: "cls_1", AccessExpiresAt: expired}
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

func TestRefreshSessionMismatchQuarantinesRotatedCredential(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	expired := time.Now().Add(-time.Minute)
	profile := Profile{Issuer: "https://api.example.com", ClientSessionID: "cls_1", AccessExpiresAt: expired}
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
	if records[0].ClientSessionID != "cls_unexpected" || recovery.RefreshToken != "refresh-new" {
		t.Fatalf("record = %#v, credential = %#v", records[0], recovery)
	}
}

func TestReplaceWriteFailureRestoresPreviousCredentials(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	old := Profile{Issuer: "https://api.example.com", ClientSessionID: "cls_old", AccessExpiresAt: time.Now().Add(time.Hour)}
	if err := store.Save(old, Credential{AccessToken: "access-old", RefreshToken: "refresh-old"}); err != nil {
		t.Fatal(err)
	}
	secrets.failAccess = true
	newProfile := Profile{Issuer: old.Issuer, ClientSessionID: "cls_new", AccessExpiresAt: time.Now().Add(time.Hour)}
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
	if loaded.ClientSessionID != "cls_old" || cred.AccessToken != "access-old" || cred.RefreshToken != "refresh-old" {
		t.Fatalf("profile = %#v, credential = %#v", loaded, cred)
	}
}

func TestSwitchRejectsChangedExpectedSessionWithoutQueueing(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, ClientSessionID: "cls_current"}, Credential{AccessToken: "access-current", RefreshToken: "refresh-current"}); err != nil {
		t.Fatal(err)
	}
	err := store.Switch("cls_stale", Profile{Issuer: issuer, ClientSessionID: "cls_new"}, Credential{AccessToken: "access-new", RefreshToken: "refresh-new"})
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
	if len(records) != 1 || records[0].ClientSessionID != "cls_1" {
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
	p := Profile{Issuer: "https://api.example.com", ClientSessionID: "cls_1", AccessExpiresAt: time.Now().Add(time.Hour)}
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
	if _, err := os.Stat(store.pendingRevocationPath(records[0].Issuer, records[0].ClientSessionID)); err != nil {
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
	if !strings.Contains(string(b), customDir) {
		t.Fatalf("location = %s", b)
	}
}
