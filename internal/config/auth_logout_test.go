package config

import "testing"

func TestTakeLogoutCredentialsAtomicallyRemovesActiveAndHistoricalSessions(t *testing.T) {
	dir := t.TempDir()
	store := ProfileStore{Path: dir, Secrets: &faultSecretStore{values: map[string]string{}}}
	issuer := "https://api.example.com"
	accountID := "account_active"
	if err := store.Save(Profile{Issuer: issuer, Account: Account{ID: accountID}, CLIClientSessionID: "cls_active"}, Credential{AccessToken: "access-active", RefreshToken: "refresh-active"}); err != nil {
		t.Fatal(err)
	}
	environmentRef := environmentManagerIdentitySecretRef(issuer, accountID, "cls_active")
	store.Secrets.(*faultSecretStore).values[environmentRef] = "encrypted-manager-record"
	if err := store.QueueRevocation(issuer, "cls_old", "refresh-old"); err != nil {
		t.Fatal(err)
	}
	credentials, err := store.TakeLogoutCredentials(issuer)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, credential := range credentials {
		got[credential.RefreshToken] = true
	}
	if !got["refresh-active"] || !got["refresh-old"] || len(got) != 2 {
		t.Fatalf("logout credentials = %#v", got)
	}
	if _, err := store.Load(issuer); err != ErrNoCredentials {
		t.Fatalf("profile remains after logout: %v", err)
	}
	if records, err := store.PendingRevocations(issuer); err != nil || len(records) != 0 {
		t.Fatalf("pending revocations remain: %#v, %v", records, err)
	}
	if _, ok := store.Secrets.(*faultSecretStore).values[environmentRef]; ok {
		t.Fatal("ENV manager private keys remain after logout")
	}
}

func TestTakeLogoutCredentialsRemovesBrokenProfileWithoutInventingToken(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, CLIClientSessionID: "cls_active"}, Credential{AccessToken: "access", RefreshToken: "refresh"}); err != nil {
		t.Fatal(err)
	}
	profile, _ := store.Load(issuer)
	delete(secrets.values, profile.RefreshSecretRef)
	credentials, err := store.TakeLogoutCredentials(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 0 {
		t.Fatalf("invented broken-profile credential: %#v", credentials)
	}
	if _, err := store.Load(issuer); err != ErrNoCredentials {
		t.Fatalf("broken profile remains after logout: %v", err)
	}
}
