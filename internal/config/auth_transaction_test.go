package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthTransactionRestartRetainsNewSessionAndPreservesActiveProfile(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, Account: Account{ID: "account_1"}, CLIClientSessionID: "cls_old"}, Credential{AccessToken: "access-old", RefreshToken: "refresh-old"}); err != nil {
		t.Fatal(err)
	}
	previous, err := store.Load(issuer)
	if err != nil {
		t.Fatal(err)
	}
	accessRef, refreshRef, err := newSecretRefs(previous.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	next := Profile{Version: ProfileVersion, Issuer: previous.Issuer, Account: previous.Account, CLIClientSessionID: "cls_new", AccessSecretRef: accessRef, RefreshSecretRef: refreshRef}
	tx := AuthTransaction{Operation: "switch", Issuer: previous.Issuer, ExpectedSessionID: previous.CLIClientSessionID, Previous: previous, Next: next, QueuePrevious: true}
	if err := store.writeAuthTransaction(tx); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueRevocation(issuer, previous.CLIClientSessionID, "refresh-old", previous.Account.ID); err != nil {
		t.Fatal(err)
	}
	if err := secrets.Set(refreshRef, "refresh-new"); err != nil {
		t.Fatal(err)
	}
	if err := secrets.Set(accessRef, "access-new"); err != nil {
		t.Fatal(err)
	}

	restarted := ProfileStore{Path: dir, Secrets: secrets}
	if err := restarted.Recover(issuer); err != nil {
		t.Fatal(err)
	}
	active, err := restarted.Load(issuer)
	if err != nil || !profileRefsMatch(active, previous) {
		t.Fatalf("active profile changed during abandoned recovery: %#v, %v", active, err)
	}
	if _, ok := secrets.values[accessRef]; ok {
		t.Fatal("staged access secret survived recovery")
	}
	if _, ok := secrets.values[refreshRef]; ok {
		t.Fatal("staged refresh secret survived recovery")
	}
	records, err := restarted.PendingRevocations(issuer)
	if err != nil || len(records) != 1 || records[0].CLIClientSessionID != "cls_new" {
		t.Fatalf("pending revocations = %#v, %v", records, err)
	}
	credential, err := restarted.PendingRevocationCredential(records[0])
	if err != nil || credential.RefreshToken != "refresh-new" {
		t.Fatalf("retained new session credential = %#v, %v", credential, err)
	}
	if _, err := os.Stat(restarted.authTransactionPath(previous.Issuer)); !os.IsNotExist(err) {
		t.Fatalf("transaction marker remains: %v", err)
	}
}

func TestPendingRevocationNeverExposesActiveRotatedSessionFamily(t *testing.T) {
	dir := t.TempDir()
	store := ProfileStore{Path: dir, Secrets: &faultSecretStore{values: map[string]string{}}}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, CLIClientSessionID: "cls_active"}, Credential{AccessToken: "access-current", RefreshToken: "refresh-current"}); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueRevocation(issuer, "cls_active", "refresh-older-rotation"); err != nil {
		t.Fatal(err)
	}
	records, err := store.PendingRevocations(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("active token family became revocable: %#v", records)
	}
}

func TestAuthTransactionRestartRecognizesCommittedProfile(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, Account: Account{ID: "account_1"}, CLIClientSessionID: "cls_old"}, Credential{AccessToken: "access-old", RefreshToken: "refresh-old"}); err != nil {
		t.Fatal(err)
	}
	previous, _ := store.Load(issuer)
	accessRef, refreshRef, _ := newSecretRefs(previous.Issuer)
	next := Profile{Version: ProfileVersion, Issuer: previous.Issuer, Account: previous.Account, CLIClientSessionID: "cls_new", AccessSecretRef: accessRef, RefreshSecretRef: refreshRef}
	next.ObsoleteSecretRefs = obsoleteSecretRefs(previous, next)
	tx := AuthTransaction{Operation: "switch", Issuer: previous.Issuer, ExpectedSessionID: previous.CLIClientSessionID, Previous: previous, Next: next, QueuePrevious: true}
	if err := store.writeAuthTransaction(tx); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueRevocation(issuer, previous.CLIClientSessionID, "refresh-old", previous.Account.ID); err != nil {
		t.Fatal(err)
	}
	_ = secrets.Set(refreshRef, "refresh-new")
	_ = secrets.Set(accessRef, "access-new")
	body, _ := jsonMarshalProfile(next)
	if err := store.writeActiveProfile(store.profilePath(previous.Issuer), body); err != nil {
		t.Fatal(err)
	}
	if err := (ProfileStore{Path: dir, Secrets: secrets}).Recover(issuer); err != nil {
		t.Fatal(err)
	}
	active, err := store.Load(issuer)
	if err != nil || active.CLIClientSessionID != "cls_new" {
		t.Fatalf("committed profile lost: %#v, %v", active, err)
	}
	credential, err := store.CredentialFor(issuer)
	if err != nil || credential.RefreshToken != "refresh-new" {
		t.Fatalf("committed credential lost: %#v, %v", credential, err)
	}
	records, err := store.PendingRevocations(issuer)
	if err != nil || len(records) != 1 || records[0].CLIClientSessionID != "cls_old" {
		t.Fatalf("old session revocation lost: %#v, %v", records, err)
	}
}

func TestRepairBrokenProfileCommitsNewPairAndQueuesReadableOldRefresh(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, Account: Account{ID: "account_1"}, CLIClientSessionID: "cls_old"}, Credential{AccessToken: "access-old", RefreshToken: "refresh-old"}); err != nil {
		t.Fatal(err)
	}
	old, _ := store.Load(issuer)
	delete(secrets.values, old.AccessSecretRef)
	if err := store.Repair("cls_old", Profile{Issuer: issuer, Account: old.Account, CLIClientSessionID: "cls_new"}, Credential{AccessToken: "access-new", RefreshToken: "refresh-new"}); err != nil {
		t.Fatal(err)
	}
	active, _ := store.Load(issuer)
	credential, err := store.CredentialFor(issuer)
	if err != nil || active.CLIClientSessionID != "cls_new" || credential.AccessToken != "access-new" || credential.RefreshToken != "refresh-new" {
		t.Fatalf("repaired state = %#v %#v %v", active, credential, err)
	}
	records, err := store.PendingRevocations(issuer)
	if err != nil || len(records) != 1 || records[0].CLIClientSessionID != "cls_old" {
		t.Fatalf("old session was not queued: %#v, %v", records, err)
	}
}

func TestRepairFailurePreservesBrokenProfileAndRetainsNewSession(t *testing.T) {
	dir := t.TempDir()
	secrets := &faultSecretStore{values: map[string]string{}}
	store := ProfileStore{Path: dir, Secrets: secrets}
	issuer := "https://api.example.com"
	if err := store.Save(Profile{Issuer: issuer, CLIClientSessionID: "cls_old"}, Credential{AccessToken: "access-old", RefreshToken: "refresh-old"}); err != nil {
		t.Fatal(err)
	}
	old, _ := store.Load(issuer)
	delete(secrets.values, old.AccessSecretRef)
	store.write = func(string, []byte, os.FileMode) error { return errors.New("injected repair commit failure") }
	err := store.Repair("cls_old", Profile{Issuer: issuer, CLIClientSessionID: "cls_new"}, Credential{AccessToken: "access-new", RefreshToken: "refresh-new"})
	if err == nil {
		t.Fatal("expected repair commit failure")
	}
	active, _ := store.Load(issuer)
	if !profileRefsMatch(active, old) {
		t.Fatalf("broken active profile changed: %#v", active)
	}
	records, pendingErr := store.PendingRevocations(issuer)
	if pendingErr != nil || len(records) != 1 || records[0].CLIClientSessionID != "cls_new" {
		entries, _ := os.ReadDir(filepath.Join(dir, "pending-revocations"))
		t.Fatalf("new failed repair session not retained: %#v, %v, entries=%v secrets=%#v", records, pendingErr, entries, secrets.values)
	}
}

func jsonMarshalProfile(profile Profile) ([]byte, error) {
	body, err := json.MarshalIndent(profile, "", "  ")
	return append(body, '\n'), err
}
