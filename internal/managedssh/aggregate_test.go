package managedssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestAggregateListsDeduplicatesAndSignsManagedAndDelegatedKeys(t *testing.T) {
	managedSigner, managedPrivate := testKey(t)
	managed, _ := NewAgent(managedSigner)
	delegatedSigner, delegatedPrivate := testKey(t)
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: delegatedPrivate, Comment: "existing key"}); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: managedPrivate, Comment: "duplicate managed key"}); err != nil {
		t.Fatal(err)
	}
	extended, ok := keyring.(agent.ExtendedAgent)
	if !ok {
		t.Fatal("keyring does not implement extended agent")
	}
	aggregate, err := NewAggregate(managed, extended)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := aggregate.List()
	if err != nil || len(keys) != 2 || !containsAgentKey(keys, managedSigner.PublicKey().Marshal()) || !containsAgentKey(keys, delegatedSigner.PublicKey().Marshal()) {
		t.Fatalf("keys=%+v error=%v", keys, err)
	}
	for _, signer := range []ssh.Signer{managedSigner, delegatedSigner} {
		payload := []byte("aggregate signing payload")
		signature, err := aggregate.Sign(signer.PublicKey(), payload)
		if err != nil || signer.PublicKey().Verify(payload, signature) != nil {
			t.Fatalf("signing key=%s error=%v", ssh.FingerprintSHA256(signer.PublicKey()), err)
		}
	}
	unknown, _ := testKey(t)
	if _, err := aggregate.Sign(unknown.PublicKey(), []byte("payload")); !errors.Is(err, ErrAgentDenied) {
		t.Fatalf("unknown signing error=%v", err)
	}
	if err := aggregate.RemoveAll(); !errors.Is(err, ErrAgentDenied) {
		t.Fatalf("aggregate mutation error=%v", err)
	}
	delegatedKeys, err := keyring.List()
	if err != nil || len(delegatedKeys) != 2 {
		t.Fatalf("delegate was mutated: keys=%d error=%v", len(delegatedKeys), err)
	}
}

func TestAggregateRejectsExcessDelegateIdentities(t *testing.T) {
	managedSigner, _ := testKey(t)
	managed, _ := NewAgent(managedSigner)
	keys := make([]*agent.Key, MaxAgentIdentities+1)
	for i := range keys {
		keys[i] = &agent.Key{Format: ssh.KeyAlgoED25519, Blob: []byte{byte(i + 1)}}
	}
	aggregate, _ := NewAggregate(managed, listOnlyAgent{keys: keys})
	if _, err := aggregate.List(); !errors.Is(err, ErrAgentIdentityLimit) {
		t.Fatalf("identity limit error=%v", err)
	}
}

func TestAggregateListsManagedIdentityWhenDelegateFails(t *testing.T) {
	managedSigner, _ := testKey(t)
	managed, _ := NewAgent(managedSigner)
	aggregate, _ := NewAggregate(managed, listOnlyAgent{err: errors.New("delegate unavailable")})
	keys, err := aggregate.List()
	if err != nil || len(keys) != 1 || !containsAgentKey(keys, managedSigner.PublicKey().Marshal()) {
		t.Fatalf("keys=%+v error=%v", keys, err)
	}
}

func TestDialOwnerAgentRejectsLoopAndDelegatesWithDeadlines(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("Unix-only agent test")
	}
	directory, err := os.MkdirTemp("/tmp", "pb-ssh-delegate-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "original.sock")
	listener, err := ListenOwnerSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	signer, private := testKey(t)
	if err := keyring.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (Server{Agent: keyring, MaxConnections: 2, IdleTimeout: time.Second}).Serve(ctx, listener)
	}()
	if _, err := DialOwnerAgent(path, path, time.Second); !errors.Is(err, ErrAgentDenied) {
		t.Fatalf("loop error=%v", err)
	}
	delegated, err := DialOwnerAgent(path, filepath.Join(directory, "aggregate.sock"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := delegated.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("delegated keys=%+v error=%v", keys, err)
	}
	payload := []byte("delegated payload")
	signature, err := delegated.Sign(signer.PublicKey(), payload)
	if err != nil || signer.PublicKey().Verify(payload, signature) != nil {
		t.Fatalf("delegated signature error=%v", err)
	}
	if err := delegated.RemoveAll(); !errors.Is(err, ErrAgentDenied) {
		t.Fatalf("delegated mutation error=%v", err)
	}
	if err := delegated.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type listOnlyAgent struct {
	agent.ExtendedAgent
	keys []*agent.Key
	err  error
}

func (a listOnlyAgent) List() ([]*agent.Key, error) { return a.keys, a.err }

func testKey(t *testing.T) (ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer, private
}
