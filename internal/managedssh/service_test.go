package managedssh

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

func TestAgentServiceOwnsSocketAndManagedIdentityLifecycle(t *testing.T) {
	directory := shortRuntimeDirectory(t, "pb-ssh-service-")
	signer, _ := testKey(t)
	service, err := StartAgentService(context.Background(), AgentServiceConfig{RuntimeDirectory: directory, Signer: signer, MaxConnections: 4, IdleTimeout: time.Second, DelegateTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := ProbeAgentIdentity(t.Context(), service.Socket(), sha256.Sum256(signer.PublicKey().Marshal()), time.Second); err != nil {
		t.Fatalf("probe managed identity: %v", err)
	}
	if err := ProbeAgentIdentity(t.Context(), service.Socket(), sha256.Sum256([]byte("other")), time.Second); !errors.Is(err, ErrAgentDenied) {
		t.Fatalf("missing identity probe error=%v", err)
	}
	connection, err := DialOwnerAgent(service.Socket(), filepath.Join(directory, "different.sock"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := connection.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys=%+v error=%v", keys, err)
	}
	_ = connection.Close()
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := os.Lstat(service.Socket()); !os.IsNotExist(err) {
		t.Fatalf("agent socket remains: %v", err)
	}
}

func TestAgentServiceAggregatesValidatedInheritedAgent(t *testing.T) {
	directory := shortRuntimeDirectory(t, "pb-ssh-aggregate-service-")
	originalPath := filepath.Join(directory, "original.sock")
	originalListener, err := ListenOwnerSocket(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	originalKeyring := agent.NewKeyring()
	originalSigner, originalPrivate := testKey(t)
	if err := originalKeyring.Add(agent.AddedKey{PrivateKey: originalPrivate}); err != nil {
		t.Fatal(err)
	}
	originalCtx, cancelOriginal := context.WithCancel(context.Background())
	originalDone := make(chan error, 1)
	go func() {
		originalDone <- (Server{Agent: originalKeyring, MaxConnections: 2, IdleTimeout: time.Second}).Serve(originalCtx, originalListener)
	}()
	managedSigner, _ := testKey(t)
	service, err := StartAgentService(context.Background(), AgentServiceConfig{RuntimeDirectory: directory, InheritedAgentSocket: originalPath, Signer: managedSigner, MaxConnections: 4, IdleTimeout: time.Second, DelegateTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client, err := DialOwnerAgent(service.Socket(), filepath.Join(directory, "caller.sock"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := client.List()
	if err != nil || len(keys) != 2 || !containsAgentKey(keys, managedSigner.PublicKey().Marshal()) || !containsAgentKey(keys, originalSigner.PublicKey().Marshal()) {
		t.Fatalf("keys=%+v error=%v", keys, err)
	}
	_ = client.Close()
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	cancelOriginal()
	if err := <-originalDone; err != nil {
		t.Fatal(err)
	}
}

func shortRuntimeDirectory(t *testing.T, prefix string) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}
