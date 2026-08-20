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
	aggregatePath := filepath.Join(directory, "different.sock")
	if os.PathSeparator != '/' {
		aggregatePath = `\\.\pipe\paperboat-ssh-agent-test-aggregate`
	}
	connection, err := DialOwnerAgent(service.Socket(), aggregatePath, time.Second)
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
	if os.PathSeparator == '/' {
		if _, err := os.Lstat(service.Socket()); !os.IsNotExist(err) {
			t.Fatalf("agent socket remains: %v", err)
		}
	}
}

func TestAgentServiceAggregatesValidatedInheritedAgent(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("Windows OpenSSH exposes one owner agent named pipe")
	}
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

func TestAgentServiceKeepsManagedIdentityWhenInheritedAgentIsUnavailable(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("Windows OpenSSH exposes one owner agent named pipe")
	}
	directory := shortRuntimeDirectory(t, "pb-ssh-missing-delegate-")
	signer, _ := testKey(t)
	service, err := StartAgentService(context.Background(), AgentServiceConfig{
		RuntimeDirectory: directory, InheritedAgentSocket: filepath.Join(directory, "missing.sock"),
		Signer: signer, MaxConnections: 4, IdleTimeout: time.Second, DelegateTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if err := ProbeAgentIdentity(t.Context(), service.Socket(), sha256.Sum256(signer.PublicKey().Marshal()), time.Second); err != nil {
		t.Fatalf("managed identity unavailable after optional delegation failure: %v", err)
	}
}

func shortRuntimeDirectory(t *testing.T, prefix string) string {
	t.Helper()
	directory := t.TempDir()
	if os.PathSeparator == '/' {
		candidate, err := os.MkdirTemp("/tmp", prefix)
		if err != nil {
			t.Fatal(err)
		}
		directory = candidate
		t.Cleanup(func() { _ = os.RemoveAll(directory) })
	}
	if err := os.Chmod(directory, 0o700); err != nil && os.PathSeparator == '/' {
		t.Fatal(err)
	}
	return directory
}
