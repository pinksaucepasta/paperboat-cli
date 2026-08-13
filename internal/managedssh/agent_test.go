package managedssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestAgentProtocolListsAndSignsOnlyManagedKey(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	managed, err := NewAgent(signer)
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- agent.ServeAgent(managed, server) }()
	remote := agent.NewClient(client)
	keys, err := remote.List()
	if err != nil || len(keys) != 1 || keys[0].Format != ssh.KeyAlgoED25519 || keys[0].Comment != "Paperboat managed SSH key" {
		t.Fatalf("keys=%+v error=%v", keys, err)
	}
	payload := []byte("SSH agent authentication payload")
	signature, err := remote.Sign(signer.PublicKey(), payload)
	if err != nil || signer.PublicKey().Verify(payload, signature) != nil {
		t.Fatalf("signature=%+v error=%v", signature, err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := ssh.NewPublicKey(otherPublic)
	if _, err := managed.Sign(other, payload); !errors.Is(err, ErrAgentDenied) {
		t.Fatal("agent signed with an unknown key")
	}
	if err := managed.Add(agent.AddedKey{PrivateKey: private}); !errors.Is(err, ErrAgentDenied) {
		t.Fatal("agent mutation succeeded")
	}
	if err := managed.Remove(signer.PublicKey()); !errors.Is(err, ErrAgentDenied) {
		t.Fatal("agent removal succeeded")
	}
	if err := managed.RemoveAll(); !errors.Is(err, ErrAgentDenied) {
		t.Fatal("agent remove-all succeeded")
	}
	if err := managed.Lock([]byte("lock")); !errors.Is(err, ErrAgentDenied) {
		t.Fatal("agent lock succeeded")
	}
	if err := managed.Unlock([]byte("lock")); !errors.Is(err, ErrAgentDenied) {
		t.Fatal("agent unlock succeeded")
	}
	if _, err := managed.Extension("query", nil); !errors.Is(err, agent.ErrExtensionUnsupported) {
		t.Fatal("agent extension succeeded")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Fatalf("serve error=%v", err)
	}
	_ = public
}

func TestAgentRejectsOversizedAndFlaggedSigning(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(private)
	managed, _ := NewAgent(signer)
	if _, err := managed.Sign(signer.PublicKey(), make([]byte, MaxSigningPayloadBytes+1)); !errors.Is(err, ErrAgentRequestTooLarge) {
		t.Fatalf("oversized error=%v", err)
	}
	if _, err := managed.SignWithFlags(signer.PublicKey(), []byte("payload"), agent.SignatureFlagRsaSha256); !errors.Is(err, ErrAgentDenied) {
		t.Fatalf("flagged error=%v", err)
	}
	keys, _ := managed.List()
	keys[0].Blob[0] ^= 0xff
	second, _ := managed.List()
	if second[0].Blob[0] == keys[0].Blob[0] {
		t.Fatal("List exposed mutable agent state")
	}
}
