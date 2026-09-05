package api

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/config"
	"golang.org/x/crypto/ssh"
)

func TestRegisterManagedSSHClientKeyEscapedSlashReachesServerRoute(t *testing.T) {
	publicKey, fingerprint, encodedFingerprint := managedSSHPathTestKey(t)
	escapedFingerprint := url.PathEscape(encodedFingerprint)
	var requestURI, escapedPath, pathValue string
	var requestBody struct {
		PublicKey string `json:"public_key"`
	}

	mux := http.NewServeMux()
	// This is the exact route pattern registered by paperboat-server's
	// internal/httpapi/router.go for managed CLI client-key registration.
	mux.Handle("PUT /v1/ssh/client-keys/{fingerprint}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURI = r.RequestURI
		escapedPath = r.URL.EscapedPath()
		pathValue = r.PathValue("fingerprint")
		if r.Header.Get("Authorization") != "Bearer token" || r.Header.Get("Idempotency-Key") != "managed-ssh-path-1" {
			t.Fatalf("headers authorization=%q idempotency=%q", r.Header.Get("Authorization"), r.Header.Get("Idempotency-Key"))
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if requestBody.PublicKey != publicKey {
			t.Fatalf("public key=%q, want %q", requestBody.PublicKey, publicKey)
		}
		if pathValue != encodedFingerprint {
			t.Fatalf("server route fingerprint=%q, want decoded %q", pathValue, encodedFingerprint)
		}
		writeData(w, http.StatusCreated, ManagedSSHClientKey{
			Type: "client_key", Version: 1, Fingerprint: encodedFingerprint,
			PublicKey: publicKey, State: "active", ReconciliationVersion: 1,
		})
	}))
	server := httptest.NewServer(mux)
	defer server.Close()

	key, err := New(server.URL, config.Credential{AccessToken: "token"}, server.Client()).RegisterManagedSSHClientKey(context.Background(), publicKey, fingerprint, "managed-ssh-path-1")
	if err != nil {
		t.Fatalf("RegisterManagedSSHClientKey: %v", err)
	}
	if key.Fingerprint != encodedFingerprint || key.PublicKey != publicKey {
		t.Fatalf("response key=%+v", key)
	}
	if !strings.Contains(encodedFingerprint, "/") {
		t.Fatalf("test fingerprint=%q does not contain slash", encodedFingerprint)
	}
	if !strings.Contains(requestURI, escapedFingerprint) || !strings.Contains(requestURI, "%2F") {
		t.Fatalf("wire request URI=%q, want escaped fingerprint=%q", requestURI, escapedFingerprint)
	}
	if !strings.Contains(escapedPath, escapedFingerprint) || !strings.Contains(escapedPath, "%2F") {
		t.Fatalf("server escaped path=%q, want escaped fingerprint=%q", escapedPath, escapedFingerprint)
	}
	t.Logf("managed SSH path wire request_uri=%q escaped_path=%q path_value=%q", requestURI, escapedPath, pathValue)
}

func managedSSHPathTestKey(t *testing.T) (string, [32]byte, string) {
	t.Helper()
	for seedByte := 0; seedByte < 256; seedByte++ {
		var seed [ed25519.SeedSize]byte
		seed[0] = byte(seedByte)
		privateKey := ed25519.NewKeyFromSeed(seed[:])
		public, err := ssh.NewPublicKey(privateKey.Public())
		if err != nil {
			t.Fatal(err)
		}
		fingerprint := sha256.Sum256(public.Marshal())
		encoded := "SHA256:" + base64.RawStdEncoding.EncodeToString(fingerprint[:])
		if strings.Contains(encoded, "/") {
			return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))), fingerprint, encoded
		}
	}
	t.Fatal("could not construct a deterministic standard-base64 fingerprint containing slash")
	return "", [32]byte{}, ""
}
