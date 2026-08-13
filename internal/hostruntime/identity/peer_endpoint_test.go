package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

func TestPeerEndpointKeysRemainLocalAndAcceptOnlyMatchingCertificate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	random := bytes.NewReader(bytes.Repeat([]byte{7}, 96))
	store, err := Open(Config{StateRoot: root, Random: random})
	if err != nil {
		t.Fatal(err)
	}
	key := store.Current()
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	if err := store.SaveRegistration(Registration{ServerURL: "https://api.example.test", MachineID: "machine_01", EnvironmentID: "env_01", PublicKeyID: key.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(key.Public()), InboxPath: filepath.Join(root, "inbox"), InstallationGeneration: 4, SetupRoles: []string{"host"}, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	endpoint, err := store.PeerEndpoint()
	if err != nil || endpoint.Generation != 4 || len(endpoint.Certificate) != 0 {
		t.Fatalf("endpoint=%+v err=%v", endpoint, err)
	}
	info, err := os.Stat(filepath.Join(root, "peer-endpoint.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("info=%v err=%v", info, err)
	}
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	certificate, err := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: "account_01", Role: endpointidentity.RoleMachine, EndpointID: "machine_01", NoisePublicKey: endpoint.NoisePublicKey(), QUICPublicKey: endpoint.QUICPublicKey(), Generation: 4, Serial: 1, IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := certificate.MarshalBinary()
	if err := store.SavePeerEndpointCertificate(rootPublic, raw, now); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(Config{StateRoot: root, Clock: fixedClock{now}})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.PeerEndpoint()
	if err != nil || !bytes.Equal(loaded.Certificate, raw) || loaded.NoisePublicKey() != endpoint.NoisePublicKey() || !bytes.Equal(loaded.QUICPublicKey(), endpoint.QUICPublicKey()) {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	bad, _ := endpointidentity.Sign(rootPrivate, endpointidentity.Claims{AccountID: "account_01", Role: endpointidentity.RoleMachine, EndpointID: "machine_01", NoisePublicKey: [32]byte{1}, QUICPublicKey: endpoint.QUICPublicKey(), Generation: 4, Serial: 2, IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	badRaw, _ := bad.MarshalBinary()
	if err := store.SavePeerEndpointCertificate(rootPublic, badRaw, now); err == nil {
		t.Fatal("mismatched certificate was accepted")
	}
}

func TestPeerEndpointRotatesKeysForNewInstallationGeneration(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	store, err := Open(Config{StateRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	key := store.Current()
	registration := Registration{ServerURL: "https://api.example.test", MachineID: "machine_01", EnvironmentID: "env_01", PublicKeyID: key.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(key.Public()), InboxPath: filepath.Join(root, "inbox"), InstallationGeneration: 1, SetupRoles: []string{"host"}, UpdatedAt: now}
	if err := store.SaveRegistration(registration); err != nil {
		t.Fatal(err)
	}
	first, err := store.PeerEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	registration.InstallationGeneration = 2
	registration.UpdatedAt = now.Add(time.Second)
	if err := store.SaveRegistration(registration); err != nil {
		t.Fatal(err)
	}
	second, err := store.PeerEndpoint()
	if err != nil || second.Generation != 2 || second.NoisePublicKey() == first.NoisePublicKey() || bytes.Equal(second.QUICPublicKey(), first.QUICPublicKey()) {
		t.Fatalf("first=%+v second=%+v err=%v", first, second, err)
	}
}

func TestPeerEndpointRecoversMalformedUnsignedState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	store, err := Open(Config{StateRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	key := store.Current()
	registration := Registration{ServerURL: "https://api.example.test", MachineID: "machine_01", EnvironmentID: "env_01", PublicKeyID: key.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(key.Public()), InboxPath: filepath.Join(root, "inbox"), InstallationGeneration: 1, SetupRoles: []string{"host"}, UpdatedAt: time.Now().UTC()}
	if err := store.SaveRegistration(registration); err != nil {
		t.Fatal(err)
	}
	first, err := store.PeerEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "peer-endpoint.json")
	malformed := `{"version":1,"generation":1,"noise_private_key_base64url":"!","quic_seed_base64url":"!"}`
	if err := os.WriteFile(path, []byte(malformed), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.PeerEndpoint()
	if err != nil || recovered.Generation != 1 || recovered.NoisePublicKey() == first.NoisePublicKey() || bytes.Equal(recovered.QUICPublicKey(), first.QUICPublicKey()) {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
	certified := `{"version":1,"generation":1,"noise_private_key_base64url":"!","quic_seed_base64url":"!","certificate_base64url":"!","root_public_key_base64url":"!"}`
	if err := os.WriteFile(path, []byte(certified), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PeerEndpoint(); err == nil {
		t.Fatal("malformed certified endpoint state was regenerated")
	}
}
