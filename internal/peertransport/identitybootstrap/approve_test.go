package identitybootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/blake2s"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

type approvalClient struct {
	root       api.E2EERoot
	pending    []api.PendingEndpointIdentity
	registered api.EndpointCertificateDocument
}

func (c *approvalClient) E2EERoot(context.Context) (api.E2EERoot, error) { return c.root, nil }
func (c *approvalClient) PendingE2EEEndpoints(context.Context) ([]api.PendingEndpointIdentity, error) {
	return append([]api.PendingEndpointIdentity(nil), c.pending...), nil
}
func (c *approvalClient) RegisterEndpointCertificate(_ context.Context, _ string, document api.EndpointCertificateDocument) (api.EndpointCertificateDocument, error) {
	c.registered = document
	return document, nil
}

func TestApproveMachineRequiresExactSafetyCodeAndSignsPublishedKeys(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store := config.ProfileStore{Path: root, Secrets: config.FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	keys, err := store.PeerIdentityKeys("https://api.example.test", "account_1", "cli_1")
	if err != nil {
		t.Fatal(err)
	}
	rootPublic := keys.RootPrivate.Public().(ed25519.PublicKey)
	rootFingerprint := sha256.Sum256(rootPublic)
	clearKeys(&keys)
	noise := sha256.Sum256([]byte("machine-noise"))
	quicPublic, _, _ := ed25519.GenerateKey(nil)
	code := machineSafetyCode("machine_1", 2, noise, quicPublic)
	client := &approvalClient{root: api.E2EERoot{Version: 1, PublicKey: base64.RawURLEncoding.EncodeToString(rootPublic), Fingerprint: hex.EncodeToString(rootFingerprint[:]), Generation: 1}, pending: []api.PendingEndpointIdentity{{RequestID: "per_0123456789abcdef", EndpointID: "machine_1", State: "pending", Generation: 2, NoisePublicKey: base64.RawURLEncoding.EncodeToString(noise[:]), QUICPublicKey: base64.RawURLEncoding.EncodeToString(quicPublic), CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(4 * time.Minute), SafetyCode: code}}}
	request := ApprovalRequest{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_1", RequestID: "per_0123456789abcdef", SafetyCode: code, Now: func() time.Time { return now }}
	result, err := ApproveMachine(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(client.registered.Certificate)
	certificate, err := endpointidentity.Verify(raw, rootPublic, endpointidentity.Expected{AccountID: "account_1", Role: endpointidentity.RoleMachine, EndpointID: "machine_1", Generation: 2}, now)
	if err != nil || certificate.Claims.NoisePublicKey != noise || string(certificate.Claims.QUICPublicKey) != string(quicPublic) || result.CertificateFingerprint != client.registered.CertificateFingerprint {
		t.Fatalf("certificate=%+v result=%+v err=%v", certificate, result, err)
	}
	request.SafetyCode = "00000-00000"
	if _, err := ApproveMachine(context.Background(), request); err == nil {
		t.Fatal("mismatched safety code accepted")
	}
}

func TestApproveCLIRequiresCLIRoleAndSignsNewSessionKeys(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store := config.ProfileStore{Path: root, Secrets: config.FileSecretStore{Dir: filepath.Join(root, "secrets")}}
	keys, err := store.PeerIdentityKeys("https://api.example.test", "account_1", "cli_existing")
	if err != nil {
		t.Fatal(err)
	}
	rootPublic := keys.RootPrivate.Public().(ed25519.PublicKey)
	rootFingerprint := sha256.Sum256(rootPublic)
	clearKeys(&keys)
	noise := sha256.Sum256([]byte("cli-noise"))
	quicPublic, _, _ := ed25519.GenerateKey(nil)
	code := machineSafetyCode("cli_new", 1, noise, quicPublic)
	client := &approvalClient{root: api.E2EERoot{Version: 1, PublicKey: base64.RawURLEncoding.EncodeToString(rootPublic), Fingerprint: hex.EncodeToString(rootFingerprint[:]), Generation: 1}, pending: []api.PendingEndpointIdentity{{RequestID: "per_0123456789abcdef", EndpointID: "cli_new", Role: "cli", State: "pending", Generation: 1, NoisePublicKey: base64.RawURLEncoding.EncodeToString(noise[:]), QUICPublicKey: base64.RawURLEncoding.EncodeToString(quicPublic), CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(4 * time.Minute), SafetyCode: code}}}
	result, err := ApproveCLI(context.Background(), ApprovalRequest{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_existing", RequestID: "per_0123456789abcdef", SafetyCode: code, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(client.registered.Certificate)
	certificate, err := endpointidentity.Verify(raw, rootPublic, endpointidentity.Expected{AccountID: "account_1", Role: endpointidentity.RoleCLI, EndpointID: "cli_new", Generation: 1}, now)
	if err != nil || client.registered.Role != "cli" || certificate.Claims.NoisePublicKey != noise || string(certificate.Claims.QUICPublicKey) != string(quicPublic) || result.CertificateFingerprint != client.registered.CertificateFingerprint {
		t.Fatalf("certificate=%+v document=%+v result=%+v err=%v", certificate, client.registered, result, err)
	}
	if _, err := ApproveMachine(context.Background(), ApprovalRequest{Store: store, Client: client, Issuer: "https://api.example.test", AccountID: "account_1", CLIClientSessionID: "cli_existing", RequestID: "per_0123456789abcdef", SafetyCode: code, Now: func() time.Time { return now }}); err == nil {
		t.Fatal("machine signer accepted a CLI request")
	}
}

func machineSafetyCode(endpointID string, generation uint64, noise [32]byte, quic []byte) string {
	buffer := append([]byte("paperboat-machine-endpoint-v1\x00"+endpointID+"\x00"), make([]byte, 8)...)
	binary.BigEndian.PutUint64(buffer[len(buffer)-8:], generation)
	buffer = append(buffer, noise[:]...)
	buffer = append(buffer, quic...)
	digest := blake2s.Sum256(buffer)
	encoded := hex.EncodeToString(digest[:5])
	return encoded[:5] + "-" + encoded[5:]
}
