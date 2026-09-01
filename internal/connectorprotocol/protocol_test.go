package connectorprotocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testIdentity() (ed25519.PrivateKey, string, string) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	thumbprint, err := IdentityThumbprint(public)
	if err != nil {
		panic(err)
	}
	keyID, err := IdentityKeyID(public)
	if err != nil {
		panic(err)
	}
	return private, keyID, thumbprint
}

func TestIdentityThumbprintUsesCanonicalRFC7638JWK(t *testing.T) {
	private, keyID, thumbprint := testIdentity()
	if keyID != "ed25519:"+thumbprint {
		t.Fatalf("key ID=%q, want ed25519:%s", keyID, thumbprint)
	}
	if err := ValidateIdentityKey(keyID, thumbprint); err != nil {
		t.Fatalf("identity validation failed: %v", err)
	}
	if _, err := IdentityThumbprint(private.Public().(ed25519.PublicKey)[:ed25519.PublicKeySize-1]); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("short public key error=%v", err)
	}
}

func testAuth(t *testing.T, now time.Time, generation uint64) (AuthRequest, ed25519.PrivateKey) {
	t.Helper()
	private, keyID, thumbprint := testIdentity()
	request := AuthRequest{AccountID: "acct_1", TunnelID: "tunnel_1", ConnectorID: "connector_1", HostID: "host_1", IdentityKeyID: keyID, IdentityKeyThumbprint: thumbprint, ProcessGeneration: generation, CredentialGeneration: 4, Nonce: "nonce-1234567890", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	var err error
	request, err = SignAuthProof(request, func(payload []byte) []byte { return ed25519.Sign(private, payload) })
	if err != nil {
		t.Fatal(err)
	}
	return request, private
}

func testConfigPayload(generation uint64, hostname string) []byte {
	return []byte(fmt.Sprintf(`{"schema":"paperboat.preview-tunnel/v1","kind":"tunnel_config_snapshot","tunnel_id":"tunnel_1","generation":%d,"name":"demo","desired_state":"active","access_mode":"public","stable_endpoint":"https://123e4567-e89b-42d3-a456-426614174000.tunnels.example.test","expires_at":null,"routes":[{"id":"route_1","name":"default","protocol":"http","match_type":"exact","match_hostname":"%s","path_prefix":null,"origin_scheme":"http","origin_address":"127.0.0.1:3000","preserve_host":true,"host_override":null,"tls_verification":"not_applicable","tls_server_name":null,"ca_reference":null,"mtls_credential_reference":null,"connect_timeout_ms":10000,"idle_timeout_ms":90000,"max_concurrent_streams":128,"desired_state":"active"}]}`, generation, hostname))
}

func TestAuthProofBindsEveryIdentityField(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	request, private := testAuth(t, now, 3)
	if err := VerifyAuthProof(request, func(message, signature []byte) bool {
		return ed25519.Verify(private.Public().(ed25519.PublicKey), message, signature)
	}); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*AuthRequest){
		"account":    func(v *AuthRequest) { v.AccountID = "acct_2" },
		"tunnel":     func(v *AuthRequest) { v.TunnelID = "tunnel_2" },
		"connector":  func(v *AuthRequest) { v.ConnectorID = "connector_2" },
		"host":       func(v *AuthRequest) { v.HostID = "host_2" },
		"generation": func(v *AuthRequest) { v.ProcessGeneration++ },
		"credential": func(v *AuthRequest) { v.CredentialGeneration++ },
		"nonce":      func(v *AuthRequest) { v.Nonce = "nonce-0987654321" },
	} {
		mutated := request
		mutate(&mutated)
		if err := VerifyAuthProof(mutated, func(message, signature []byte) bool {
			return ed25519.Verify(private.Public().(ed25519.PublicKey), message, signature)
		}); err == nil {
			t.Fatalf("mutated %s proof verified", name)
		}
	}
}

func TestAuthValidationRejectsControlCharactersButAllowsOrdinaryNonceLetters(t *testing.T) {
	now := time.Now().UTC()
	request, _ := testAuth(t, now, 1)
	request.Nonce = "nonce-contains-r-and-n"
	request, _ = SignAuthProof(request, func(payload []byte) []byte { return bytes.Repeat([]byte{1}, ed25519.SignatureSize) })
	if err := request.Validate(now); err != nil {
		t.Fatalf("ordinary nonce rejected: %v", err)
	}
	request.Nonce = "nonce-contains-\r\n"
	if err := request.Validate(now); err == nil {
		t.Fatal("control-character nonce accepted")
	}
}

func TestAuthValidationRejectsStaleIssuedAt(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	request, _ := testAuth(t, now.Add(-MaxClockSkew-time.Second), 1)
	if err := request.Validate(now); !errors.Is(err, ErrCredentialExpired) {
		t.Fatalf("stale auth error=%v", err)
	}
}

func TestVersionAndWelcomeValidationAreStrict(t *testing.T) {
	if _, err := NegotiateVersion("999999999999999999999999999999999999.0", ProtocolVersion); !errors.Is(err, ErrProtocolIncompatible) {
		t.Fatalf("overflow version error=%v", err)
	}
	now := time.Now().UTC()
	welcome := Welcome{Protocol: ProtocolName, Version: ProtocolVersion, SessionID: "sess_1", Capabilities: requiredCapabilityList(), RequiresSnapshot: true, ServerTime: now, Lease: Lease{SessionID: "sess_2", ExpiresAt: now.Add(time.Minute), HeartbeatIntervalMS: 1000}}
	if err := welcome.Validate(now); err == nil {
		t.Fatal("welcome with mismatched lease session accepted")
	}
}

func TestCanonicalHashUsesSortedKeysAndJSONNumbers(t *testing.T) {
	payload := []byte(`{"routes":[{"weight":1.25,"port":80}],"generation":7}`)
	canonical, err := canonicalJSON(payload, MaxSnapshotBytes)
	if err != nil {
		t.Fatal(err)
	}
	const wantCanonical = `{"generation":7,"routes":[{"port":80,"weight":1.25}]}`
	if string(canonical) != wantCanonical {
		t.Fatalf("canonical payload=%s", canonical)
	}
	digest := sha256.Sum256(canonical)
	_ = digest
}

func TestSecretBearingPayloadsAreRejected(t *testing.T) {
	for _, payload := range []string{
		`{"headers":{"Authorization":"Bearer x"}}`,
		`{"api_key":"x"}`,
		`{"url":"https://user:password@example.test/path"}`,
		`{"url":"https://example.test/path?token=x"}`,
	} {
		if _, err := NewSnapshot("tunnel_1", 1, []byte(payload)); err == nil {
			t.Fatalf("secret payload accepted: %s", payload)
		}
	}
	safe := strings.Replace(string(testConfigPayload(1, "preview.example.test")), `"mtls_credential_reference":null`, `"mtls_credential_reference":"keychain://paperboat/connectors/connector_1"`, 1)
	if _, err := NewSnapshot("tunnel_1", 1, []byte(safe)); err != nil {
		t.Fatalf("safe reference rejected: %v", err)
	}
}

func TestFrameRoundTripAndBounds(t *testing.T) {
	payload, err := NewSnapshot("tunnel_1", 1, testConfigPayload(1, "preview.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	payload.AccountID = "acct_1"
	payload.ConnectorID = "connector_1"
	payload.SessionID = "sess_1"
	payload.ProcessGeneration = 1
	frame, err := NewFrame(MessageSnapshot, "req_1", payload)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := WriteFrame(&wire, frame); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadFrame(&wire)
	if err != nil || decoded.Type != MessageSnapshot || decoded.RequestID != "req_1" {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	oversizedPayload := append([]byte{'"'}, bytes.Repeat([]byte("x"), MaxSnapshotBytes-1)...)
	oversizedPayload = append(oversizedPayload, '"')
	oversized := Snapshot{TunnelID: "tunnel_1", Generation: 1, ContentHash: "sha256:" + strings.Repeat("a", 64), Payload: oversizedPayload}
	if _, err := NewFrame(MessageSnapshot, "req_1", oversized); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversize frame error=%v", err)
	}
	var truncated bytes.Buffer
	truncated.Write([]byte{0, 0, 0, 4})
	truncated.WriteString("{}{}")
	if _, err := ReadFrame(&truncated); !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("trailing frame error=%v", err)
	}
}

func TestAckRejectsUnknownCode(t *testing.T) {
	ack := Ack{AccountID: "acct_1", TunnelID: "tunnel_1", ConnectorID: "connector_1", SessionID: "sess_1", ProcessGeneration: 1, Kind: AckSnapshot, Status: AckRejected, Generation: 1, ContentHash: "sha256:" + strings.Repeat("a", 64), Code: Code("made_up")}
	if err := ack.Validate(); err == nil {
		t.Fatal("unknown ack code accepted")
	}
}

func requiredCapabilityList() []string {
	return []string{CapabilitySnapshot, CapabilityDelta, CapabilityAck, CapabilityHeartbeat, CapabilityRenewal, CapabilityDrain}
}
