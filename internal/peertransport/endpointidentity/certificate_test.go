package endpointidentity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestCertificateIsDeterministicAndIdentityBound(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	quicPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	claims := Claims{AccountID: "account_01", Role: RoleMachine, EndpointID: "machine_01", QUICPublicKey: quicPublic, Generation: 3, Serial: 9, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	copy(claims.NoisePublicKey[:], bytes.Repeat([]byte{7}, 32))
	first, err := Sign(rootPrivate, claims)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Sign(rootPrivate, claims)
	if err != nil {
		t.Fatal(err)
	}
	firstRaw, _ := first.MarshalBinary()
	secondRaw, _ := second.MarshalBinary()
	if !bytes.Equal(firstRaw, secondRaw) || first.Fingerprint() != second.Fingerprint() {
		t.Fatal("same claims produced different certificates")
	}
	verified, err := Verify(firstRaw, rootPublic, Expected{AccountID: claims.AccountID, Role: claims.Role, EndpointID: claims.EndpointID, Generation: claims.Generation}, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Claims.Serial != claims.Serial || !bytes.Equal(verified.Claims.NoisePublicKey[:], claims.NoisePublicKey[:]) {
		t.Fatalf("verified claims=%+v", verified.Claims)
	}
	rootFingerprint, err := RootFingerprint(rootPublic)
	if err != nil || len(rootFingerprint) != 64 {
		t.Fatalf("root fingerprint=%q err=%v", rootFingerprint, err)
	}
}

func TestCertificateRejectsTamperingSubstitutionAndExpiry(t *testing.T) {
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	otherRoot, _, _ := ed25519.GenerateKey(rand.Reader)
	quicPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0).UTC()
	certificate, err := Sign(rootPrivate, Claims{AccountID: "account_01", Role: RoleCLI, EndpointID: "cli_01", NoisePublicKey: noiseKey(2), QUICPublicKey: quicPublic, Generation: 2, Serial: 4, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := certificate.MarshalBinary()
	checks := []struct {
		name     string
		raw      []byte
		root     ed25519.PublicKey
		expected Expected
		now      time.Time
	}{
		{name: "wrong root", raw: raw, root: otherRoot, expected: Expected{AccountID: "account_01"}, now: now},
		{name: "wrong account", raw: raw, root: rootPublic, expected: Expected{AccountID: "account_02"}, now: now},
		{name: "wrong endpoint", raw: raw, root: rootPublic, expected: Expected{EndpointID: "cli_02"}, now: now},
		{name: "wrong role", raw: raw, root: rootPublic, expected: Expected{Role: RoleMachine}, now: now},
		{name: "wrong generation", raw: raw, root: rootPublic, expected: Expected{Generation: 3}, now: now},
		{name: "expired", raw: raw, root: rootPublic, expected: Expected{AccountID: "account_01"}, now: now.Add(time.Minute)},
	}
	tampered := append([]byte(nil), raw...)
	tampered[12] ^= 1
	checks = append(checks, struct {
		name     string
		raw      []byte
		root     ed25519.PublicKey
		expected Expected
		now      time.Time
	}{name: "tampered", raw: tampered, root: rootPublic, expected: Expected{}, now: now})
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if _, err := Verify(check.raw, check.root, check.expected, check.now); err == nil {
				t.Fatal("invalid certificate accepted")
			}
		})
	}
}

func TestTLSLeafRequiresCertifiedQUICKey(t *testing.T) {
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	quicPublic, quicPrivate, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0).UTC()
	certificate, err := Sign(rootPrivate, Claims{AccountID: "account_01", Role: RoleMachine, EndpointID: "machine_01", NoisePublicKey: noiseKey(3), QUICPublicKey: quicPublic, Generation: 1, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewTLSCertificate(certificate, rootPublic, wrongPrivate, now, time.Hour); err == nil {
		t.Fatal("wrong QUIC private key accepted")
	}
	leaf, err := NewTLSCertificate(certificate, rootPublic, quicPrivate, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := certificate.MarshalBinary()
	config, err := ServerTLS(leaf, PeerExpectation{RootPublic: rootPublic, Certificate: raw, Expected: Expected{AccountID: "account_01", Role: RoleMachine, EndpointID: "machine_01", Generation: 1}}, "paperboat-test-v1", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if !config.InsecureSkipVerify || config.VerifyConnection == nil || config.ClientAuth != tls.RequireAnyClientCert {
		t.Fatalf("config=%+v", config)
	}
}

func TestTLSVerifierRejectsEndpointSubstitutionAndLeafMutation(t *testing.T) {
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	quicPublic, quicPrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0).UTC()
	claims := Claims{AccountID: "account_01", Role: RoleMachine, EndpointID: "machine_01", QUICPublicKey: quicPublic, Generation: 1, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	copy(claims.NoisePublicKey[:], bytes.Repeat([]byte{1}, 32))
	expected, _ := Sign(rootPrivate, claims)
	expectedRaw, _ := expected.MarshalBinary()
	expectedLeaf, err := NewTLSCertificate(expected, rootPublic, quicPrivate, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	config, err := ClientTLS(expectedLeaf, PeerExpectation{RootPublic: rootPublic, Certificate: expectedRaw, Expected: Expected{AccountID: claims.AccountID, Role: claims.Role, EndpointID: claims.EndpointID, Generation: 1}}, "paperboat-test-v1", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{expectedLeaf.Leaf}, NegotiatedProtocol: "paperboat-test-v1"}
	if err := config.VerifyConnection(state); err != nil {
		t.Fatalf("valid leaf rejected: %v", err)
	}

	substitutedClaims := claims
	substitutedClaims.EndpointID = "machine_02"
	substitutedClaims.Serial = 2
	substituted, _ := Sign(rootPrivate, substitutedClaims)
	substitutedRaw, _ := substituted.MarshalBinary()
	if _, err := ClientTLS(expectedLeaf, PeerExpectation{RootPublic: rootPublic, Certificate: substitutedRaw, Expected: Expected{AccountID: claims.AccountID, Role: claims.Role, EndpointID: claims.EndpointID, Generation: 1}}, "paperboat-test-v1", func() time.Time { return now }); err == nil {
		t.Fatal("substituted endpoint identity accepted")
	}

	mutated := *expectedLeaf.Leaf
	mutated.Signature = append([]byte(nil), mutated.Signature...)
	mutated.Signature[0] ^= 1
	state.PeerCertificates = []*x509.Certificate{&mutated}
	if err := config.VerifyConnection(state); err == nil {
		t.Fatal("mutated leaf signature accepted")
	}
}

func noiseKey(value byte) [32]byte {
	var key [32]byte
	for index := range key {
		key[index] = value
	}
	return key
}
