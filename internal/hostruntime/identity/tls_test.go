package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

func TestCurrentTLSCertificateIsEphemeralClientLeafForCurrentIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	store, err := Open(Config{StateRoot: root, Random: bytes.NewReader(bytes.Repeat([]byte{0x37}, ed25519.SeedSize))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	certificate, err := store.CurrentTLSCertificate(now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.Certificate) != 1 || certificate.PrivateKey == nil || certificate.Leaf == nil {
		t.Fatalf("certificate = %#v", certificate)
	}
	key := store.Current()
	public, ok := certificate.PrivateKey.(ed25519.PrivateKey)
	if !ok || !bytes.Equal(public.Public().(ed25519.PublicKey), key.Public()) {
		t.Fatal("TLS leaf does not use the current machine key")
	}
	if certificate.Leaf.IsCA || !certificate.Leaf.BasicConstraintsValid {
		// The certificate is a leaf, not a CA. IsCA must be false while the
		// basic constraints extension remains valid.
		t.Fatalf("unexpected CA constraints: is_ca=%v valid=%v", certificate.Leaf.IsCA, certificate.Leaf.BasicConstraintsValid)
	}
	if len(certificate.Leaf.ExtKeyUsage) != 1 || certificate.Leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("extended key usages = %v", certificate.Leaf.ExtKeyUsage)
	}
	if !certificate.Leaf.NotBefore.Before(now) || !certificate.Leaf.NotAfter.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("validity = %s..%s", certificate.Leaf.NotBefore, certificate.Leaf.NotAfter)
	}
	if err := certificate.Leaf.CheckSignature(certificate.Leaf.SignatureAlgorithm, certificate.Leaf.RawTBSCertificate, certificate.Leaf.Signature); err != nil {
		t.Fatalf("self signature: %v", err)
	}
	if got := base64.RawURLEncoding.EncodeToString(key.Public()); got == "" {
		t.Fatal("current public key unexpectedly empty")
	}
}

func TestCurrentTLSCertificateRejectsLongLivedOrInvalidRequests(t *testing.T) {
	store, err := Open(Config{StateRoot: filepath.Join(t.TempDir(), "identity"), Random: bytes.NewReader(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	for name, lifetime := range map[string]time.Duration{"zero": 0, "long": MaxTLSCertificateLifetime + time.Nanosecond} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.CurrentTLSCertificate(now, lifetime); !errors.Is(err, ErrInvalidTLSCertificate) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if _, err := store.CurrentTLSCertificate(time.Time{}, time.Minute); !errors.Is(err, ErrInvalidTLSCertificate) {
		t.Fatalf("zero time err=%v", err)
	}
}

func TestCurrentTLSCertificateWithURIsCarriesOneEphemeralBinding(t *testing.T) {
	store, err := Open(Config{StateRoot: filepath.Join(t.TempDir(), "identity"), Random: bytes.NewReader(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	uri, err := url.Parse("urn:paperboat:connector-v1:carrier:test")
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := store.CurrentTLSCertificateWithURIs(now, time.Minute, []*url.URL{uri})
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.Leaf.URIs) != 1 || certificate.Leaf.URIs[0].String() != uri.String() {
		t.Fatalf("URI SANs = %v", certificate.Leaf.URIs)
	}
	if _, err := store.CurrentTLSCertificateWithURIs(now, time.Minute, nil); !errors.Is(err, ErrInvalidTLSCertificate) {
		t.Fatalf("missing URI error = %v", err)
	}
}
