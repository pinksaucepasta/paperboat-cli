package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"time"
)

var ErrInvalidTLSCertificate = errors.New("invalid machine identity TLS certificate")

const (
	DefaultTLSCertificateLifetime = 5 * time.Minute
	MaxTLSCertificateLifetime     = 10 * time.Minute
)

// CurrentTLSCertificate creates a short-lived, in-memory client certificate
// for the current machine identity. The private key is never persisted or
// returned through the identity metadata APIs. Callers must supply the
// resulting certificate only to the authenticated transport that needs it.
func (s *Store) CurrentTLSCertificate(now time.Time, lifetime time.Duration) (tls.Certificate, error) {
	return s.currentTLSCertificate(now, lifetime, nil)
}

// CurrentTLSCertificateWithURIs creates the same ephemeral client leaf while
// carrying a caller-supplied URI SAN. Carrier transports use one URI SAN for
// the exact non-secret connector identity; the enrolled machine key remains
// the signing key and is never rotated or persisted by this method.
func (s *Store) CurrentTLSCertificateWithURIs(now time.Time, lifetime time.Duration, uris []*url.URL) (tls.Certificate, error) {
	if len(uris) != 1 || uris[0] == nil || uris[0].String() == "" {
		return tls.Certificate{}, ErrInvalidTLSCertificate
	}
	return s.currentTLSCertificate(now, lifetime, uris)
}

func (s *Store) currentTLSCertificate(now time.Time, lifetime time.Duration, uris []*url.URL) (tls.Certificate, error) {
	if s == nil {
		return tls.Certificate{}, ErrInvalidTLSCertificate
	}
	if now.IsZero() || lifetime <= 0 || lifetime > MaxTLSCertificateLifetime {
		return tls.Certificate{}, ErrInvalidTLSCertificate
	}
	now = now.UTC()
	key := s.Current()
	if len(key.private) != ed25519.PrivateKeySize || key.ID == "" {
		return tls.Certificate{}, ErrInvalidTLSCertificate
	}
	public, ok := key.private.Public().(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return tls.Certificate{}, ErrInvalidTLSCertificate
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, ErrInvalidTLSCertificate
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: key.ID},
		NotBefore:             now.Add(-30 * time.Second),
		NotAfter:              now.Add(lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key.private)
	if err != nil {
		return tls.Certificate{}, ErrInvalidTLSCertificate
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, ErrInvalidTLSCertificate
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key.private, Leaf: leaf}, nil
}
