package endpointidentity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const maximumLeafLifetime = 24 * time.Hour

type PeerExpectation struct {
	RootPublic  ed25519.PublicKey
	Certificate []byte
	Expected    Expected
}

func NewTLSCertificate(certificate Certificate, rootPublic ed25519.PublicKey, private ed25519.PrivateKey, now time.Time, lifetime time.Duration) (tls.Certificate, error) {
	raw, err := certificate.MarshalBinary()
	if err != nil {
		return tls.Certificate{}, err
	}
	verified, err := Verify(raw, rootPublic, Expected{AccountID: certificate.Claims.AccountID, Role: certificate.Claims.Role, EndpointID: certificate.Claims.EndpointID, Generation: certificate.Claims.Generation}, now)
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(private) != ed25519.PrivateKeySize || !bytes.Equal(private.Public().(ed25519.PublicKey), verified.Claims.QUICPublicKey) {
		return tls.Certificate{}, errors.New("QUIC private key does not match endpoint certificate")
	}
	if lifetime <= 0 || lifetime > maximumLeafLifetime {
		return tls.Certificate{}, errors.New("invalid QUIC leaf lifetime")
	}
	notBefore := now.UTC().Add(-time.Minute).Truncate(time.Second)
	notAfter := now.UTC().Add(lifetime).Truncate(time.Second)
	if notAfter.After(verified.Claims.ExpiresAt) {
		notAfter = verified.Claims.ExpiresAt
	}
	if !notAfter.After(notBefore) {
		return tls.Certificate{}, errors.New("endpoint certificate expires too soon for a QUIC leaf")
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate QUIC leaf serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: verified.Claims.EndpointID},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create QUIC leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse QUIC leaf: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: leaf}, nil
}

func ClientTLS(local tls.Certificate, peer PeerExpectation, alpn string, now func() time.Time) (*tls.Config, error) {
	return tlsConfig(local, peer, alpn, now, false)
}

func ServerTLS(local tls.Certificate, peer PeerExpectation, alpn string, now func() time.Time) (*tls.Config, error) {
	return tlsConfig(local, peer, alpn, now, true)
}

func tlsConfig(local tls.Certificate, peer PeerExpectation, alpn string, now func() time.Time, server bool) (*tls.Config, error) {
	if len(local.Certificate) != 1 || local.PrivateKey == nil || alpn == "" || now == nil {
		return nil, errors.New("invalid endpoint TLS configuration")
	}
	if _, err := Verify(peer.Certificate, peer.RootPublic, peer.Expected, now()); err != nil {
		return nil, fmt.Errorf("verify expected peer: %w", err)
	}
	verify := func(state tls.ConnectionState) error {
		expected, err := Verify(peer.Certificate, peer.RootPublic, peer.Expected, now())
		if err != nil {
			return fmt.Errorf("revalidate expected peer: %w", err)
		}
		if len(state.PeerCertificates) != 1 {
			return errors.New("peer presented an invalid certificate chain")
		}
		leaf := state.PeerCertificates[0]
		if now().Before(leaf.NotBefore) || !now().Before(leaf.NotAfter) || leaf.NotAfter.Sub(leaf.NotBefore) > maximumLeafLifetime+time.Minute {
			return errors.New("peer QUIC leaf is not currently valid")
		}
		public, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok || !bytes.Equal(public, expected.Claims.QUICPublicKey) {
			return errors.New("peer QUIC key does not match endpoint certificate")
		}
		if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
			return errors.New("peer QUIC leaf self-signature is invalid")
		}
		if state.NegotiatedProtocol != alpn {
			return errors.New("peer QUIC ALPN mismatch")
		}
		return nil
	}
	config := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{alpn},
		Certificates: []tls.Certificate{local},
		// The peer uses a self-signed leaf. VerifyConnection below replaces
		// ambient Web PKI with the pinned Paperboat endpoint certificate.
		InsecureSkipVerify: true, //nolint:gosec
		VerifyConnection:   verify,
	}
	if server {
		config.ClientAuth = tls.RequireAnyClientCert
	}
	return config, nil
}
