package endpointidentity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func FuzzParseCertificate(f *testing.F) {
	_, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	quicPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	valid, err := Sign(rootPrivate, Claims{
		AccountID: "account_01", EndpointID: "machine_01", Role: RoleMachine,
		NoisePublicKey: noiseKey(1), QUICPublicKey: quicPublic,
		Generation: 1, Serial: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		f.Fatal(err)
	}
	validRaw, err := valid.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validRaw)
	f.Add([]byte(nil))
	f.Add(make([]byte, maximumCertificateBytes+1))

	f.Fuzz(func(t *testing.T, raw []byte) {
		certificate, err := Parse(raw)
		if err != nil {
			return
		}
		if len(raw) > maximumCertificateBytes {
			t.Fatal("accepted certificate exceeds wire limit")
		}
		canonical, err := certificate.MarshalBinary()
		if err != nil {
			t.Fatalf("accepted certificate cannot be encoded: %v", err)
		}
		if !bytes.Equal(canonical, raw) {
			t.Fatal("accepted certificate is not canonical")
		}
	})
}

func FuzzVerifyCertificate(f *testing.F) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	quicPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	expected := Expected{AccountID: "account_01", EndpointID: "machine_01", Role: RoleMachine, Generation: 3}
	valid, err := Sign(rootPrivate, Claims{
		AccountID: expected.AccountID, EndpointID: expected.EndpointID, Role: expected.Role,
		NoisePublicKey: noiseKey(2), QUICPublicKey: quicPublic,
		Generation: expected.Generation, Serial: 9, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		f.Fatal(err)
	}
	validRaw, err := valid.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validRaw)
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, raw []byte) {
		certificate, err := Verify(raw, rootPublic, expected, now)
		if err != nil {
			return
		}
		claims := certificate.Claims
		if claims.AccountID != expected.AccountID || claims.EndpointID != expected.EndpointID || claims.Role != expected.Role || claims.Generation != expected.Generation {
			t.Fatal("verified certificate escaped expected identity")
		}
		if now.Before(claims.IssuedAt) || !now.Before(claims.ExpiresAt) {
			t.Fatal("verified certificate escaped validity window")
		}
		canonical, err := certificate.MarshalBinary()
		if err != nil || !bytes.Equal(canonical, raw) {
			t.Fatalf("verified certificate is not canonical: %v", err)
		}
	})
}
