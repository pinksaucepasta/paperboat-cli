package endpointidentity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type certificateVector struct {
	RootPublicKey          string `json:"root_public_key"`
	KeyID                  string `json:"key_id"`
	Certificate            string `json:"certificate"`
	CertificateFingerprint string `json:"certificate_fingerprint"`
	Now                    string `json:"now"`
}

func TestApprovedEndpointCertificateVector(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/contracts/p2p-v1/fixtures/endpoint-certificate.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector certificateVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	root, rootErr := base64.RawURLEncoding.Strict().DecodeString(vector.RootPublicKey)
	certificate, certificateErr := base64.RawURLEncoding.Strict().DecodeString(vector.Certificate)
	now, timeErr := time.Parse(time.RFC3339, vector.Now)
	if rootErr != nil || certificateErr != nil || timeErr != nil {
		t.Fatalf("root=%v certificate=%v time=%v", rootErr, certificateErr, timeErr)
	}
	verified, err := Verify(certificate, ed25519.PublicKey(root), Expected{AccountID: "account_01", Role: RoleCLI, EndpointID: "cli_01", Generation: 2}, now)
	if err != nil {
		t.Fatal(err)
	}
	rootFingerprint, err := RootFingerprint(ed25519.PublicKey(root))
	if err != nil || vector.KeyID != "aek_"+rootFingerprint || verified.Fingerprint() != vector.CertificateFingerprint || verified.Claims.Serial != 7 {
		t.Fatalf("root=%s certificate=%s serial=%d error=%v", vector.KeyID, verified.Fingerprint(), verified.Claims.Serial, err)
	}
}
