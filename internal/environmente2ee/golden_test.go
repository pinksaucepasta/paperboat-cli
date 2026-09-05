package environmente2ee

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type goldenVector struct {
	Schema                     string            `json:"schema"`
	RootPublic                 string            `json:"root_public"`
	Authority                  string            `json:"authority"`
	AuthorityID                string            `json:"authority_id"`
	Manifest                   string            `json:"manifest"`
	ManifestID                 string            `json:"manifest_id"`
	SetManifest                string            `json:"set_manifest"`
	SetManifestID              string            `json:"set_manifest_id"`
	ExpectedValues             map[string]string `json:"expected_values"`
	Abort                      string            `json:"abort"`
	AbortID                    string            `json:"abort_id"`
	AbortTransitionID          string            `json:"abort_transition_id"`
	ManagerSigningSeed         string            `json:"manager_signing_seed"`
	ManagerRecipientPrivate    string            `json:"manager_recipient_private"`
	ManagerRecipientKeyID      string            `json:"manager_recipient_key_id"`
	HostRecipientPrivate       string            `json:"host_recipient_private"`
	HostRecipientKeyID         string            `json:"host_recipient_key_id"`
	ScopeKey                   string            `json:"scope_key"`
	CanonicalEnrollmentRequest string            `json:"canonical_enrollment_request"`
	SafetyCode                 string            `json:"safety_code"`
	Recovery                   string            `json:"recovery"`
}

func TestGoldenVector(t *testing.T) {
	file, err := os.Open("../../testdata/contracts/environment-e2ee-v1/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var vector goldenVector
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vector); err != nil {
		t.Fatal(err)
	}
	if vector.Schema != "paperboat.environment-e2ee-vector/v1" {
		t.Fatal("unexpected vector schema")
	}
	rootPublic := decodeVector(t, vector.RootPublic, ed25519.PublicKeySize)
	rootDigest := sha256.Sum256(rootPublic)
	rootID := "aek_" + hex.EncodeToString(rootDigest[:])
	authorityRaw := decodeVector(t, vector.Authority, -1)
	authority, err := ParseAuthority(authorityRaw, RootKeys{rootID: ed25519.PublicKey(rootPublic)})
	if err != nil || authority.ID.String() != vector.AuthorityID {
		t.Fatalf("authority vector rejected: id=%s err=%v", authority.ID, err)
	}
	manifestRaw := decodeVector(t, vector.Manifest, -1)
	manifest, err := ParseManifest(manifestRaw, authority)
	if err != nil || manifest.ID.String() != vector.ManifestID {
		t.Fatalf("manifest vector rejected: id=%s err=%v", manifest.ID, err)
	}
	scopeKey := decodeVector(t, vector.ScopeKey, 32)
	recipients := []RecipientPrivate{
		{Kind: RecipientManager, SubjectID: "cli_01", KeyGeneration: 1, KeyID: vector.ManagerRecipientKeyID, PrivateKey: decodeVector(t, vector.ManagerRecipientPrivate, 32)},
		{Kind: RecipientHost, SubjectID: "machine_01", KeyGeneration: 1, KeyID: vector.HostRecipientKeyID, PrivateKey: decodeVector(t, vector.HostRecipientPrivate, 32)},
	}
	for _, recipient := range recipients {
		decrypted, err := DecryptManifest(manifest, recipient)
		if err != nil || len(decrypted.Values) != 0 || !bytes.Equal(decrypted.ScopeKey, scopeKey) {
			t.Fatalf("recipient vector rejected: kind=%d err=%v", recipient.Kind, err)
		}
		clear(decrypted.ScopeKey)
	}
	setRaw := decodeVector(t, vector.SetManifest, -1)
	setManifest, err := ParseManifest(setRaw, authority)
	if err != nil || setManifest.ID.String() != vector.SetManifestID {
		t.Fatalf("set manifest vector rejected: id=%s err=%v", setManifest.ID, err)
	}
	if err := ValidateManifestSuccessor(&manifest, setManifest, false); err != nil {
		t.Fatalf("set manifest vector transition rejected: %v", err)
	}
	for _, recipient := range recipients {
		decrypted, err := DecryptManifest(setManifest, recipient)
		if err != nil || !bytes.Equal(decrypted.ScopeKey, scopeKey) || len(decrypted.Values) != len(vector.ExpectedValues) {
			t.Fatalf("set recipient vector rejected: kind=%d err=%v", recipient.Kind, err)
		}
		for name, expected := range vector.ExpectedValues {
			if string(decrypted.Values[name]) != expected {
				t.Fatalf("set value mismatch for %s", name)
			}
		}
		clearValues(decrypted.Values)
		clear(decrypted.ScopeKey)
	}
	f := fixture(t)
	manager := findBinding(t, f.authority, SubjectManagerCLI, "cli_01")
	request := EnrollmentRequest{AccountID: "acct_01", OperationID: [16]byte{4}, SubjectKind: SubjectManagerCLI, SubjectID: "cli_01", SubjectGeneration: 1, KeyGeneration: 1, EndpointCertificate: manager.EndpointCertificate, SigningPublic: manager.SigningPublic, SigningKeyID: manager.SigningKeyID, RecipientPublic: manager.RecipientPublic, RecipientKeyID: manager.RecipientKeyID, RequestExpiresAt: 1788134700}
	requestRaw, err := CanonicalEnrollmentRequest(request)
	if err != nil || !bytes.Equal(requestRaw, decodeVector(t, vector.CanonicalEnrollmentRequest, -1)) {
		t.Fatalf("enrollment request vector mismatch: %v", err)
	}
	safety, err := EnrollmentSafetyCode(request)
	if err != nil || safety != vector.SafetyCode {
		t.Fatalf("safety vector mismatch: %q %v", safety, err)
	}
	recovery, err := EncodeRecovery(f.recoveryPrivate)
	if err != nil || recovery != vector.Recovery {
		t.Fatalf("recovery vector mismatch: %v", err)
	}
	seed := decodeVector(t, vector.ManagerSigningSeed, ed25519.SeedSize)
	if !bytes.Equal(ed25519.NewKeyFromSeed(seed), f.managerSign) {
		t.Fatal("manager signing vector mismatch")
	}
	abort, err := ParseAuthorityTransitionAbort(decodeVector(t, vector.Abort, -1), f.rootKeys)
	if err != nil || abort.ID.String() != vector.AbortID || abort.ActiveAuthorityID != f.authority.ID || abort.TransitionID.String() != vector.AbortTransitionID {
		t.Fatalf("abort vector rejected: id=%s err=%v", abort.ID, err)
	}
}

func decodeVector(t *testing.T, value string, size int) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || size >= 0 && len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		t.Fatalf("invalid vector encoding: size=%d err=%v", len(decoded), err)
	}
	return decoded
}
