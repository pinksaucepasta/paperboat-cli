package identity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
)

var errPeerEndpointGeneration = errors.New("peer endpoint generation changed")

type PeerEndpoint struct {
	Generation      uint64
	NoisePrivateKey [32]byte
	QUICPrivateKey  ed25519.PrivateKey
	RootPublicKey   ed25519.PublicKey
	RootKeyID       string
	// TrustedKeys is the complete account E2EE root set authenticated by the
	// machine endpoint approval response. RootPublicKey remains the key which
	// issued this endpoint certificate; ENV documents may be signed by another
	// root in the same enrolled set.
	TrustedKeys []endpointidentity.TrustedKey
	Certificate []byte
}

func (p PeerEndpoint) NoisePublicKey() [32]byte { return peerNoisePublic(p.NoisePrivateKey) }

func (p PeerEndpoint) QUICPublicKey() ed25519.PublicKey {
	if len(p.QUICPrivateKey) != ed25519.PrivateKeySize {
		return nil
	}
	return append(ed25519.PublicKey(nil), p.QUICPrivateKey.Public().(ed25519.PublicKey)...)
}

type peerEndpointDocument struct {
	Version         int                              `json:"version"`
	Generation      uint64                           `json:"generation"`
	NoisePrivateKey string                           `json:"noise_private_key_base64url"`
	QUICSeed        string                           `json:"quic_seed_base64url"`
	Certificate     string                           `json:"certificate_base64url,omitempty"`
	RootPublicKey   string                           `json:"root_public_key_base64url,omitempty"`
	RootKeyID       string                           `json:"root_key_id,omitempty"`
	TrustedKeys     []peerEndpointTrustedKeyDocument `json:"trusted_keys,omitempty"`
}

type peerEndpointTrustedKeyDocument struct {
	KeyID       string `json:"key_id"`
	PublicKey   string `json:"public_key_base64url"`
	Fingerprint string `json:"fingerprint_hex"`
	Generation  uint64 `json:"generation"`
}

func (s *Store) PeerEndpoint() (PeerEndpoint, error) {
	registration, err := s.Registration()
	if err != nil || registration.InstallationGeneration < 1 {
		return PeerEndpoint{}, ErrInvalidStore
	}
	value, err := s.loadPeerEndpoint(uint64(registration.InstallationGeneration), registration.MachineID)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, errPeerEndpointGeneration) {
		value, err = s.generatePeerEndpoint(uint64(registration.InstallationGeneration))
		if err == nil {
			err = s.writePeerEndpoint(value)
		}
	} else if errors.Is(err, ErrInvalidStore) && s.recoverableUnsignedPeerEndpoint(uint64(registration.InstallationGeneration)) {
		// An endpoint without a certificate is replaceable local key material. Recover
		// malformed unsigned state so a host can self-heal after interrupted writes;
		// certified state remains fail-closed in loadPeerEndpoint.
		value, err = s.generatePeerEndpoint(uint64(registration.InstallationGeneration))
		if err == nil {
			err = s.writePeerEndpoint(value)
		}
	}
	return value, err
}

func (s *Store) recoverableUnsignedPeerEndpoint(generation uint64) bool {
	path := filepath.Join(s.config.StateRoot, "peer-endpoint.json")
	info, err := os.Lstat(path)
	if err != nil || !secureIdentityPath(path, info, true) || info.Size() > 16<<10 {
		return false
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var document peerEndpointDocument
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var extra any
	return decoder.Decode(&document) == nil && decoder.Decode(&extra) == io.EOF && document.Version == 1 && document.Generation == generation && document.Certificate == ""
}

func (s *Store) SavePeerEndpointCertificate(rootPublic ed25519.PublicKey, raw []byte, now time.Time) error {
	return s.SavePeerEndpointCertificateWithTrustedKeys(rootPublic, nil, raw, now)
}

// SavePeerEndpointCertificateWithTrustedKeys persists the endpoint
// certificate and the complete account root set returned by the authenticated
// machine enrollment ceremony. The certificate issuer must be a member of the
// set. A nil set retains the legacy single-root representation.
func (s *Store) SavePeerEndpointCertificateWithTrustedKeys(rootPublic ed25519.PublicKey, trusted []endpointidentity.TrustedKey, raw []byte, now time.Time) error {
	value, err := s.PeerEndpoint()
	if err != nil {
		return err
	}
	registration, err := s.Registration()
	if err != nil {
		return err
	}
	certificate, err := endpointidentity.Verify(raw, rootPublic, endpointidentity.Expected{Role: endpointidentity.RoleMachine, EndpointID: registration.MachineID, Generation: value.Generation}, now.UTC())
	noisePublic := peerNoisePublic(value.NoisePrivateKey)
	if err != nil || !bytes.Equal(certificate.Claims.NoisePublicKey[:], noisePublic[:]) || !bytes.Equal(certificate.Claims.QUICPublicKey, value.QUICPrivateKey.Public().(ed25519.PublicKey)) {
		return ErrInvalidStore
	}
	trusted, err = normalizeTrustedKeys(rootPublic, trusted)
	if err != nil {
		return err
	}
	value.Certificate = append([]byte(nil), raw...)
	value.RootPublicKey = append(ed25519.PublicKey(nil), rootPublic...)
	fingerprint := sha256.Sum256(rootPublic)
	value.RootKeyID = "aek_" + hex.EncodeToString(fingerprint[:])
	value.TrustedKeys = trusted
	return s.writePeerEndpoint(value)
}

func (s *Store) generatePeerEndpoint(generation uint64) (PeerEndpoint, error) {
	noise, err := ecdh.X25519().GenerateKey(s.config.Random)
	if err != nil {
		return PeerEndpoint{}, err
	}
	_, quic, err := ed25519.GenerateKey(s.config.Random)
	if err != nil {
		return PeerEndpoint{}, err
	}
	var noisePrivate [32]byte
	copy(noisePrivate[:], noise.Bytes())
	return PeerEndpoint{Generation: generation, NoisePrivateKey: noisePrivate, QUICPrivateKey: quic}, nil
}

func (s *Store) loadPeerEndpoint(generation uint64, machineID string) (PeerEndpoint, error) {
	path := filepath.Join(s.config.StateRoot, "peer-endpoint.json")
	info, err := os.Lstat(path)
	if err != nil {
		return PeerEndpoint{}, err
	}
	if !secureIdentityPath(path, info, true) || info.Size() > 16<<10 {
		return PeerEndpoint{}, ErrInvalidStore
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return PeerEndpoint{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var document peerEndpointDocument
	var extra any
	if decoder.Decode(&document) != nil || decoder.Decode(&extra) != io.EOF || document.Version != 1 {
		return PeerEndpoint{}, ErrInvalidStore
	}
	if document.Generation != generation {
		return PeerEndpoint{}, errPeerEndpointGeneration
	}
	noise, noiseErr := base64.RawURLEncoding.Strict().DecodeString(document.NoisePrivateKey)
	seed, seedErr := base64.RawURLEncoding.Strict().DecodeString(document.QUICSeed)
	certificate, certificateErr := base64.RawURLEncoding.Strict().DecodeString(document.Certificate)
	rootPublic, rootErr := base64.RawURLEncoding.Strict().DecodeString(document.RootPublicKey)
	rootFingerprint := sha256.Sum256(rootPublic)
	expectedRootKeyID := "aek_" + hex.EncodeToString(rootFingerprint[:])
	if noiseErr != nil || seedErr != nil || len(noise) != 32 || len(seed) != ed25519.SeedSize || document.NoisePrivateKey != base64.RawURLEncoding.EncodeToString(noise) || document.QUICSeed != base64.RawURLEncoding.EncodeToString(seed) || document.Certificate != "" && (certificateErr != nil || rootErr != nil || len(rootPublic) != ed25519.PublicKeySize || document.RootKeyID != expectedRootKeyID) || document.Certificate == "" && (document.RootPublicKey != "" || document.RootKeyID != "" || len(document.TrustedKeys) != 0) {
		return PeerEndpoint{}, ErrInvalidStore
	}
	trusted, err := decodeTrustedKeys(document.TrustedKeys)
	if err != nil {
		return PeerEndpoint{}, ErrInvalidStore
	}
	if len(trusted) > 0 {
		if _, ok := endpointidentity.TrustedKeyFor(trusted, expectedRootKeyID); !ok {
			return PeerEndpoint{}, ErrInvalidStore
		}
	}
	var noisePrivate [32]byte
	copy(noisePrivate[:], noise)
	clear(noise)
	private := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	value := PeerEndpoint{Generation: generation, NoisePrivateKey: noisePrivate, QUICPrivateKey: private, RootPublicKey: ed25519.PublicKey(rootPublic), RootKeyID: document.RootKeyID, TrustedKeys: trusted, Certificate: certificate}
	if len(certificate) > 0 {
		verified, err := endpointidentity.Verify(certificate, value.RootPublicKey, endpointidentity.Expected{Role: endpointidentity.RoleMachine, EndpointID: machineID, Generation: generation}, s.config.Clock.Now().UTC())
		noisePublic := value.NoisePublicKey()
		if err != nil || !bytes.Equal(verified.Claims.NoisePublicKey[:], noisePublic[:]) || !bytes.Equal(verified.Claims.QUICPublicKey, value.QUICPublicKey()) {
			return PeerEndpoint{}, ErrInvalidStore
		}
	}
	return value, nil
}

func (s *Store) writePeerEndpoint(value PeerEndpoint) error {
	if value.Generation == 0 || len(value.QUICPrivateKey) != ed25519.PrivateKeySize {
		return ErrInvalidStore
	}
	document := peerEndpointDocument{Version: 1, Generation: value.Generation, NoisePrivateKey: base64.RawURLEncoding.EncodeToString(value.NoisePrivateKey[:]), QUICSeed: base64.RawURLEncoding.EncodeToString(value.QUICPrivateKey.Seed())}
	if len(value.Certificate) > 0 {
		if len(value.RootPublicKey) != ed25519.PublicKeySize {
			return ErrInvalidStore
		}
		fingerprint := sha256.Sum256(value.RootPublicKey)
		expectedRootKeyID := "aek_" + hex.EncodeToString(fingerprint[:])
		if value.RootKeyID != expectedRootKeyID {
			return ErrInvalidStore
		}
		document.Certificate = base64.RawURLEncoding.EncodeToString(value.Certificate)
		document.RootPublicKey = base64.RawURLEncoding.EncodeToString(value.RootPublicKey)
		document.RootKeyID = value.RootKeyID
		trusted, err := normalizeTrustedKeys(value.RootPublicKey, value.TrustedKeys)
		if err != nil {
			return err
		}
		document.TrustedKeys = make([]peerEndpointTrustedKeyDocument, 0, len(trusted))
		for _, key := range trusted {
			document.TrustedKeys = append(document.TrustedKeys, peerEndpointTrustedKeyDocument{
				KeyID: key.KeyID, PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey),
				Fingerprint: hex.EncodeToString(key.Fingerprint[:]), Generation: key.Generation,
			})
		}
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return err
	}
	return s.writePrivateDocument("peer-endpoint.json", ".peer-endpoint-*", encoded)
}

func normalizeTrustedKeys(rootPublic ed25519.PublicKey, trusted []endpointidentity.TrustedKey) ([]endpointidentity.TrustedKey, error) {
	rootFingerprint := sha256.Sum256(rootPublic)
	rootKeyID := "aek_" + hex.EncodeToString(rootFingerprint[:])
	if len(trusted) == 0 {
		return []endpointidentity.TrustedKey{{KeyID: rootKeyID, PublicKey: append(ed25519.PublicKey(nil), rootPublic...), Fingerprint: rootFingerprint, Generation: 1}}, nil
	}
	validated, err := endpointidentity.ValidateTrustedKeySet(trusted)
	if err != nil {
		return nil, ErrInvalidStore
	}
	for _, key := range validated {
		fingerprint := sha256.Sum256(key.PublicKey)
		if key.KeyID != "aek_"+hex.EncodeToString(fingerprint[:]) {
			clearTrustedKeys(validated)
			return nil, ErrInvalidStore
		}
	}
	if _, ok := endpointidentity.TrustedKeyFor(validated, rootKeyID); !ok {
		clearTrustedKeys(validated)
		return nil, ErrInvalidStore
	}
	return validated, nil
}

func decodeTrustedKeys(documents []peerEndpointTrustedKeyDocument) ([]endpointidentity.TrustedKey, error) {
	if len(documents) == 0 {
		return nil, nil
	}
	keys := make([]endpointidentity.TrustedKey, 0, len(documents))
	for _, document := range documents {
		public, publicErr := base64.RawURLEncoding.Strict().DecodeString(document.PublicKey)
		fingerprintBytes, fingerprintErr := hex.DecodeString(document.Fingerprint)
		if publicErr != nil || len(public) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(public) != document.PublicKey || fingerprintErr != nil || len(fingerprintBytes) != sha256.Size || hex.EncodeToString(fingerprintBytes) != document.Fingerprint {
			clear(public)
			clear(fingerprintBytes)
			return nil, ErrInvalidStore
		}
		var fingerprint [sha256.Size]byte
		copy(fingerprint[:], fingerprintBytes)
		clear(fingerprintBytes)
		keys = append(keys, endpointidentity.TrustedKey{KeyID: document.KeyID, PublicKey: ed25519.PublicKey(public), Fingerprint: fingerprint, Generation: document.Generation})
	}
	validated, err := endpointidentity.ValidateTrustedKeySet(keys)
	clearTrustedKeys(keys)
	if err != nil {
		return nil, ErrInvalidStore
	}
	for _, key := range validated {
		fingerprint := sha256.Sum256(key.PublicKey)
		if key.KeyID != "aek_"+hex.EncodeToString(fingerprint[:]) {
			clearTrustedKeys(validated)
			return nil, ErrInvalidStore
		}
	}
	return validated, nil
}

func clearTrustedKeys(keys []endpointidentity.TrustedKey) {
	for index := range keys {
		clear(keys[index].PublicKey)
	}
}

func peerNoisePublic(private [32]byte) [32]byte {
	key, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		return [32]byte{}
	}
	var public [32]byte
	copy(public[:], key.PublicKey().Bytes())
	return public
}
