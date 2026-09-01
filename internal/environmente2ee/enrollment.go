package environmente2ee

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"io"
	"strings"

	"golang.org/x/crypto/blake2s"
)

type EnrollmentRequest struct {
	AccountID           string
	OperationID         [16]byte
	SubjectKind         SubjectKind
	SubjectID           string
	SubjectGeneration   uint64
	KeyGeneration       uint64
	EndpointCertificate []byte
	SigningPublic       ed25519.PublicKey
	SigningKeyID        string
	RecipientPublic     []byte
	RecipientKeyID      string
	RequestExpiresAt    uint64
}

type EnrollmentChallengeContext struct {
	AccountID      string
	RequestID      string
	OperationID    [16]byte
	RecipientKeyID string
	RequestDigest  [sha256.Size]byte
}

func CanonicalEnrollmentRequest(request EnrollmentRequest) ([]byte, error) {
	if validateEnrollmentRequest(request) != nil {
		return nil, ErrInvalid
	}
	raw, err := encode(enrollmentArray(request))
	if err != nil || len(raw) > MaximumEnrollmentBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}

func ParseEnrollmentRequest(raw []byte) (EnrollmentRequest, error) {
	var value any
	if decodeCanonical(raw, MaximumEnrollmentBytes, &value) != nil {
		return EnrollmentRequest{}, ErrInvalid
	}
	items, err := array(value, 15)
	if err != nil || requireDomain(items, "paperboat.environment.enrollment-request", 1) != nil {
		return EnrollmentRequest{}, ErrInvalid
	}
	account, e1 := text(items[2])
	operation, e2 := bytesValue(items[3], 16)
	kind, e3 := uintValue(items[4], false)
	subject, e4 := text(items[5])
	subjectGeneration, e5 := uintValue(items[6], false)
	keyGeneration, e6 := uintValue(items[7], false)
	endpoint, e7 := nullableBytes(items[8])
	signingPublic, e8 := nullableBytes(items[9])
	signingID, e9 := nullableText(items[10])
	recipientPublic, e10 := bytesValue(items[11], 32)
	recipientID, e11 := text(items[12])
	expiresAt, e12 := uintValue(items[14], false)
	if anyError(e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12) || items[13] != nil {
		return EnrollmentRequest{}, ErrInvalid
	}
	request := EnrollmentRequest{
		AccountID: account, SubjectKind: SubjectKind(kind), SubjectID: subject,
		SubjectGeneration: subjectGeneration, KeyGeneration: keyGeneration,
		EndpointCertificate: endpoint, RecipientPublic: recipientPublic,
		RecipientKeyID: recipientID, RequestExpiresAt: expiresAt,
	}
	copy(request.OperationID[:], operation)
	if signingPublic != nil {
		request.SigningPublic = ed25519.PublicKey(signingPublic)
	}
	if signingID != nil {
		request.SigningKeyID = *signingID
	}
	if validateEnrollmentRequest(request) != nil {
		return EnrollmentRequest{}, ErrInvalid
	}
	return request, nil
}

// VerifyPendingEnrollment parses the exact server-returned request, requires
// the correct proof shape for its subject kind, verifies a manager proof, and
// returns the independently recomputed safety code. Account, PBEC, generation,
// and receipt-time expiry authorization remain caller policy.
func VerifyPendingEnrollment(raw, signingProof []byte) (EnrollmentRequest, string, error) {
	request, err := ParseEnrollmentRequest(raw)
	if err != nil {
		return EnrollmentRequest{}, "", ErrInvalid
	}
	switch request.SubjectKind {
	case SubjectManagerCLI, SubjectManagerBrowser:
		if VerifyEnrollmentRequestSignature(request, signingProof) != nil {
			return EnrollmentRequest{}, "", ErrInvalid
		}
	case SubjectHost:
		if len(signingProof) != 0 {
			return EnrollmentRequest{}, "", ErrInvalid
		}
	default:
		return EnrollmentRequest{}, "", ErrInvalid
	}
	safety, err := EnrollmentSafetyCode(request)
	if err != nil {
		return EnrollmentRequest{}, "", ErrInvalid
	}
	return request, safety, nil
}

func SignEnrollmentRequest(request EnrollmentRequest, private ed25519.PrivateKey) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	raw, err := CanonicalEnrollmentRequest(request)
	if err != nil {
		return nil, err
	}
	kid, err := KeyIDEd25519(private.Public().(ed25519.PublicKey))
	if err != nil || kid != request.SigningKeyID {
		return nil, ErrInvalid
	}
	message, err := encode([]any{"paperboat.environment.enrollment-request-signature", uint64(1), raw})
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(private, message), nil
}

func VerifyEnrollmentRequestSignature(request EnrollmentRequest, signature []byte) error {
	if len(request.SigningPublic) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	raw, err := CanonicalEnrollmentRequest(request)
	if err != nil {
		return err
	}
	message, err := encode([]any{"paperboat.environment.enrollment-request-signature", uint64(1), raw})
	if err != nil || !ed25519.Verify(request.SigningPublic, message, signature) {
		return ErrInvalid
	}
	return nil
}

func EnrollmentSafetyCode(request EnrollmentRequest) (string, error) {
	raw, err := CanonicalEnrollmentRequest(request)
	if err != nil {
		return "", err
	}
	message, err := encode([]any{"paperboat.environment.enrollment-safety-code", uint64(1), raw})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(message)
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:10]))
	return encoded[:4] + "-" + encoded[4:8] + "-" + encoded[8:12] + "-" + encoded[12:16], nil
}

func EnrollmentRequestDigest(request EnrollmentRequest) ([sha256.Size]byte, error) {
	raw, err := CanonicalEnrollmentRequest(request)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

func SealEnrollmentChallenge(context EnrollmentChallengeContext, recipientPublic []byte, random io.Reader) (sealed, challenge []byte, resultErr error) {
	if validateChallengeContext(context) != nil {
		return nil, nil, ErrInvalid
	}
	kid, err := KeyIDX25519(recipientPublic)
	if err != nil || kid != context.RecipientKeyID {
		return nil, nil, ErrInvalid
	}
	if random == nil {
		random = rand.Reader
	}
	challenge = make([]byte, 32)
	if _, err = io.ReadFull(random, challenge); err != nil {
		return nil, nil, err
	}
	public, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(recipientPublic)
	if err != nil {
		clear(challenge)
		return nil, nil, ErrInvalid
	}
	info, _ := challengeInfo(context)
	aad, _ := challengeAAD(context)
	enc, sender, err := hpke.NewSender(public, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		clear(challenge)
		return nil, nil, ErrInvalid
	}
	ciphertext, err := sender.Seal(aad, challenge)
	if err != nil {
		clear(challenge)
		return nil, nil, ErrInvalid
	}
	sealed = append(cloneBytes(enc), ciphertext...)
	if len(sealed) != 80 {
		clear(challenge)
		clear(sealed)
		return nil, nil, ErrInvalid
	}
	return sealed, challenge, nil
}

func OpenEnrollmentChallenge(context EnrollmentChallengeContext, recipientPrivate, sealed []byte) ([]byte, error) {
	if validateChallengeContext(context) != nil || len(recipientPrivate) != 32 || len(sealed) != 80 {
		return nil, ErrInvalid
	}
	private, err := hpke.DHKEM(ecdh.X25519()).NewPrivateKey(recipientPrivate)
	if err != nil {
		return nil, ErrInvalid
	}
	kid, err := KeyIDX25519(private.PublicKey().Bytes())
	if err != nil || kid != context.RecipientKeyID {
		return nil, ErrInvalid
	}
	info, _ := challengeInfo(context)
	aad, _ := challengeAAD(context)
	receiver, err := hpke.NewRecipient(sealed[:32], private, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, ErrInvalid
	}
	challenge, err := receiver.Open(aad, sealed[32:])
	if err != nil || len(challenge) != 32 {
		clear(challenge)
		return nil, ErrInvalid
	}
	return challenge, nil
}

func EnrollmentProof(context EnrollmentChallengeContext, challenge []byte) ([sha256.Size]byte, error) {
	if validateChallengeContext(context) != nil || len(challenge) != 32 {
		return [sha256.Size]byte{}, ErrInvalid
	}
	raw, err := encode([]any{"paperboat.environment.enrollment-proof", uint64(1), context.AccountID, context.RequestID, context.OperationID[:], context.RequestDigest[:], challenge})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

func challengeInfo(c EnrollmentChallengeContext) ([]byte, error) {
	return encode([]any{"paperboat.environment.enrollment-challenge-info", uint64(1), uint64(1), c.AccountID, c.RequestID, c.OperationID[:], c.RecipientKeyID})
}
func challengeAAD(c EnrollmentChallengeContext) ([]byte, error) {
	return encode([]any{"paperboat.environment.enrollment-challenge-aad", uint64(1), c.RequestDigest[:]})
}
func validateChallengeContext(c EnrollmentChallengeContext) error {
	if !validIdentifier(c.AccountID) || !validIdentifier(c.RequestID) || allZero(c.OperationID[:]) || !validKeyID(c.RecipientKeyID) || allZero(c.RequestDigest[:]) {
		return ErrInvalid
	}
	return nil
}

func enrollmentArray(r EnrollmentRequest) []any {
	var endpoint, signing, signingID any
	if r.EndpointCertificate != nil {
		endpoint = r.EndpointCertificate
	}
	if r.SigningPublic != nil {
		signing = []byte(r.SigningPublic)
	}
	if r.SigningKeyID != "" {
		signingID = r.SigningKeyID
	}
	return []any{"paperboat.environment.enrollment-request", uint64(1), r.AccountID, r.OperationID[:], uint64(r.SubjectKind), r.SubjectID, r.SubjectGeneration, r.KeyGeneration, endpoint, signing, signingID, r.RecipientPublic, r.RecipientKeyID, nil, r.RequestExpiresAt}
}
func validateEnrollmentRequest(r EnrollmentRequest) error {
	if !validIdentifier(r.AccountID) || !validIdentifier(r.SubjectID) || r.SubjectGeneration == 0 || r.SubjectGeneration > MaximumContractInteger || r.KeyGeneration == 0 || r.KeyGeneration > MaximumContractInteger || r.RequestExpiresAt == 0 || r.RequestExpiresAt > MaximumContractInteger || allZero(r.OperationID[:]) {
		return ErrInvalid
	}
	kid, err := KeyIDX25519(r.RecipientPublic)
	if err != nil || kid != r.RecipientKeyID {
		return ErrInvalid
	}
	switch r.SubjectKind {
	case SubjectManagerCLI:
		if len(r.EndpointCertificate) == 0 {
			return ErrInvalid
		}
		fallthrough
	case SubjectManagerBrowser:
		sig, err := KeyIDEd25519(r.SigningPublic)
		if err != nil || sig != r.SigningKeyID {
			return ErrInvalid
		}
		if r.SubjectKind == SubjectManagerBrowser && len(r.EndpointCertificate) != 0 {
			return ErrInvalid
		}
	case SubjectHost:
		if len(r.EndpointCertificate) == 0 || len(r.SigningPublic) != 0 || r.SigningKeyID != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

const recoveryPrefix = "pb-env-recovery-v1-"

func EncodeRecovery(private []byte) (string, error) {
	encoded, err := EncodeRecoveryBytes(private)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func EncodeRecoveryBytes(private []byte) ([]byte, error) {
	canonical, err := canonicalPrivate(private)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 37)
	copy(payload, canonical)
	checksum := blake2s.Sum256(append([]byte("paperboat-env-recovery-v1\x00"), canonical...))
	copy(payload[32:], checksum[:5])
	clear(canonical)
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	encoded := make([]byte, len(recoveryPrefix)+encoding.EncodedLen(len(payload)))
	copy(encoded, recoveryPrefix)
	encoding.Encode(encoded[len(recoveryPrefix):], payload)
	for index := len(recoveryPrefix); index < len(encoded); index++ {
		if encoded[index] >= 'A' && encoded[index] <= 'Z' {
			encoded[index] += 'a' - 'A'
		}
	}
	clear(payload)
	return encoded, nil
}

func DecodeRecovery(value string) ([]byte, error) {
	return DecodeRecoveryBytes([]byte(value))
}

func DecodeRecoveryBytes(value []byte) ([]byte, error) {
	if !bytes.HasPrefix(value, []byte(recoveryPrefix)) {
		return nil, ErrInvalid
	}
	encoded := cloneBytes(value[len(recoveryPrefix):])
	defer clear(encoded)
	for index := range encoded {
		if encoded[index] >= 'A' && encoded[index] <= 'Z' {
			return nil, ErrInvalid
		}
		if encoded[index] >= 'a' && encoded[index] <= 'z' {
			encoded[index] -= 'a' - 'A'
		}
	}
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	decoded := make([]byte, encoding.DecodedLen(len(encoded)))
	count, err := encoding.Decode(decoded, encoded)
	decoded = decoded[:count]
	canonical := make([]byte, encoding.EncodedLen(len(decoded)))
	encoding.Encode(canonical, decoded)
	defer clear(canonical)
	if err != nil || len(decoded) != 37 || !bytes.Equal(canonical, encoded) {
		clear(decoded)
		return nil, ErrInvalid
	}
	checksum := blake2s.Sum256(append([]byte("paperboat-env-recovery-v1\x00"), decoded[:32]...))
	if subtle.ConstantTimeCompare(decoded[32:], checksum[:5]) != 1 {
		clear(decoded)
		return nil, ErrInvalid
	}
	private, err := canonicalPrivate(decoded[:32])
	clear(decoded)
	if err != nil {
		return nil, ErrInvalid
	}
	return private, nil
}

func canonicalPrivate(raw []byte) ([]byte, error) {
	if len(raw) != 32 {
		return nil, ErrInvalid
	}
	key, err := hpke.DHKEM(ecdh.X25519()).NewPrivateKey(raw)
	if err != nil {
		return nil, ErrInvalid
	}
	canonical, err := key.Bytes()
	if err != nil || len(canonical) != 32 {
		return nil, ErrInvalid
	}
	return canonical, nil
}
