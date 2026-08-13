// Package endpointidentity implements Paperboat's account-rooted endpoint identity.
package endpointidentity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	ProtocolVersion         = 1
	maximumContractInteger  = 9007199254740991
	encodedClaimsLen        = 4 + 1 + 2 + 128 + 1 + 2 + 128 + 32 + 32 + 8 + 8 + 8 + 8
	maximumCertificateBytes = encodedClaimsLen + ed25519.SignatureSize
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

type Role uint8

const (
	RoleCLI Role = iota + 1
	RoleMachine
)

type Claims struct {
	AccountID      string
	Role           Role
	EndpointID     string
	NoisePublicKey [32]byte
	QUICPublicKey  ed25519.PublicKey
	Generation     uint64
	Serial         uint64
	IssuedAt       time.Time
	ExpiresAt      time.Time
}

type Certificate struct {
	Claims    Claims
	Signature [ed25519.SignatureSize]byte
	raw       []byte
}

type Expected struct {
	AccountID  string
	Role       Role
	EndpointID string
	Generation uint64
}

func Sign(rootPrivate ed25519.PrivateKey, claims Claims) (Certificate, error) {
	if len(rootPrivate) != ed25519.PrivateKeySize {
		return Certificate{}, errors.New("invalid account root private key")
	}
	payload, err := marshalClaims(claims)
	if err != nil {
		return Certificate{}, err
	}
	signature := ed25519.Sign(rootPrivate, payload)
	raw := append(append([]byte(nil), payload...), signature...)
	var fixed [ed25519.SignatureSize]byte
	copy(fixed[:], signature)
	return Certificate{Claims: cloneClaims(claims), Signature: fixed, raw: raw}, nil
}

func Parse(raw []byte) (Certificate, error) {
	if len(raw) < ed25519.SignatureSize || len(raw) > maximumCertificateBytes {
		return Certificate{}, errors.New("endpoint certificate size is invalid")
	}
	payload := raw[:len(raw)-ed25519.SignatureSize]
	claims, err := unmarshalClaims(payload)
	if err != nil {
		return Certificate{}, err
	}
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], raw[len(payload):])
	return Certificate{Claims: claims, Signature: signature, raw: append([]byte(nil), raw...)}, nil
}

func Verify(raw []byte, rootPublic ed25519.PublicKey, expected Expected, now time.Time) (Certificate, error) {
	if len(rootPublic) != ed25519.PublicKeySize {
		return Certificate{}, errors.New("invalid account root public key")
	}
	certificate, err := Parse(raw)
	if err != nil {
		return Certificate{}, err
	}
	payload := certificate.raw[:len(certificate.raw)-ed25519.SignatureSize]
	if !ed25519.Verify(rootPublic, payload, certificate.Signature[:]) {
		return Certificate{}, errors.New("endpoint certificate signature is invalid")
	}
	claims := certificate.Claims
	if expected.AccountID != "" && subtle.ConstantTimeCompare([]byte(claims.AccountID), []byte(expected.AccountID)) != 1 ||
		expected.EndpointID != "" && subtle.ConstantTimeCompare([]byte(claims.EndpointID), []byte(expected.EndpointID)) != 1 ||
		expected.Role != 0 && claims.Role != expected.Role ||
		expected.Generation != 0 && claims.Generation != expected.Generation {
		return Certificate{}, errors.New("endpoint certificate identity does not match")
	}
	if now.Before(claims.IssuedAt) || !now.Before(claims.ExpiresAt) {
		return Certificate{}, errors.New("endpoint certificate is not currently valid")
	}
	return certificate, nil
}

func (c Certificate) MarshalBinary() ([]byte, error) {
	if len(c.raw) == 0 {
		return nil, errors.New("empty endpoint certificate")
	}
	return append([]byte(nil), c.raw...), nil
}

func (c Certificate) Fingerprint() string {
	digest := sha256.Sum256(c.raw)
	return hex.EncodeToString(digest[:])
}

func RootFingerprint(rootPublic ed25519.PublicKey) (string, error) {
	if len(rootPublic) != ed25519.PublicKeySize {
		return "", errors.New("invalid account root public key")
	}
	digest := sha256.Sum256(rootPublic)
	return hex.EncodeToString(digest[:]), nil
}

func marshalClaims(claims Claims) ([]byte, error) {
	if !identifierPattern.MatchString(claims.AccountID) || !identifierPattern.MatchString(claims.EndpointID) {
		return nil, errors.New("invalid endpoint certificate identifier")
	}
	if claims.Role != RoleCLI && claims.Role != RoleMachine {
		return nil, errors.New("invalid endpoint role")
	}
	if len(claims.QUICPublicKey) != ed25519.PublicKeySize || claims.Generation == 0 || claims.Generation > maximumContractInteger || claims.Serial == 0 || claims.Serial > maximumContractInteger {
		return nil, errors.New("invalid endpoint certificate key or version")
	}
	var zeroNoise [32]byte
	if subtle.ConstantTimeCompare(claims.NoisePublicKey[:], zeroNoise[:]) == 1 || allZero(claims.QUICPublicKey) {
		return nil, errors.New("endpoint public keys must not be zero")
	}
	issued := claims.IssuedAt.UTC().Truncate(time.Second)
	expires := claims.ExpiresAt.UTC().Truncate(time.Second)
	if issued.IsZero() || !expires.After(issued) {
		return nil, errors.New("invalid endpoint certificate validity")
	}
	buffer := make([]byte, 0, encodedClaimsLen)
	buffer = append(buffer, 'P', 'B', 'E', 'C', ProtocolVersion)
	buffer = appendString(buffer, claims.AccountID)
	buffer = append(buffer, byte(claims.Role))
	buffer = appendString(buffer, claims.EndpointID)
	buffer = append(buffer, claims.NoisePublicKey[:]...)
	buffer = append(buffer, claims.QUICPublicKey...)
	buffer = binary.BigEndian.AppendUint64(buffer, claims.Generation)
	buffer = binary.BigEndian.AppendUint64(buffer, claims.Serial)
	buffer = binary.BigEndian.AppendUint64(buffer, uint64(issued.Unix()))
	buffer = binary.BigEndian.AppendUint64(buffer, uint64(expires.Unix()))
	return buffer, nil
}

func unmarshalClaims(payload []byte) (Claims, error) {
	if len(payload) < 5 || string(payload[:4]) != "PBEC" || payload[4] != ProtocolVersion {
		return Claims{}, errors.New("invalid endpoint certificate protocol")
	}
	offset := 5
	accountID, err := readString(payload, &offset)
	if err != nil || offset >= len(payload) {
		return Claims{}, errors.New("invalid endpoint certificate account")
	}
	role := Role(payload[offset])
	offset++
	endpointID, err := readString(payload, &offset)
	if err != nil || len(payload)-offset != 32+32+8+8+8+8 {
		return Claims{}, errors.New("invalid endpoint certificate length")
	}
	var noise [32]byte
	copy(noise[:], payload[offset:offset+32])
	offset += 32
	quicPublic := append(ed25519.PublicKey(nil), payload[offset:offset+32]...)
	offset += 32
	claims := Claims{AccountID: accountID, Role: role, EndpointID: endpointID, NoisePublicKey: noise, QUICPublicKey: quicPublic}
	claims.Generation = binary.BigEndian.Uint64(payload[offset:])
	offset += 8
	claims.Serial = binary.BigEndian.Uint64(payload[offset:])
	offset += 8
	issued := int64(binary.BigEndian.Uint64(payload[offset:]))
	offset += 8
	expires := int64(binary.BigEndian.Uint64(payload[offset:]))
	claims.IssuedAt = time.Unix(issued, 0).UTC()
	claims.ExpiresAt = time.Unix(expires, 0).UTC()
	if _, err := marshalClaims(claims); err != nil {
		return Claims{}, fmt.Errorf("invalid endpoint certificate claims: %w", err)
	}
	return claims, nil
}

func appendString(target []byte, value string) []byte {
	target = binary.BigEndian.AppendUint16(target, uint16(len(value)))
	return append(target, value...)
}

func readString(payload []byte, offset *int) (string, error) {
	if len(payload)-*offset < 2 {
		return "", errors.New("truncated string length")
	}
	length := int(binary.BigEndian.Uint16(payload[*offset:]))
	*offset += 2
	if length == 0 || length > 128 || len(payload)-*offset < length {
		return "", errors.New("invalid string length")
	}
	value := string(payload[*offset : *offset+length])
	*offset += length
	return value, nil
}

func cloneClaims(claims Claims) Claims {
	claims.QUICPublicKey = append(ed25519.PublicKey(nil), claims.QUICPublicKey...)
	claims.IssuedAt = claims.IssuedAt.UTC().Truncate(time.Second)
	claims.ExpiresAt = claims.ExpiresAt.UTC().Truncate(time.Second)
	return claims
}

func allZero(value []byte) bool {
	result := byte(0)
	for _, item := range value {
		result |= item
	}
	return subtle.ConstantTimeByteEq(result, 0) == 1
}
