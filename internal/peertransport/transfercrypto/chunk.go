// Package transfercrypto owns the carrier-independent encrypted file-transfer
// representation used by direct QUIC and relay HTTP.
package transfercrypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"regexp"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ProtocolVersion   = 1
	ChunkSize         = 1 << 20
	keyRecordSize     = 45
	recordFileOrdinal = ^uint64(0)
)

var (
	ErrAuthentication = errors.New("file-transfer E2EE authentication failed")
	ErrInvalid        = errors.New("invalid file-transfer encryption input")
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
)

type Direction uint8

const (
	DirectionToMachine Direction = iota + 1
	DirectionFromMachine
)

type KeyMaterial struct {
	Key         [chacha20poly1305.KeySize]byte
	NoncePrefix [8]byte
}

func GenerateKeyMaterial() (KeyMaterial, error) {
	return generateKeyMaterial(rand.Reader)
}

func generateKeyMaterial(source io.Reader) (KeyMaterial, error) {
	var material KeyMaterial
	if _, err := io.ReadFull(source, material.Key[:]); err != nil {
		return KeyMaterial{}, fmt.Errorf("generate transfer content key: %w", err)
	}
	if _, err := io.ReadFull(source, material.NoncePrefix[:]); err != nil {
		clear(material.Key[:])
		clear(material.NoncePrefix[:])
		return KeyMaterial{}, fmt.Errorf("generate transfer nonce prefix: %w", err)
	}
	if allZero(material.Key[:]) || allZero(material.NoncePrefix[:]) {
		clear(material.Key[:])
		clear(material.NoncePrefix[:])
		return KeyMaterial{}, ErrInvalid
	}
	return material, nil
}

func (k *KeyMaterial) Destroy() {
	if k == nil {
		return
	}
	clear(k.Key[:])
	clear(k.NoncePrefix[:])
}

func (k KeyMaterial) Valid() bool { return !allZero(k.Key[:]) && !allZero(k.NoncePrefix[:]) }

// MarshalBinary encodes the bounded file_transfer_key control payload. This
// record must itself be carried only inside direct TLS or relay Noise E2EE.
func (k KeyMaterial) MarshalBinary() ([]byte, error) {
	if allZero(k.Key[:]) || allZero(k.NoncePrefix[:]) {
		return nil, ErrInvalid
	}
	result := make([]byte, keyRecordSize)
	copy(result, []byte{'P', 'B', 'T', 'K'})
	result[4] = ProtocolVersion
	copy(result[5:37], k.Key[:])
	copy(result[37:45], k.NoncePrefix[:])
	return result, nil
}

func ParseKeyMaterial(value []byte) (KeyMaterial, error) {
	var material KeyMaterial
	if len(value) != keyRecordSize || string(value[:4]) != "PBTK" || value[4] != ProtocolVersion {
		return material, ErrInvalid
	}
	copy(material.Key[:], value[5:37])
	copy(material.NoncePrefix[:], value[37:45])
	if allZero(material.Key[:]) || allZero(material.NoncePrefix[:]) {
		clear(material.Key[:])
		clear(material.NoncePrefix[:])
		return KeyMaterial{}, ErrInvalid
	}
	return material, nil
}

type ChunkContext struct {
	AccountID                string
	DeviceID                 string
	MachineID                string
	InitiatorCertificateHash [32]byte
	ResponderCertificateHash [32]byte
	OperationID              string
	TransferID               string
	Direction                Direction
	TransferGeneration       uint64
	FileOrdinal              uint64
	ChunkOrdinal             uint64
	Final                    bool
}

func ValidateChunkContext(material KeyMaterial, context ChunkContext) error {
	if !material.Valid() {
		return ErrInvalid
	}
	_, err := context.additionalData(0)
	return err
}

func EncryptChunk(material KeyMaterial, context ChunkContext, plaintext []byte) ([]byte, error) {
	if len(plaintext) > ChunkSize {
		return nil, ErrInvalid
	}
	aead, nonce, additionalData, err := prepare(material, context, len(plaintext))
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce[:], plaintext, additionalData), nil
}

func DecryptChunk(material KeyMaterial, context ChunkContext, ciphertext []byte) ([]byte, error) {
	plaintextLength := len(ciphertext) - chacha20poly1305.Overhead
	if plaintextLength < 0 || plaintextLength > ChunkSize {
		return nil, ErrInvalid
	}
	aead, nonce, additionalData, err := prepare(material, context, plaintextLength)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, additionalData)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func prepare(material KeyMaterial, context ChunkContext, plaintextLength int) (cipher.AEAD, [chacha20poly1305.NonceSizeX]byte, []byte, error) {
	var nonce [chacha20poly1305.NonceSizeX]byte
	if allZero(material.Key[:]) || allZero(material.NoncePrefix[:]) {
		return nil, nonce, nil, ErrInvalid
	}
	additionalData, err := context.additionalData(plaintextLength)
	if err != nil {
		return nil, nonce, nil, err
	}
	aead, err := chacha20poly1305.NewX(material.Key[:])
	if err != nil {
		return nil, nonce, nil, fmt.Errorf("create transfer cipher: %w", err)
	}
	copy(nonce[:8], material.NoncePrefix[:])
	binary.BigEndian.PutUint64(nonce[8:16], context.FileOrdinal)
	binary.BigEndian.PutUint64(nonce[16:24], context.ChunkOrdinal)
	return aead, nonce, additionalData, nil
}

func (c ChunkContext) additionalData(plaintextLength int) ([]byte, error) {
	identifiers := []string{c.AccountID, c.DeviceID, c.MachineID, c.OperationID, c.TransferID}
	for _, value := range identifiers {
		if !identifierPattern.MatchString(value) {
			return nil, ErrInvalid
		}
	}
	if c.Direction != DirectionToMachine && c.Direction != DirectionFromMachine || c.TransferGeneration == 0 || c.FileOrdinal == recordFileOrdinal || allZero(c.InitiatorCertificateHash[:]) || allZero(c.ResponderCertificateHash[:]) || plaintextLength < 0 || plaintextLength > ChunkSize {
		return nil, ErrInvalid
	}
	encoded := []byte{'P', 'B', 'T', 'C', ProtocolVersion}
	for _, value := range identifiers[:3] {
		encoded = appendString(encoded, value)
	}
	encoded = append(encoded, c.InitiatorCertificateHash[:]...)
	encoded = append(encoded, c.ResponderCertificateHash[:]...)
	for _, value := range identifiers[3:] {
		encoded = appendString(encoded, value)
	}
	encoded = append(encoded, byte(c.Direction))
	encoded = binary.BigEndian.AppendUint64(encoded, c.TransferGeneration)
	encoded = binary.BigEndian.AppendUint64(encoded, c.FileOrdinal)
	encoded = binary.BigEndian.AppendUint64(encoded, c.ChunkOrdinal)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(plaintextLength))
	if c.Final {
		encoded = append(encoded, 1)
	} else {
		encoded = append(encoded, 0)
	}
	return encoded, nil
}

func appendString(target []byte, value string) []byte {
	target = binary.BigEndian.AppendUint16(target, uint16(len(value)))
	return append(target, value...)
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
