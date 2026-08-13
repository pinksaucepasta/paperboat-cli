package transfercrypto

import (
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

const maxRecordOrdinal = uint64(1<<56) - 1

type RecordType uint8

const (
	RecordBatchManifest RecordType = iota + 1
	RecordFileManifest
	RecordFinalManifest
	RecordFinalReceipt
)

type RecordContext struct {
	AccountID                string
	DeviceID                 string
	MachineID                string
	InitiatorCertificateHash [32]byte
	ResponderCertificateHash [32]byte
	OperationID              string
	TransferID               string
	Direction                Direction
	TransferGeneration       uint64
	Type                     RecordType
	Ordinal                  uint64
}

func EncryptRecord(material KeyMaterial, context RecordContext, plaintext []byte) ([]byte, error) {
	if len(plaintext) > ChunkSize {
		return nil, ErrInvalid
	}
	aead, nonce, additionalData, err := prepareRecord(material, context, len(plaintext))
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce[:], plaintext, additionalData), nil
}

func DecryptRecord(material KeyMaterial, context RecordContext, ciphertext []byte) ([]byte, error) {
	plaintextLength := len(ciphertext) - chacha20poly1305.Overhead
	if plaintextLength < 0 || plaintextLength > ChunkSize {
		return nil, ErrInvalid
	}
	aead, nonce, additionalData, err := prepareRecord(material, context, plaintextLength)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, additionalData)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func prepareRecord(material KeyMaterial, context RecordContext, plaintextLength int) (cipher.AEAD, [chacha20poly1305.NonceSizeX]byte, []byte, error) {
	var nonce [chacha20poly1305.NonceSizeX]byte
	additionalData, err := context.additionalData(plaintextLength)
	if err != nil || allZero(material.Key[:]) || allZero(material.NoncePrefix[:]) {
		return nil, nonce, nil, ErrInvalid
	}
	aead, err := chacha20poly1305.NewX(material.Key[:])
	if err != nil {
		return nil, nonce, nil, ErrInvalid
	}
	copy(nonce[:8], material.NoncePrefix[:])
	binary.BigEndian.PutUint64(nonce[8:16], recordFileOrdinal)
	binary.BigEndian.PutUint64(nonce[16:24], uint64(context.Type)<<56|context.Ordinal)
	return aead, nonce, additionalData, nil
}

func (c RecordContext) additionalData(plaintextLength int) ([]byte, error) {
	identifiers := []string{c.AccountID, c.DeviceID, c.MachineID, c.OperationID, c.TransferID}
	for _, value := range identifiers {
		if !identifierPattern.MatchString(value) {
			return nil, ErrInvalid
		}
	}
	if c.Direction != DirectionToMachine && c.Direction != DirectionFromMachine || c.TransferGeneration == 0 || !validRecordType(c.Type) || c.Ordinal > maxRecordOrdinal || allZero(c.InitiatorCertificateHash[:]) || allZero(c.ResponderCertificateHash[:]) || plaintextLength < 0 || plaintextLength > ChunkSize {
		return nil, ErrInvalid
	}
	encoded := []byte{'P', 'B', 'T', 'R', ProtocolVersion}
	for _, value := range identifiers[:3] {
		encoded = appendString(encoded, value)
	}
	encoded = append(encoded, c.InitiatorCertificateHash[:]...)
	encoded = append(encoded, c.ResponderCertificateHash[:]...)
	for _, value := range identifiers[3:] {
		encoded = appendString(encoded, value)
	}
	encoded = append(encoded, byte(c.Direction), byte(c.Type))
	encoded = binary.BigEndian.AppendUint64(encoded, c.TransferGeneration)
	encoded = binary.BigEndian.AppendUint64(encoded, c.Ordinal)
	return binary.BigEndian.AppendUint32(encoded, uint32(plaintextLength)), nil
}

func validRecordType(value RecordType) bool {
	return value >= RecordBatchManifest && value <= RecordFinalReceipt
}
