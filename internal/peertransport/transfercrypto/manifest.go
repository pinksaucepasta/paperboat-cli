package transfercrypto

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"unicode/utf8"
)

const (
	maxFilenameBytes = 255
	maxPathBytes     = 4096
	maxManifestFiles = 65535
)

type Manifest struct {
	BatchID string
	Files   []ManifestFile
}

type ManifestFile struct {
	TransferID          string
	FileOrdinal         uint64
	Name                string
	RelativeDestination string
	Mode                uint32
	Size                uint64
	PlaintextSHA256     [sha256.Size]byte
	ChunkCount          uint64
}

func (m Manifest) MarshalBinary() ([]byte, error) {
	if !identifierPattern.MatchString(m.BatchID) || len(m.Files) == 0 || len(m.Files) > maxManifestFiles {
		return nil, ErrInvalid
	}
	encoded := []byte{'P', 'B', 'M', 'F', ProtocolVersion}
	encoded = appendString(encoded, m.BatchID)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(m.Files)))
	seenTransfers := make(map[string]struct{}, len(m.Files))
	seenOrdinals := make(map[uint64]struct{}, len(m.Files))
	for _, file := range m.Files {
		if err := validateManifestFile(file); err != nil {
			return nil, err
		}
		if _, exists := seenTransfers[file.TransferID]; exists {
			return nil, ErrInvalid
		}
		if _, exists := seenOrdinals[file.FileOrdinal]; exists {
			return nil, ErrInvalid
		}
		seenTransfers[file.TransferID] = struct{}{}
		seenOrdinals[file.FileOrdinal] = struct{}{}
		encoded = appendString(encoded, file.TransferID)
		encoded = binary.BigEndian.AppendUint64(encoded, file.FileOrdinal)
		encoded = appendString(encoded, file.Name)
		encoded = appendString(encoded, file.RelativeDestination)
		encoded = binary.BigEndian.AppendUint32(encoded, file.Mode)
		encoded = binary.BigEndian.AppendUint64(encoded, file.Size)
		encoded = append(encoded, file.PlaintextSHA256[:]...)
		encoded = binary.BigEndian.AppendUint64(encoded, file.ChunkCount)
	}
	if len(encoded) > ChunkSize {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func ParseManifest(encoded []byte) (Manifest, error) {
	if len(encoded) == 0 || len(encoded) > ChunkSize {
		return Manifest{}, ErrInvalid
	}
	decoder := binaryDecoder{value: encoded}
	if !decoder.magic("PBMF") || decoder.byte() != ProtocolVersion {
		return Manifest{}, ErrInvalid
	}
	manifest := Manifest{BatchID: decoder.string(maxPathBytes)}
	count := int(decoder.uint16())
	if decoder.err != nil || !identifierPattern.MatchString(manifest.BatchID) || count == 0 {
		return Manifest{}, ErrInvalid
	}
	manifest.Files = make([]ManifestFile, count)
	for index := range manifest.Files {
		file := &manifest.Files[index]
		file.TransferID = decoder.string(128)
		file.FileOrdinal = decoder.uint64()
		file.Name = decoder.string(maxFilenameBytes)
		file.RelativeDestination = decoder.string(maxPathBytes)
		file.Mode = decoder.uint32()
		file.Size = decoder.uint64()
		decoder.copy(file.PlaintextSHA256[:])
		file.ChunkCount = decoder.uint64()
	}
	if decoder.err != nil || !decoder.done() {
		return Manifest{}, ErrInvalid
	}
	canonical, err := manifest.MarshalBinary()
	if err != nil || !equalBytes(canonical, encoded) {
		return Manifest{}, ErrInvalid
	}
	return manifest, nil
}

func (m Manifest) Hash() ([sha256.Size]byte, error) {
	encoded, err := m.MarshalBinary()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func validateManifestFile(file ManifestFile) error {
	if !identifierPattern.MatchString(file.TransferID) || file.FileOrdinal == recordFileOrdinal || !validFilename(file.Name) || !validRelativePath(file.RelativeDestination) || file.Mode&^uint32(0o777) != 0 || allZero(file.PlaintextSHA256[:]) {
		return ErrInvalid
	}
	wantChunks := file.Size / ChunkSize
	if file.Size%ChunkSize != 0 {
		wantChunks++
	}
	if wantChunks == 0 {
		wantChunks = 1
	}
	if file.ChunkCount != wantChunks {
		return ErrInvalid
	}
	return nil
}

func ValidateManifestFile(file ManifestFile) error { return validateManifestFile(file) }

type CollisionResult uint8

const (
	CollisionOriginal CollisionResult = iota + 1
	CollisionRenamed
	CollisionRejected
)

type FinalReceipt struct {
	ManifestHash [sha256.Size]byte
	Files        []ReceiptFile
}

type ReceiptFile struct {
	FileOrdinal  uint64
	Result       CollisionResult
	RelativePath string
}

func EncryptManifest(material KeyMaterial, context RecordContext, manifest Manifest) ([]byte, error) {
	plaintext, err := manifest.MarshalBinary()
	if err != nil {
		return nil, err
	}
	context.Type = RecordFinalManifest
	context.Ordinal = 0
	return EncryptRecord(material, context, plaintext)
}

func DecryptManifest(material KeyMaterial, context RecordContext, ciphertext []byte) (Manifest, error) {
	context.Type = RecordFinalManifest
	context.Ordinal = 0
	plaintext, err := DecryptRecord(material, context, ciphertext)
	if err != nil {
		return Manifest{}, err
	}
	return ParseManifest(plaintext)
}

func EncryptFinalReceipt(material KeyMaterial, context RecordContext, receipt FinalReceipt) ([]byte, error) {
	plaintext, err := receipt.MarshalBinary()
	if err != nil {
		return nil, err
	}
	context.Type = RecordFinalReceipt
	context.Ordinal = 0
	return EncryptRecord(material, context, plaintext)
}

func DecryptFinalReceipt(material KeyMaterial, context RecordContext, ciphertext []byte) (FinalReceipt, error) {
	context.Type = RecordFinalReceipt
	context.Ordinal = 0
	plaintext, err := DecryptRecord(material, context, ciphertext)
	if err != nil {
		return FinalReceipt{}, err
	}
	return ParseFinalReceipt(plaintext)
}

func (r FinalReceipt) MarshalBinary() ([]byte, error) {
	if allZero(r.ManifestHash[:]) || len(r.Files) == 0 || len(r.Files) > maxManifestFiles {
		return nil, ErrInvalid
	}
	encoded := []byte{'P', 'B', 'R', 'C', ProtocolVersion}
	encoded = append(encoded, r.ManifestHash[:]...)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(r.Files)))
	seen := make(map[uint64]struct{}, len(r.Files))
	for _, file := range r.Files {
		if file.FileOrdinal == recordFileOrdinal || !validReceiptFile(file) {
			return nil, ErrInvalid
		}
		if _, exists := seen[file.FileOrdinal]; exists {
			return nil, ErrInvalid
		}
		seen[file.FileOrdinal] = struct{}{}
		encoded = binary.BigEndian.AppendUint64(encoded, file.FileOrdinal)
		encoded = append(encoded, byte(file.Result))
		encoded = appendString(encoded, file.RelativePath)
	}
	if len(encoded) > ChunkSize {
		return nil, ErrInvalid
	}
	return encoded, nil
}

func ParseFinalReceipt(encoded []byte) (FinalReceipt, error) {
	if len(encoded) == 0 || len(encoded) > ChunkSize {
		return FinalReceipt{}, ErrInvalid
	}
	decoder := binaryDecoder{value: encoded}
	if !decoder.magic("PBRC") || decoder.byte() != ProtocolVersion {
		return FinalReceipt{}, ErrInvalid
	}
	var receipt FinalReceipt
	decoder.copy(receipt.ManifestHash[:])
	count := int(decoder.uint16())
	if decoder.err != nil || count == 0 {
		return FinalReceipt{}, ErrInvalid
	}
	receipt.Files = make([]ReceiptFile, count)
	for index := range receipt.Files {
		receipt.Files[index] = ReceiptFile{FileOrdinal: decoder.uint64(), Result: CollisionResult(decoder.byte()), RelativePath: decoder.string(maxPathBytes)}
	}
	if decoder.err != nil || !decoder.done() {
		return FinalReceipt{}, ErrInvalid
	}
	canonical, err := receipt.MarshalBinary()
	if err != nil || !equalBytes(canonical, encoded) {
		return FinalReceipt{}, ErrInvalid
	}
	return receipt, nil
}

func validCollision(value CollisionResult) bool {
	return value >= CollisionOriginal && value <= CollisionRejected
}

func validReceiptFile(file ReceiptFile) bool {
	if !validCollision(file.Result) {
		return false
	}
	if file.Result == CollisionRejected {
		return file.RelativePath == ""
	}
	return validRelativePath(file.RelativePath)
}

func validFilename(value string) bool {
	return len(value) > 0 && len(value) <= maxFilenameBytes && utf8.ValidString(value) && value != "." && value != ".." && !strings.ContainsAny(value, "/\\\x00")
}

func validRelativePath(value string) bool {
	if len(value) == 0 || len(value) > maxPathBytes || !utf8.ValidString(value) || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\\x00") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

type binaryDecoder struct {
	value  []byte
	offset int
	err    error
}

func (d *binaryDecoder) take(size int) []byte {
	if d.err != nil || size < 0 || d.offset > len(d.value)-size {
		d.err = ErrInvalid
		return nil
	}
	result := d.value[d.offset : d.offset+size]
	d.offset += size
	return result
}

func (d *binaryDecoder) magic(value string) bool { return string(d.take(len(value))) == value }
func (d *binaryDecoder) byte() byte {
	value := d.take(1)
	if len(value) != 1 {
		return 0
	}
	return value[0]
}
func (d *binaryDecoder) uint16() uint16 { return binary.BigEndian.Uint16(pad(d.take(2), 2)) }
func (d *binaryDecoder) uint32() uint32 { return binary.BigEndian.Uint32(pad(d.take(4), 4)) }
func (d *binaryDecoder) uint64() uint64 { return binary.BigEndian.Uint64(pad(d.take(8), 8)) }
func (d *binaryDecoder) string(maximum int) string {
	length := int(d.uint16())
	if length > maximum {
		d.err = ErrInvalid
		return ""
	}
	return string(d.take(length))
}
func (d *binaryDecoder) copy(target []byte) { copy(target, d.take(len(target))) }
func (d *binaryDecoder) done() bool         { return d.err == nil && d.offset == len(d.value) }

func pad(value []byte, size int) []byte {
	if len(value) == size {
		return value
	}
	return make([]byte, size)
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}
