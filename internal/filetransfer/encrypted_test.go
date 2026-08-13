package filetransfer

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

func TestEncryptedChunkReaderIsResumableAndOpaque(t *testing.T) {
	content := bytes.Repeat([]byte("paperboat-private-"), 90000)
	source := Source{Basename: "private.bin", Size: int64(len(content)), Reader: bytes.NewReader(content)}
	material := encryptedMaterial()
	context := encryptedContext()
	reader, err := NewEncryptedChunkReader(source, material, context)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	first, final, err := reader.ReadChunk(0)
	if err != nil || final || bytes.Contains(first, content[:64]) {
		t.Fatalf("first final=%v err=%v", final, err)
	}
	resumed, final, err := reader.ReadChunk(1)
	if err != nil || !final {
		t.Fatalf("resumed final=%v err=%v", final, err)
	}
	retry, retryFinal, err := reader.ReadChunk(1)
	if err != nil || !retryFinal || !bytes.Equal(resumed, retry) {
		t.Fatal("retry changed ciphertext")
	}
	if _, _, err := reader.ReadChunk(2); err != io.EOF {
		t.Fatalf("after final err=%v", err)
	}
	firstContext := context
	firstContext.ChunkOrdinal = 0
	firstContext.Final = false
	opened, err := transfercrypto.DecryptChunk(material, firstContext, first)
	if err != nil || !bytes.Equal(opened, content[:transfercrypto.ChunkSize]) {
		t.Fatalf("opened=%d err=%v", len(opened), err)
	}
	secondContext := context
	secondContext.ChunkOrdinal = 1
	secondContext.Final = true
	opened, err = transfercrypto.DecryptChunk(material, secondContext, resumed)
	if err != nil || !bytes.Equal(opened, content[transfercrypto.ChunkSize:]) {
		t.Fatalf("resumed opened=%d err=%v", len(opened), err)
	}
}

func TestEncryptedChunkWriterAuthenticatesBeforeStagingAndCompletesHash(t *testing.T) {
	content := bytes.Repeat([]byte("private"), 200000)
	material := encryptedMaterial()
	context := encryptedContext()
	digest := sha256.Sum256(content)
	expected := transfercrypto.ManifestFile{TransferID: context.TransferID, FileOrdinal: context.FileOrdinal, Name: "private.bin", RelativeDestination: "Paperboat Inbox/private.bin", Mode: 0o600, Size: uint64(len(content)), PlaintextSHA256: digest, ChunkCount: 2}
	source := Source{Basename: expected.Name, Size: int64(len(content)), Reader: bytes.NewReader(content)}
	reader, err := NewEncryptedChunkReader(source, material, context)
	if err != nil {
		t.Fatal(err)
	}
	var staged bytes.Buffer
	writer, err := NewEncryptedChunkWriter(&staged, material, context, expected)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.Complete(); err == nil {
		t.Fatal("incomplete transfer completed")
	}
	for ordinal := uint64(0); ordinal < expected.ChunkCount; ordinal++ {
		chunk, _, err := reader.ReadChunk(ordinal)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.WriteChunk(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Complete(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(staged.Bytes(), content) {
		t.Fatal("staged plaintext mismatch")
	}
}

func TestEncryptedChunkWriterResumesAtAuthenticatedChunkOrdinal(t *testing.T) {
	content := bytes.Repeat([]byte("r"), transfercrypto.ChunkSize+19)
	digest := sha256.Sum256(content)
	material, _ := transfercrypto.GenerateKeyMaterial()
	context := transfercrypto.ChunkContext{AccountID: "account_01", DeviceID: "cli_01", MachineID: "machine_01", OperationID: "operation_01", TransferID: "batch_01", Direction: transfercrypto.DirectionFromMachine, TransferGeneration: 2}
	context.InitiatorCertificateHash[0], context.ResponderCertificateHash[0] = 1, 2
	expected := transfercrypto.ManifestFile{TransferID: "resource_01", Name: "resume.bin", RelativeDestination: "Paperboat Inbox/resume.bin", Mode: 0o600, Size: uint64(len(content)), PlaintextSHA256: digest, ChunkCount: 2}
	reader, err := NewEncryptedChunkReader(Source{Basename: expected.Name, Size: int64(len(content)), SHA256: digest, Reader: bytes.NewReader(content)}, material, context)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := reader.ReadChunk(0)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := transfercrypto.DecryptChunk(material, transfercrypto.ChunkContext{AccountID: context.AccountID, DeviceID: context.DeviceID, MachineID: context.MachineID, InitiatorCertificateHash: context.InitiatorCertificateHash, ResponderCertificateHash: context.ResponderCertificateHash, OperationID: context.OperationID, TransferID: context.TransferID, Direction: context.Direction, TransferGeneration: context.TransferGeneration, ChunkOrdinal: 0}, first)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(t.TempDir(), "resume-*.part")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write(opened); err != nil {
		t.Fatal(err)
	}
	clear(opened)
	writer, ordinal, err := NewResumingEncryptedChunkWriter(file, material, context, expected)
	if err != nil || ordinal != 1 {
		t.Fatalf("ordinal=%d err=%v", ordinal, err)
	}
	second, _, err := reader.ReadChunk(1)
	if err != nil || writer.WriteChunk(second) != nil || writer.Complete() != nil {
		t.Fatalf("resume err=%v", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(file)
	if !bytes.Equal(got, content) {
		t.Fatal("resumed plaintext differs")
	}
}

func TestEncryptedAdaptersEraseInternalKeysOnClose(t *testing.T) {
	material := encryptedMaterial()
	context := encryptedContext()
	reader, err := NewEncryptedChunkReader(Source{Basename: "empty", Reader: bytes.NewReader(nil)}, material, context)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil || reader.material.Valid() {
		t.Fatalf("reader close err=%v valid=%v", err, reader.material.Valid())
	}
	if _, _, err := reader.ReadChunk(0); err == nil {
		t.Fatal("closed reader remained usable")
	}
	digest := sha256.Sum256(nil)
	expected := transfercrypto.ManifestFile{TransferID: context.TransferID, FileOrdinal: context.FileOrdinal, Name: "empty", RelativeDestination: "Paperboat Inbox/empty", Mode: 0o600, PlaintextSHA256: digest, ChunkCount: 1}
	writer, err := NewEncryptedChunkWriter(io.Discard, material, context, expected)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil || writer.material.Valid() {
		t.Fatalf("writer close err=%v valid=%v", err, writer.material.Valid())
	}
	if err := writer.WriteChunk(nil); err == nil {
		t.Fatal("closed writer remained usable")
	}
}

func TestEncryptedChunkWriterPoisonsBeforeWritingTamperedChunk(t *testing.T) {
	content := []byte("private")
	material := encryptedMaterial()
	context := encryptedContext()
	digest := sha256.Sum256(content)
	expected := transfercrypto.ManifestFile{TransferID: context.TransferID, FileOrdinal: context.FileOrdinal, Name: "private.bin", RelativeDestination: "Paperboat Inbox/private.bin", Mode: 0o600, Size: uint64(len(content)), PlaintextSHA256: digest, ChunkCount: 1}
	reader, _ := NewEncryptedChunkReader(Source{Basename: expected.Name, Size: int64(len(content)), Reader: bytes.NewReader(content)}, material, context)
	chunk, _, _ := reader.ReadChunk(0)
	chunk[len(chunk)-1] ^= 1
	var staged bytes.Buffer
	writer, _ := NewEncryptedChunkWriter(&staged, material, context, expected)
	if err := writer.WriteChunk(chunk); !errors.Is(err, transfercrypto.ErrAuthentication) {
		t.Fatalf("tamper err=%v", err)
	}
	if staged.Len() != 0 {
		t.Fatal("tampered plaintext reached staging writer")
	}
	if err := writer.WriteChunk(chunk); err == nil {
		t.Fatal("poisoned writer accepted another chunk")
	}
}

func TestEncryptedAdaptersRejectMalformedOwnershipAtConstruction(t *testing.T) {
	material := encryptedMaterial()
	context := encryptedContext()
	digest := sha256.Sum256(nil)
	expected := transfercrypto.ManifestFile{TransferID: context.TransferID, FileOrdinal: context.FileOrdinal, Name: "empty", RelativeDestination: "Paperboat Inbox/empty", Mode: 0o600, PlaintextSHA256: digest, ChunkCount: 1}
	invalidMaterial := material
	invalidMaterial.Destroy()
	invalidContext := context
	invalidContext.ChunkOrdinal = 1

	for name, input := range map[string]struct {
		material transfercrypto.KeyMaterial
		context  transfercrypto.ChunkContext
	}{
		"material": {material: invalidMaterial, context: context},
		"ordinal":  {material: material, context: invalidContext},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewEncryptedChunkReader(Source{Basename: "empty", Reader: bytes.NewReader(nil)}, input.material, input.context); err == nil {
				t.Fatal("reader accepted malformed ownership")
			}
			if _, err := NewEncryptedChunkWriter(io.Discard, input.material, input.context, expected); err == nil {
				t.Fatal("writer accepted malformed ownership")
			}
		})
	}
}

func encryptedMaterial() transfercrypto.KeyMaterial {
	var material transfercrypto.KeyMaterial
	copy(material.Key[:], bytes.Repeat([]byte{7}, len(material.Key)))
	copy(material.NoncePrefix[:], bytes.Repeat([]byte{8}, len(material.NoncePrefix)))
	return material
}

func encryptedContext() transfercrypto.ChunkContext {
	context := transfercrypto.ChunkContext{AccountID: "account_01", DeviceID: "cli_01", MachineID: "machine_01", OperationID: "operation_01", TransferID: "transfer_01", Direction: transfercrypto.DirectionToMachine, TransferGeneration: 1}
	copy(context.InitiatorCertificateHash[:], bytes.Repeat([]byte{1}, 32))
	copy(context.ResponderCertificateHash[:], bytes.Repeat([]byte{2}, 32))
	return context
}
