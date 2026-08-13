package transfercrypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestChunkRoundTripIsCarrierIndependent(t *testing.T) {
	material := testMaterial()
	context := testContext()
	plaintext := []byte("private-file-content")
	first, err := EncryptChunk(material, context, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncryptChunk(material, context, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || bytes.Contains(first, plaintext) || len(first) != len(plaintext)+16 {
		t.Fatal("ciphertext is not deterministic, opaque, and correctly sized")
	}
	opened, err := DecryptChunk(material, context, first)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened=%q err=%v", opened, err)
	}
}

func TestChunkAuthenticationBindsEveryContextField(t *testing.T) {
	material := testMaterial()
	base := testContext()
	ciphertext, err := EncryptChunk(material, base, []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*ChunkContext){
		func(c *ChunkContext) { c.AccountID = "account_02" },
		func(c *ChunkContext) { c.DeviceID = "cli_02" },
		func(c *ChunkContext) { c.MachineID = "machine_02" },
		func(c *ChunkContext) { c.InitiatorCertificateHash[0]++ },
		func(c *ChunkContext) { c.ResponderCertificateHash[0]++ },
		func(c *ChunkContext) { c.OperationID = "operation_02" },
		func(c *ChunkContext) { c.TransferID = "transfer_02" },
		func(c *ChunkContext) { c.Direction = DirectionFromMachine },
		func(c *ChunkContext) { c.TransferGeneration++ },
		func(c *ChunkContext) { c.FileOrdinal++ },
		func(c *ChunkContext) { c.ChunkOrdinal++ },
		func(c *ChunkContext) { c.Final = !c.Final },
	}
	for index, mutate := range mutations {
		changed := base
		mutate(&changed)
		if _, err := DecryptChunk(material, changed, ciphertext); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("mutation %d err=%v", index, err)
		}
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 1
	if _, err := DecryptChunk(material, base, tampered); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tamper err=%v", err)
	}
}

func TestChunkNonceSeparatesFileAndChunkOrdinals(t *testing.T) {
	material := testMaterial()
	context := testContext()
	plaintext := []byte("same")
	base, _ := EncryptChunk(material, context, plaintext)
	context.FileOrdinal++
	fileCiphertext, _ := EncryptChunk(material, context, plaintext)
	context.FileOrdinal--
	context.ChunkOrdinal++
	chunkCiphertext, _ := EncryptChunk(material, context, plaintext)
	if bytes.Equal(base, fileCiphertext) || bytes.Equal(base, chunkCiphertext) || bytes.Equal(fileCiphertext, chunkCiphertext) {
		t.Fatal("ordinal change reused ciphertext")
	}
}

func TestChunkLimitsAndKeyControlRecord(t *testing.T) {
	material := testMaterial()
	encoded, err := material.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseKeyMaterial(encoded)
	if err != nil || parsed != material {
		t.Fatalf("parsed=%v err=%v", parsed == material, err)
	}
	corrupt := append([]byte(nil), encoded...)
	corrupt[4]++
	if _, err := ParseKeyMaterial(corrupt); !errors.Is(err, ErrInvalid) {
		t.Fatalf("version err=%v", err)
	}
	if _, err := EncryptChunk(material, testContext(), make([]byte, ChunkSize+1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized err=%v", err)
	}
	maximum, err := EncryptChunk(material, testContext(), make([]byte, ChunkSize))
	if err != nil || len(maximum) != ChunkSize+16 {
		t.Fatalf("maximum length=%d err=%v", len(maximum), err)
	}
}

func TestValidateChunkContextRejectsInvalidMaterialAndContext(t *testing.T) {
	material, context := testMaterial(), testContext()
	if err := ValidateChunkContext(material, context); err != nil {
		t.Fatal(err)
	}
	material.Destroy()
	if err := ValidateChunkContext(material, context); !errors.Is(err, ErrInvalid) {
		t.Fatalf("material error=%v", err)
	}
	material, context = testMaterial(), testContext()
	context.TransferGeneration = 0
	if err := ValidateChunkContext(material, context); !errors.Is(err, ErrInvalid) {
		t.Fatalf("context error=%v", err)
	}
}

func testMaterial() KeyMaterial {
	var material KeyMaterial
	copy(material.Key[:], bytes.Repeat([]byte{3}, len(material.Key)))
	copy(material.NoncePrefix[:], bytes.Repeat([]byte{4}, len(material.NoncePrefix)))
	return material
}

func testContext() ChunkContext {
	context := ChunkContext{AccountID: "account_01", DeviceID: "cli_01", MachineID: "machine_01", OperationID: "operation_01", TransferID: "transfer_01", Direction: DirectionToMachine, TransferGeneration: 2, FileOrdinal: 3, ChunkOrdinal: 4, Final: true}
	copy(context.InitiatorCertificateHash[:], bytes.Repeat([]byte{1}, 32))
	copy(context.ResponderCertificateHash[:], bytes.Repeat([]byte{2}, 32))
	return context
}
