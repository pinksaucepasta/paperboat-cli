package transfercrypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncryptedRecordTypesUseDisjointNonces(t *testing.T) {
	material := testMaterial()
	context := testRecordContext()
	plaintext := []byte("private manifest or receipt")
	seen := make(map[string]RecordType)
	for recordType := RecordBatchManifest; recordType <= RecordFinalReceipt; recordType++ {
		context.Type = recordType
		ciphertext, err := EncryptRecord(material, context, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if prior, exists := seen[string(ciphertext)]; exists {
			t.Fatalf("record types %d and %d reused ciphertext", prior, recordType)
		}
		seen[string(ciphertext)] = recordType
		opened, err := DecryptRecord(material, context, ciphertext)
		if err != nil || !bytes.Equal(opened, plaintext) {
			t.Fatalf("type=%d opened=%q err=%v", recordType, opened, err)
		}
	}
}

func TestEncryptedRecordBindsTypeOrdinalAndTransferContext(t *testing.T) {
	material := testMaterial()
	base := testRecordContext()
	ciphertext, err := EncryptRecord(material, base, []byte("private manifest"))
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*RecordContext){
		func(c *RecordContext) { c.AccountID = "account_02" },
		func(c *RecordContext) { c.DeviceID = "cli_02" },
		func(c *RecordContext) { c.MachineID = "machine_02" },
		func(c *RecordContext) { c.InitiatorCertificateHash[0]++ },
		func(c *RecordContext) { c.ResponderCertificateHash[0]++ },
		func(c *RecordContext) { c.OperationID = "operation_02" },
		func(c *RecordContext) { c.TransferID = "transfer_02" },
		func(c *RecordContext) { c.Direction = DirectionFromMachine },
		func(c *RecordContext) { c.TransferGeneration++ },
		func(c *RecordContext) { c.Type = RecordFinalReceipt },
		func(c *RecordContext) { c.Ordinal++ },
	}
	for index, mutate := range mutations {
		changed := base
		mutate(&changed)
		if _, err := DecryptRecord(material, changed, ciphertext); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("mutation %d err=%v", index, err)
		}
	}
}

func TestReservedRecordOrdinalCannotEncryptFileContent(t *testing.T) {
	chunk := testContext()
	chunk.FileOrdinal = recordFileOrdinal
	if _, err := EncryptChunk(testMaterial(), chunk, []byte("private")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reserved file ordinal err=%v", err)
	}
	record := testRecordContext()
	record.Ordinal = maxRecordOrdinal + 1
	if _, err := EncryptRecord(testMaterial(), record, []byte("private")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized record ordinal err=%v", err)
	}
	record.Ordinal = 0
	record.Type = 0
	if _, err := EncryptRecord(testMaterial(), record, []byte("private")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid record type err=%v", err)
	}
}

func testRecordContext() RecordContext {
	chunk := testContext()
	return RecordContext{
		AccountID:                chunk.AccountID,
		DeviceID:                 chunk.DeviceID,
		MachineID:                chunk.MachineID,
		InitiatorCertificateHash: chunk.InitiatorCertificateHash,
		ResponderCertificateHash: chunk.ResponderCertificateHash,
		OperationID:              chunk.OperationID,
		TransferID:               chunk.TransferID,
		Direction:                chunk.Direction,
		TransferGeneration:       chunk.TransferGeneration,
		Type:                     RecordFileManifest,
		Ordinal:                  7,
	}
}
