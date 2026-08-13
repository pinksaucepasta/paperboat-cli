package transfercrypto

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
)

func TestManifestCanonicalRoundTripAndHash(t *testing.T) {
	manifest := testManifest()
	encoded, err := manifest.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseManifest(encoded)
	if err != nil || !reflect.DeepEqual(parsed, manifest) {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
	}
	first, err := manifest.Hash()
	if err != nil {
		t.Fatal(err)
	}
	second := sha256.Sum256(encoded)
	if first != second {
		t.Fatal("manifest hash is not canonical encoding hash")
	}
	trailing := append(append([]byte(nil), encoded...), 0)
	if _, err := ParseManifest(trailing); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing data err=%v", err)
	}
}

func TestManifestValidationRejectsUnsafeOrMutableLayout(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"traversal": func(m *Manifest) { m.Files[0].RelativeDestination = "../secret" },
		"separator": func(m *Manifest) { m.Files[0].Name = "dir/file" },
		"mode":      func(m *Manifest) { m.Files[0].Mode = 0o1000 },
		"chunks":    func(m *Manifest) { m.Files[0].ChunkCount++ },
		"hash":      func(m *Manifest) { m.Files[0].PlaintextSHA256 = [32]byte{} },
		"transfer":  func(m *Manifest) { m.Files[1].TransferID = m.Files[0].TransferID },
		"ordinal":   func(m *Manifest) { m.Files[1].FileOrdinal = m.Files[0].FileOrdinal },
	} {
		t.Run(name, func(t *testing.T) {
			manifest := testManifest()
			mutate(&manifest)
			if _, err := manifest.MarshalBinary(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestManifestAndReceiptEncryptionAreOpaqueAndTyped(t *testing.T) {
	material := testMaterial()
	context := testRecordContext()
	manifest := testManifest()
	manifestCiphertext, err := EncryptManifest(material, context, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(manifestCiphertext, []byte(manifest.Files[0].Name)) {
		t.Fatal("manifest filename visible in ciphertext")
	}
	openedManifest, err := DecryptManifest(material, context, manifestCiphertext)
	if err != nil || !reflect.DeepEqual(openedManifest, manifest) {
		t.Fatalf("manifest=%+v err=%v", openedManifest, err)
	}
	hash, _ := manifest.Hash()
	receipt := FinalReceipt{ManifestHash: hash, Files: []ReceiptFile{{FileOrdinal: 0, Result: CollisionOriginal, RelativePath: "Paperboat Inbox/empty"}, {FileOrdinal: 1, Result: CollisionRenamed, RelativePath: "Paperboat Inbox/résumé 最終 (1).bin"}}}
	receiptCiphertext, err := EncryptFinalReceipt(material, context, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(receiptCiphertext, []byte("Paperboat Inbox")) || bytes.Equal(receiptCiphertext, manifestCiphertext) {
		t.Fatal("receipt is visible or not type-separated")
	}
	openedReceipt, err := DecryptFinalReceipt(material, context, receiptCiphertext)
	if err != nil || !reflect.DeepEqual(openedReceipt, receipt) {
		t.Fatalf("receipt=%+v err=%v", openedReceipt, err)
	}
	wrong := context
	wrong.TransferGeneration++
	if _, err := DecryptManifest(material, wrong, manifestCiphertext); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong context err=%v", err)
	}
	if _, err := DecryptManifest(material, context, receiptCiphertext); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("record substitution err=%v", err)
	}
}

func TestFinalReceiptRejectsInvalidCollisionAndPaths(t *testing.T) {
	manifest := testManifest()
	hash, _ := manifest.Hash()
	base := FinalReceipt{ManifestHash: hash, Files: []ReceiptFile{{FileOrdinal: 0, Result: CollisionOriginal, RelativePath: "Paperboat Inbox/file"}}}
	for name, mutate := range map[string]func(*FinalReceipt){
		"collision": func(r *FinalReceipt) { r.Files[0].Result = 0 },
		"absolute":  func(r *FinalReceipt) { r.Files[0].RelativePath = "/tmp/file" },
		"traversal": func(r *FinalReceipt) { r.Files[0].RelativePath = "Inbox/../file" },
		"hash":      func(r *FinalReceipt) { r.ManifestHash = [32]byte{} },
	} {
		t.Run(name, func(t *testing.T) {
			receipt := base
			receipt.Files = append([]ReceiptFile(nil), base.Files...)
			mutate(&receipt)
			if _, err := receipt.MarshalBinary(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	rejected := FinalReceipt{ManifestHash: hash, Files: []ReceiptFile{{FileOrdinal: 0, Result: CollisionRejected}}}
	encoded, err := rejected.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseFinalReceipt(encoded); err != nil || !reflect.DeepEqual(parsed, rejected) {
		t.Fatalf("rejected=%+v err=%v", parsed, err)
	}
	rejected.Files[0].RelativePath = "must/not/exist"
	if _, err := rejected.MarshalBinary(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rejected path err=%v", err)
	}
}

func testManifest() Manifest {
	emptyHash := sha256.Sum256(nil)
	fullHash := sha256.Sum256([]byte("content"))
	return Manifest{BatchID: "batch_01", Files: []ManifestFile{
		{TransferID: "transfer_01", FileOrdinal: 0, Name: "empty", RelativeDestination: "Paperboat Inbox/empty", Mode: 0o600, Size: 0, PlaintextSHA256: emptyHash, ChunkCount: 1},
		{TransferID: "transfer_02", FileOrdinal: 1, Name: "résumé 最終.bin", RelativeDestination: "Paperboat Inbox/résumé 最終.bin", Mode: 0o640, Size: uint64(len("content")), PlaintextSHA256: fullHash, ChunkCount: 1},
	}}
}
