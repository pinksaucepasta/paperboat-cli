package transfercrypto

import (
	"bytes"
	"testing"
)

func FuzzParseManifest(f *testing.F) {
	valid, err := testManifest().MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("PBMF"))
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, encoded []byte) {
		manifest, err := ParseManifest(encoded)
		if err != nil {
			return
		}
		canonical, err := manifest.MarshalBinary()
		if err != nil {
			t.Fatalf("accepted manifest cannot be encoded: %v", err)
		}
		if !bytes.Equal(canonical, encoded) {
			t.Fatal("accepted manifest is not canonical")
		}
	})
}

func FuzzParseFinalReceipt(f *testing.F) {
	hash, err := testManifest().Hash()
	if err != nil {
		f.Fatal(err)
	}
	valid, err := (FinalReceipt{ManifestHash: hash, Files: []ReceiptFile{{
		FileOrdinal:  1,
		Result:       CollisionOriginal,
		RelativePath: "Paperboat Inbox/file",
	}}}).MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("PBRC"))
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, encoded []byte) {
		receipt, err := ParseFinalReceipt(encoded)
		if err != nil {
			return
		}
		canonical, err := receipt.MarshalBinary()
		if err != nil {
			t.Fatalf("accepted receipt cannot be encoded: %v", err)
		}
		if !bytes.Equal(canonical, encoded) {
			t.Fatal("accepted receipt is not canonical")
		}
	})
}

func FuzzDecryptChunk(f *testing.F) {
	material := testMaterial()
	context := testContext()
	valid, err := EncryptChunk(material, context, []byte("private-file-content"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(nil))
	f.Add(make([]byte, 16))

	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		plaintext, err := DecryptChunk(material, context, ciphertext)
		if err != nil {
			return
		}
		reencrypted, err := EncryptChunk(material, context, plaintext)
		if err != nil {
			t.Fatalf("accepted plaintext cannot be encrypted: %v", err)
		}
		if !bytes.Equal(reencrypted, ciphertext) {
			t.Fatal("accepted ciphertext is not canonical")
		}
	})
}
