package inbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

type encryptedInboxSecrets struct {
	mu    sync.Mutex
	items map[string]string
}

func (s *encryptedInboxSecrets) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[key] = value
	return nil
}
func (s *encryptedInboxSecrets) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.items[key]
	if !ok {
		return "", errors.New("missing")
	}
	return value, nil
}
func (s *encryptedInboxSecrets) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
	return nil
}

type encryptedInboxKeyPeer struct {
	material transfercrypto.KeyMaterial
	peer     peercontext.Context
}

func (p *encryptedInboxKeyPeer) DeliverTransferKey(context.Context, resolver.ConnectInfo, transfercrypto.KeyControlBinding, transfercrypto.KeyMaterial) (peercontext.Context, error) {
	return peercontext.Context{}, errors.New("unexpected key delivery")
}
func (p *encryptedInboxKeyPeer) ReceiveTransferKey(_ context.Context, _ resolver.ConnectInfo, binding transfercrypto.KeyControlBinding, vault *transfercrypto.KeyVault) (peercontext.Context, error) {
	if err := vault.SaveBound(binding.TransferID, binding.Generation, p.material, binding.ExpiresAt, p.peer); err != nil {
		return peercontext.Context{}, err
	}
	return p.peer, nil
}

type encryptedInboxClient struct {
	material transfercrypto.KeyMaterial
	peer     peercontext.Context
	manifest transfercrypto.Manifest
	content  [][]byte
	receipt  transfercrypto.FinalReceipt
}

func (*encryptedInboxClient) PendingEncrypted(context.Context, string, int) ([]filetransfer.EncryptedPendingBatch, error) {
	return nil, nil
}
func (c *encryptedInboxClient) EncryptedManifest(_ context.Context, batch filetransfer.EncryptedPendingBatch, _ transfercrypto.KeyMaterial, _ transfercrypto.RecordContext) (filetransfer.EncryptedManifest, error) {
	resources := make([]filetransfer.EncryptedResource, len(c.manifest.Files))
	for index, file := range c.manifest.Files {
		resources[index] = filetransfer.EncryptedResource{TransferID: file.TransferID, State: "pending", ExpiresAt: batch.ExpiresAt}
	}
	return filetransfer.EncryptedManifest{Manifest: c.manifest, Resources: resources}, nil
}
func (c *encryptedInboxClient) EncryptedChunk(_ context.Context, resourceID string, ordinal uint64) ([]byte, error) {
	for index, file := range c.manifest.Files {
		if file.TransferID != resourceID {
			continue
		}
		offset := ordinal * transfercrypto.ChunkSize
		if offset > uint64(len(c.content[index])) {
			return nil, errors.New("invalid ordinal")
		}
		end := offset + transfercrypto.ChunkSize
		if end > uint64(len(c.content[index])) {
			end = uint64(len(c.content[index]))
		}
		chunkContext := reverseChunkContext(c.peer, c.manifest.BatchID, 4, uint64(index))
		chunkContext.ChunkOrdinal = ordinal
		chunkContext.Final = ordinal+1 == file.ChunkCount
		return transfercrypto.EncryptChunk(c.material, chunkContext, c.content[index][offset:end])
	}
	return nil, errors.New("unknown resource")
}
func (c *encryptedInboxClient) EncryptedReceipt(_ context.Context, _ string, ciphertext []byte) error {
	receipt, err := transfercrypto.DecryptFinalReceipt(c.material, reverseRecordContext(c.peer, c.manifest.BatchID, 4), ciphertext)
	if err == nil {
		c.receipt = receipt
	}
	return err
}

func TestDeliverEncryptedPublishesVerifiedBatchAndEncryptedCollisionReceipt(t *testing.T) {
	root := t.TempDir()
	if err := EnsurePath(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "report.txt"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	content := [][]byte{[]byte("first private file"), bytes.Repeat([]byte("z"), transfercrypto.ChunkSize+7)}
	manifest := transfercrypto.Manifest{BatchID: "reverse_batch", Files: make([]transfercrypto.ManifestFile, len(content))}
	for index, data := range content {
		digest := sha256.Sum256(data)
		chunks := uint64(len(data)) / transfercrypto.ChunkSize
		if len(data)%transfercrypto.ChunkSize != 0 || chunks == 0 {
			chunks++
		}
		name := []string{"report.txt", "archive.bin"}[index]
		manifest.Files[index] = transfercrypto.ManifestFile{TransferID: "reverse_batch." + strconv.Itoa(index), FileOrdinal: uint64(index), Name: name, RelativeDestination: "Paperboat Inbox/" + name, Mode: 0o600, Size: uint64(len(data)), PlaintextSHA256: digest, ChunkCount: chunks}
	}
	material, _ := transfercrypto.GenerateKeyMaterial()
	defer material.Destroy()
	peer := peercontext.Context{AccountID: "user_1", UserID: "user_1", DeviceID: "cli_1", MachineID: "machine_host", HostGeneration: 2, AuthorizationGeneration: 3, IntentID: "intent_1", OperationID: filetransfer.KeyOperationID(manifest.BatchID), Consumer: "file_transfer_key", InitiatorRole: "controlling", ResponderRole: "controlled", AttemptGeneration: 1}
	peer.InitiatorCertificateHash[0], peer.ResponderCertificateHash[0] = 1, 2
	vault, _ := transfercrypto.NewKeyVault(&encryptedInboxSecrets{items: make(map[string]string)})
	keys, _ := filetransfer.NewKeyCoordinator(vault, &encryptedInboxKeyPeer{material: material, peer: peer})
	encrypted := &encryptedInboxClient{material: material, peer: peer, manifest: manifest, content: content}
	receiver, err := New(Config{Client: &fakeClient{}, Encrypted: encrypted, Keys: keys, Target: resolver.ConnectInfo{Terminal: &resolver.TerminalTarget{}}, MachineID: "machine_client", SessionID: "ses_1", Path: root})
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	batch := filetransfer.EncryptedPendingBatch{TransferID: manifest.BatchID, TransferGeneration: 4, State: "pending", ExpiresAt: expires, Resources: []filetransfer.EncryptedResource{{TransferID: manifest.Files[0].TransferID, State: "pending", ExpiresAt: expires}, {TransferID: manifest.Files[1].TransferID, State: "pending", ExpiresAt: expires}}}
	paths, err := receiver.DeliverEncrypted(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] == "Paperboat Inbox/report.txt" || paths[1] != "Paperboat Inbox/archive.bin" {
		t.Fatalf("paths=%v", paths)
	}
	for index, path := range paths {
		stored, readErr := os.ReadFile(filepath.Join(root, strings.TrimPrefix(path, "Paperboat Inbox/")))
		if readErr != nil || !bytes.Equal(stored, content[index]) {
			t.Fatalf("path=%s content=%d err=%v", path, len(stored), readErr)
		}
	}
	manifestHash, _ := manifest.Hash()
	if encrypted.receipt.ManifestHash != manifestHash || len(encrypted.receipt.Files) != 2 || encrypted.receipt.Files[0].Result != transfercrypto.CollisionRenamed || encrypted.receipt.Files[1].Result != transfercrypto.CollisionOriginal {
		t.Fatalf("receipt=%+v", encrypted.receipt)
	}
	if _, err := vault.Load(manifest.BatchID, 4); !errors.Is(err, transfercrypto.ErrKeyUnavailable) {
		t.Fatalf("recipient key retained after receipt: %v", err)
	}
}
