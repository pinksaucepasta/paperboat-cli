package filetransfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

type uploaderDeleteFailStore struct {
	keyMemoryStore
	deleteErr   error
	deleteCalls atomic.Int32
}

func (s *uploaderDeleteFailStore) Delete(key string) error {
	s.deleteCalls.Add(1)
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.keyMemoryStore.Delete(key)
}

func TestEncryptedUploaderPreservesAcknowledgedDeliveryWhenSenderKeyCleanupFails(t *testing.T) {
	const batchID = "fb_cleanup_warning"
	const resourceID = batchID + ".0"
	content := []byte("delivered once")
	contentDigest := sha256.Sum256(content)
	peer := keyContext(KeyOperationID(batchID))
	var deliveredMaterial transfercrypto.KeyMaterial
	var createCalls atomic.Int32
	var receiptCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/":
			createCalls.Add(1)
			writeUploaderJSON(writer, http.StatusCreated, encryptedCreateResult{BatchID: batchID, Resources: []encryptedResource{{TransferID: resourceID, State: "created"}}})
		case request.Method == http.MethodGet && request.URL.Path == "/"+resourceID:
			writeUploaderJSON(writer, http.StatusOK, encryptedResource{TransferID: resourceID, State: "uploading"})
		case request.Method == http.MethodPut && request.URL.Path == "/"+resourceID+"/chunks/0":
			_, _ = io.Copy(io.Discard, request.Body)
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPost && request.URL.Path == "/"+resourceID+"/complete":
			manifest := transfercrypto.Manifest{BatchID: batchID, Files: []transfercrypto.ManifestFile{{
				TransferID: resourceID, FileOrdinal: 0, Name: "payload.txt", RelativeDestination: "Paperboat Inbox/payload.txt",
				Mode: 0o600, Size: uint64(len(content)), PlaintextSHA256: contentDigest, ChunkCount: 1,
			}}}
			manifestHash, err := manifest.Hash()
			if err != nil {
				t.Error(err)
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			receipt := transfercrypto.FinalReceipt{ManifestHash: manifestHash, Files: []transfercrypto.ReceiptFile{{FileOrdinal: 0, Result: transfercrypto.CollisionOriginal, RelativePath: "Paperboat Inbox/payload.txt"}}}
			ciphertext, err := transfercrypto.EncryptFinalReceipt(deliveredMaterial, recordContextFromPeer(peer, batchID, 1), receipt)
			if err != nil {
				t.Error(err)
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			digest := sha256.Sum256(ciphertext)
			writeUploaderJSON(writer, http.StatusOK, encryptedCompleteResult{EncryptedReceipt: base64.RawURLEncoding.EncodeToString(ciphertext), ReceiptDigest: hex.EncodeToString(digest[:])})
		case request.Method == http.MethodPost && request.URL.Path == "/"+resourceID+"/receipt":
			receiptCalls.Add(1)
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	cleanupErr := errors.New("credential store unavailable")
	store := &uploaderDeleteFailStore{keyMemoryStore: keyMemoryStore{values: make(map[string]string)}, deleteErr: cleanupErr}
	vault, err := transfercrypto.NewKeyVault(store)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := NewKeyCoordinator(vault, keyDelivererFunc(func(_ context.Context, _ resolver.ConnectInfo, _ transfercrypto.KeyControlBinding, material transfercrypto.KeyMaterial) (peerContext peercontext.Context, deliveryErr error) {
		deliveredMaterial = material
		return peer, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(server.URL, Auth{Token: "token"}, Binding{SourceMachineID: "source_01", DestinationMachineID: peer.MachineID, InitiatingUserID: peer.AccountID}, server.Client())
	var warnings []error
	uploader := &EncryptedUploader{Client: client, Keys: keys, Retention: time.Hour, Generation: 1, CleanupWarning: func(err error) { warnings = append(warnings, err) }}
	batch, err := uploader.SendBatch(context.Background(), batchID, "session_01", []Source{{Basename: "payload.txt", Size: int64(len(content)), SHA256: contentDigest, Reader: bytes.NewReader(content)}})
	if err != nil {
		t.Fatalf("acknowledged delivery became an error: %v", err)
	}
	if batch.BatchID != batchID || len(batch.Transfers) != 1 || batch.Transfers[0].State != "delivered" || batch.Paths[0] != "Paperboat Inbox/payload.txt" {
		t.Fatalf("batch=%+v", batch)
	}
	if createCalls.Load() != 1 || receiptCalls.Load() != 1 {
		t.Fatalf("create calls=%d receipt calls=%d, want one acknowledged delivery", createCalls.Load(), receiptCalls.Load())
	}
	if store.deleteCalls.Load() != 1 || len(warnings) != 1 || !errors.Is(warnings[0], cleanupErr) {
		t.Fatalf("delete calls=%d warnings=%v", store.deleteCalls.Load(), warnings)
	}
	retained, loadErr := vault.Load(batchID, 1)
	if loadErr != nil || !retained.Valid() {
		t.Fatalf("failed cleanup did not retain a retryable sender key: valid=%t err=%v", retained.Valid(), loadErr)
	}
	retained.Destroy()
	deliveredMaterial.Destroy()
}

func TestEncryptedUploaderDoesNotHidePreCommitFailure(t *testing.T) {
	var createCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		createCalls.Add(1)
		writeUploaderJSON(writer, http.StatusBadRequest, &Error{Code: "create_rejected", Message: "rejected before delivery"})
	}))
	defer server.Close()

	store := &uploaderDeleteFailStore{keyMemoryStore: keyMemoryStore{values: make(map[string]string)}}
	vault, _ := transfercrypto.NewKeyVault(store)
	keys, _ := NewKeyCoordinator(vault, keyDelivererFunc(func(_ context.Context, _ resolver.ConnectInfo, binding transfercrypto.KeyControlBinding, _ transfercrypto.KeyMaterial) (peerContext peercontext.Context, deliveryErr error) {
		return keyContext(binding.OperationID), nil
	}))
	client := NewClient(server.URL, Auth{Token: "token"}, Binding{SourceMachineID: "source_01", DestinationMachineID: "machine_01", InitiatingUserID: "account_01"}, server.Client())
	var warnings []error
	uploader := &EncryptedUploader{Client: client, Keys: keys, Retention: time.Hour, CleanupWarning: func(err error) { warnings = append(warnings, err) }}
	content := []byte("not delivered")
	digest := sha256.Sum256(content)
	batch, err := uploader.SendBatch(context.Background(), "fb_precommit_failure", "session_01", []Source{{Basename: "payload.txt", Size: int64(len(content)), SHA256: digest, Reader: bytes.NewReader(content)}})
	if err == nil || batch.BatchID != "" {
		t.Fatalf("batch=%+v err=%v, want original pre-commit failure", batch, err)
	}
	if createCalls.Load() != 1 || store.deleteCalls.Load() != 0 || len(warnings) != 0 {
		t.Fatalf("create calls=%d delete calls=%d warnings=%v", createCalls.Load(), store.deleteCalls.Load(), warnings)
	}
}

func writeUploaderJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
