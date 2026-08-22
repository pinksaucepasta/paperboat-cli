package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/config"
	clienttransfer "github.com/pinksaucepasta/paperboat/internal/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/operation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/store"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

type readProbe struct{ reads int }

func (r *readProbe) Read([]byte) (int, error) { r.reads++; return 0, io.EOF }
func (*readProbe) Close() error               { return nil }

type loseFirstCompleteResponse struct {
	base http.RoundTripper
	lost atomic.Bool
}

func (t *loseFirstCompleteResponse) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil || !strings.HasSuffix(request.URL.Path, "/complete") || !t.lost.CompareAndSwap(false, true) {
		return response, err
	}
	_ = response.Body.Close()
	return nil, io.ErrUnexpectedEOF
}

type revocableBody struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

type closingFileAuthorizer struct {
	authorization Authorization
	closed        *atomic.Int32
}

func (a *closingFileAuthorizer) Authorize(context.Context, protocol.Frame) (Authorization, error) {
	return a.authorization, nil
}
func (a *closingFileAuthorizer) CloseAuthorization() { a.closed.Add(1) }

func (b *revocableBody) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.closed
	return 0, net.ErrClosed
}
func (b *revocableBody) Close() error {
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

func fileTransferTestHandler(t *testing.T) (*FileTransferHandler, *store.Store) {
	t.Helper()
	root := t.TempDir()
	durable, err := store.Open(context.Background(), store.Config{Root: filepath.Join(root, "state")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = durable.Close() })
	service, err := filetransfer.New(filetransfer.Config{Root: filepath.Join(root, "files"), LocalMachineID: "machine_host", Store: durable})
	if err != nil {
		t.Fatal(err)
	}
	journal, _ := operation.NewJournal(32)
	handler, err := NewFileTransferHandler(FileTransferHandlerConfig{Service: service, Journal: journal, Authorizer: func(token string) (Authorizer, error) {
		if token != "token" {
			return nil, errors.New("invalid")
		}
		return authorizerFunc(func(context.Context, protocol.Frame) (Authorization, error) {
			return Authorization{JournalBinding: "env:1:cli:1", EnvironmentID: "env_1", MachineID: "machine_host", UserID: "user_1", ClientID: "cli_1", SessionID: "ses_1"}, nil
		}), nil
	}, AuthorizeCreate: func(authorization Authorization, request CreateFileTransferRequest) bool {
		return request.DestinationMachineID == authorization.MachineID && request.InitiatingUserID == authorization.UserID
	}})
	if err != nil {
		t.Fatal(err)
	}
	return handler, durable
}
func addressedTransferRequest(batchID, sessionID string, files []filetransfer.File) CreateFileTransferRequest {
	return CreateFileTransferRequest{BatchID: batchID, SourceMachineID: "machine_client", DestinationMachineID: "machine_host", InitiatingUserID: "user_1", SessionID: sessionID, Files: files}
}
func transferRequest(method, url string, body []byte) *http.Request {
	request := httptest.NewRequest(method, url, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set(HeaderRequestID, "req_ft")
	request.Header.Set(HeaderOperationID, "operation_ft_1")
	return request
}
func transferDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestFileTransferHTTPResumesCompletesAndRangesOpaqueContent(t *testing.T) {
	handler, _ := fileTransferTestHandler(t)
	data := []byte("abcdefgh")
	input, _ := json.Marshal(addressedTransferRequest("fb_1", "ses_1", []filetransfer.File{{Basename: "archive.dat", Size: int64(len(data)), SHA256: transferDigest(data)}}))
	request := transferRequest(http.MethodPost, "http://helper.test/v1/file-transfers", input)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create=%d %s", response.Code, response.Body.String())
	}
	var created createFileTransferResponse
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || len(created.Transfers) != 1 {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	id := created.Transfers[0].ID
	for _, part := range []struct {
		offset int64
		chunk  []byte
	}{{0, data[:3]}, {3, data[3:]}} {
		request = transferRequest(http.MethodPatch, "http://helper.test/v1/file-transfers/"+id+"/content", part.chunk)
		request.Header.Set("Content-Type", "application/offset+octet-stream")
		request.Header.Set(HeaderUploadOffset, strconv.FormatInt(part.offset, 10))
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("patch=%d %s", response.Code, response.Body.String())
		}
	}
	request = transferRequest(http.MethodHead, "http://helper.test/v1/file-transfers/"+id+"/content", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Header().Get(HeaderUploadOffset) != "8" || response.Header().Get("ETag") == "" {
		t.Fatalf("head=%d headers=%v", response.Code, response.Header())
	}
	for attempt := 0; attempt < 2; attempt++ {
		request = transferRequest(http.MethodPost, "http://helper.test/v1/file-transfers/"+id+"/complete", nil)
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("complete attempt=%d status=%d %s", attempt, response.Code, response.Body.String())
		}
	}
	etag := `"sha256:` + transferDigest(data) + `"`
	request = transferRequest(http.MethodGet, "http://helper.test/v1/file-transfers/"+id+"/content", nil)
	request.Header.Set("If-Match", etag)
	request.Header.Set("Range", "bytes=2-5")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusPartialContent || response.Body.String() != "cdef" || response.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("download=%d body=%q headers=%v", response.Code, response.Body.String(), response.Header())
	}
}

func TestEncryptedFileTransferPublishesOnlyAfterAuthenticatedManifestChunksAndReceipt(t *testing.T) {
	handler, _ := fileTransferTestHandler(t)
	vault, err := transfercrypto.NewKeyVault(config.FileSecretStore{Dir: filepath.Join(t.TempDir(), "keys")})
	if err != nil {
		t.Fatal(err)
	}
	handler.config.TransferKeys = vault
	now := time.Now().UTC().Truncate(time.Second)
	peer := peercontext.Context{AccountID: "user_1", UserID: "user_1", DeviceID: "cli_1", MachineID: "machine_host", HostGeneration: 2, AuthorizationGeneration: 3, IntentID: "intent_01", OperationID: "operation_key_01", Consumer: "file_transfer_key", InitiatorRole: "controlling", ResponderRole: "controlled", AttemptGeneration: 1}
	peer.InitiatorCertificateHash[0], peer.ResponderCertificateHash[0] = 1, 2
	material, _ := transfercrypto.GenerateKeyMaterial()
	batchID := "fb_encrypted_01"
	if err := vault.SaveBound(batchID, 1, material, now.Add(time.Hour), peer); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	lossy := &loseFirstCompleteResponse{base: server.Client().Transport}
	client := clienttransfer.NewClient(server.URL+"/v1/file-transfers", clienttransfer.Auth{Token: "token"}, clienttransfer.Binding{SourceMachineID: "machine_client", DestinationMachineID: "machine_host", InitiatingUserID: "user_1"}, &http.Client{Transport: lossy})
	plaintext := []byte("private file payload")
	digest := sha256.Sum256(plaintext)
	batch, err := client.SendEncryptedBatch(context.Background(), batchID, "ses_1", []clienttransfer.Source{{Basename: "private.txt", Size: int64(len(plaintext)), SHA256: digest, Reader: bytes.NewReader(plaintext)}}, 1, clienttransfer.PreparedKey{Material: material, Context: peer})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Transfers) != 1 || batch.Transfers[0].State != "delivered" || batch.Paths[0] != "Paperboat Inbox/fb_encrypted_01.0-private.txt" {
		t.Fatalf("batch=%+v", batch)
	}
	if !lossy.lost.Load() {
		t.Fatal("completion response loss was not exercised")
	}
	published, err := handler.config.Service.PublishedPath(context.Background(), batch.Transfers[0].TransferID)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(published)
	if err != nil || !bytes.Equal(content, plaintext) {
		t.Fatalf("published=%q err=%v", content, err)
	}
	if _, err := vault.Load(batchID, 1); !errors.Is(err, transfercrypto.ErrKeyUnavailable) {
		t.Fatalf("completed transfer key still available: %v", err)
	}
}

func TestEncryptedManifestTamperingFailsAfterVisibleDigestReplacement(t *testing.T) {
	handler, _ := fileTransferTestHandler(t)
	vault, err := transfercrypto.NewKeyVault(config.FileSecretStore{Dir: filepath.Join(t.TempDir(), "keys")})
	if err != nil {
		t.Fatal(err)
	}
	handler.config.TransferKeys = vault
	peer := peercontext.Context{AccountID: "user_1", UserID: "user_1", DeviceID: "cli_1", MachineID: "machine_host", HostGeneration: 2, AuthorizationGeneration: 3, IntentID: "intent_01", OperationID: "operation_key_01", Consumer: "file_transfer_key", InitiatorRole: "controlling", ResponderRole: "controlled", AttemptGeneration: 1}
	peer.InitiatorCertificateHash[0], peer.ResponderCertificateHash[0] = 1, 2
	material, err := transfercrypto.GenerateKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	defer material.Destroy()
	batchID := "fb_manifest_tamper"
	if err := vault.SaveBound(batchID, 1, material, time.Now().UTC().Add(time.Hour), peer); err != nil {
		t.Fatal(err)
	}
	plaintextDigest := sha256.Sum256([]byte("private"))
	manifest := transfercrypto.Manifest{BatchID: batchID, Files: []transfercrypto.ManifestFile{{TransferID: batchID + ".0", Name: "private.txt", RelativeDestination: "Paperboat Inbox/private.txt", Mode: 0o600, Size: 7, PlaintextSHA256: plaintextDigest, ChunkCount: 1}}}
	ciphertext, err := transfercrypto.EncryptManifest(material, recordContext(peer, batchID, 1), manifest)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 1
	visibleDigest := sha256.Sum256(ciphertext)
	envelope := &fileTransferE2EE{Version: 1, TransferID: batchID, TransferGeneration: 1, EncryptedManifest: base64.RawURLEncoding.EncodeToString(ciphertext), ManifestDigest: hex.EncodeToString(visibleDigest[:])}
	input := &CreateFileTransferRequest{BatchID: batchID, SourceMachineID: "machine_client", DestinationMachineID: "machine_host", InitiatingUserID: "user_1"}
	if err := handler.openEncryptedCreate(envelope, input, Authorization{UserID: "user_1"}); !errors.Is(err, transfercrypto.ErrAuthentication) {
		t.Fatalf("tampered manifest err=%v", err)
	}
	if len(input.Files) != 0 {
		t.Fatalf("tampered manifest created files: %+v", input.Files)
	}
}

func TestFileTransferHTTPCreateIsIdempotentAndOffsetConflictReportsCommittedOffset(t *testing.T) {
	handler, _ := fileTransferTestHandler(t)
	data := []byte("x")
	input, _ := json.Marshal(addressedTransferRequest("fb_1", "ses_1", []filetransfer.File{{Basename: "x", Size: 1, SHA256: transferDigest(data)}}))
	var first createFileTransferResponse
	for attempt := 0; attempt < 2; attempt++ {
		request := transferRequest(http.MethodPost, "http://helper.test/v1/file-transfers", input)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusCreated {
			t.Fatalf("attempt=%d status=%d", attempt, response.Code)
		}
		var got createFileTransferResponse
		_ = json.Unmarshal(response.Body.Bytes(), &got)
		if attempt == 0 {
			first = got
		} else if got.Transfers[0].ID != first.Transfers[0].ID || response.Header().Get(HeaderReplayed) != "true" {
			t.Fatalf("replay=%#v headers=%v", got, response.Header())
		}
	}
	id := first.Transfers[0].ID
	request := transferRequest(http.MethodPatch, "http://helper.test/v1/file-transfers/"+id+"/content", data)
	request.Header.Set("Content-Type", "application/offset+octet-stream")
	request.Header.Set(HeaderUploadOffset, "1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("conflict=%d %s", response.Code, response.Body.String())
	}
}

func TestFileTransferHTTPAuthenticatesBeforeReadingCreateBody(t *testing.T) {
	handler, _ := fileTransferTestHandler(t)
	probe := &readProbe{}
	request := transferRequest(http.MethodPost, "http://helper.test/v1/file-transfers", nil)
	request.Header.Set("Authorization", "Bearer wrong")
	request.Body = probe
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || probe.reads != 0 {
		t.Fatalf("status=%d reads=%d", response.Code, probe.reads)
	}
}

func TestFileTransferHTTPRejectsSessionOutsideCredentialBinding(t *testing.T) {
	handler, _ := fileTransferTestHandler(t)
	input, _ := json.Marshal(addressedTransferRequest("fb_1", "ses_other", []filetransfer.File{{Basename: "x", Size: 0, SHA256: transferDigest(nil)}}))
	request := transferRequest(http.MethodPost, "http://helper.test/v1/file-transfers", input)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestFileTransferHTTPPendingIsRecipientPinnedAndReceiptIsRelative(t *testing.T) {
	handler, _ := fileTransferTestHandler(t)
	data := []byte("delivery")
	created, err := handler.config.Service.Create(context.Background(), filetransfer.CreateRequest{BatchID: "fb_send", SourceMachineID: "machine_host", DestinationMachineID: "machine_client", InitiatingUserID: "user_1", SessionID: "ses_1", DeliveryClientID: "cli_1", Files: []filetransfer.File{{Basename: "delivery.bin", Size: int64(len(data)), SHA256: transferDigest(data)}}})
	if err != nil {
		t.Fatal(err)
	}
	id := created[0].ID
	if _, err := handler.config.Service.Append(context.Background(), id, 0, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.config.Service.Complete(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	request := transferRequest(http.MethodGet, "http://helper.test/v1/file-transfers/pending?session_id=ses_1&wait_seconds=0", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(id)) {
		t.Fatalf("pending=%d %s", response.Code, response.Body.String())
	}
	receipt, _ := json.Marshal(map[string]any{"result_code": "stored", "path": "Paperboat Inbox/delivery.bin"})
	request = transferRequest(http.MethodPost, "http://helper.test/v1/file-transfers/"+id+"/receipt", receipt)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("receipt=%d %s", response.Code, response.Body.String())
	}
	manifest, err := handler.config.Service.Get(context.Background(), id)
	if err != nil || manifest.State != "delivered" || manifest.ReceiptPath != "Paperboat Inbox/delivery.bin" {
		t.Fatalf("manifest=%#v err=%v", manifest, err)
	}
	request = transferRequest(http.MethodGet, "http://helper.test/v1/file-transfers/pending?session_id=ses_1&wait_seconds=0", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || bytes.Contains(response.Body.Bytes(), []byte(id)) {
		t.Fatalf("redelivery=%d %s", response.Code, response.Body.String())
	}
}

func TestEncryptedReversePendingManifestAndChunksAreOpaque(t *testing.T) {
	handler, _ := fileTransferTestHandler(t)
	vault, err := transfercrypto.NewKeyVault(config.FileSecretStore{Dir: filepath.Join(t.TempDir(), "keys")})
	if err != nil {
		t.Fatal(err)
	}
	handler.config.TransferKeys = vault
	plaintext := []byte("machine to cli private payload")
	batchID := "fb_reverse_encrypted"
	resourceID := batchID + ".0"
	generation := uint64(3)
	material, _ := transfercrypto.GenerateKeyMaterial()
	defer material.Destroy()
	keyBytes, _ := material.MarshalBinary()
	expiresAt := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	local, err := NewLocalFileTransferHandler(LocalFileTransferConfig{Token: strings.Repeat("l", 43), MachineID: "machine_host", Service: handler.config.Service, TransferKeys: vault, ResolveRecipient: func(sessionID, machineID string) (string, error) {
		if sessionID == "ses_1" && machineID == "machine_client" {
			return "cli_1", nil
		}
		return "", errors.New("missing")
	}})
	if err != nil {
		t.Fatal(err)
	}
	createPayload, _ := json.Marshal(localFileTransferCreate{BatchID: batchID, DestinationMachineID: "machine_client", InitiatingUserID: "user_1", SessionID: "ses_1", TransferGeneration: generation, ExpiresAt: expiresAt, KeyMaterial: base64.RawURLEncoding.EncodeToString(keyBytes), Files: []filetransfer.File{{ID: resourceID, Basename: "private-name.txt", Size: int64(len(plaintext)), SHA256: transferDigest(plaintext), Ordinal: 0}}})
	localRequest := httptest.NewRequest(http.MethodPost, "http://helper.test/v1/local-file-transfers", bytes.NewReader(createPayload))
	localRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("l", 43))
	localResponse := httptest.NewRecorder()
	local.ServeHTTP(localResponse, localRequest)
	if localResponse.Code != http.StatusCreated {
		t.Fatalf("local create=%d %s", localResponse.Code, localResponse.Body.String())
	}
	localRequest = httptest.NewRequest(http.MethodPatch, "http://helper.test/v1/local-file-transfers/"+resourceID+"/content", bytes.NewReader(plaintext))
	localRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("l", 43))
	localRequest.Header.Set("Content-Type", "application/offset+octet-stream")
	localRequest.Header.Set(HeaderUploadOffset, "0")
	localResponse = httptest.NewRecorder()
	local.ServeHTTP(localResponse, localRequest)
	if localResponse.Code != http.StatusNoContent {
		t.Fatalf("local content=%d %s", localResponse.Code, localResponse.Body.String())
	}
	localRequest = httptest.NewRequest(http.MethodPost, "http://helper.test/v1/local-file-transfers/"+resourceID+"/complete", nil)
	localRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("l", 43))
	localResponse = httptest.NewRecorder()
	local.ServeHTTP(localResponse, localRequest)
	if localResponse.Code != http.StatusOK {
		t.Fatalf("local complete=%d %s", localResponse.Code, localResponse.Body.String())
	}
	peer := peercontext.Context{AccountID: "user_1", UserID: "user_1", DeviceID: "cli_1", MachineID: "machine_host", HostGeneration: 2, AuthorizationGeneration: 3, IntentID: "intent_reverse", OperationID: clienttransfer.KeyOperationID(batchID), Consumer: "file_transfer_key", InitiatorRole: "controlling", ResponderRole: "controlled", AttemptGeneration: 1}
	peer.InitiatorCertificateHash[0], peer.ResponderCertificateHash[0] = 1, 2
	if err := vault.SaveLocalBound(batchID, generation, material, expiresAt, peer); err != nil {
		t.Fatal(err)
	}

	request := transferRequest(http.MethodGet, "http://helper.test/v1/file-transfers/pending?session_id=ses_1&wait_seconds=0", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("pending=%d %s", response.Code, response.Body.String())
	}
	pending := response.Body.String()
	for _, forbidden := range []string{"private-name.txt", transferDigest(plaintext), "machine_host", "machine_client", "user_1", "Paperboat Inbox", `\"size\"`, `\"basename\"`, `\"sha256\"`} {
		if strings.Contains(pending, forbidden) {
			t.Fatalf("pending exposed %q: %s", forbidden, pending)
		}
	}
	if !strings.Contains(pending, batchID) || !strings.Contains(pending, resourceID) {
		t.Fatalf("pending omitted opaque identities: %s", pending)
	}

	request = transferRequest(http.MethodGet, "http://helper.test/v1/file-transfers/"+resourceID+"/e2ee-manifest", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("manifest=%d %s", response.Code, response.Body.String())
	}
	var envelope encryptedManifestResponse
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(envelope.EncryptedManifest)
	visibleDigest := sha256.Sum256(ciphertext)
	if err != nil || envelope.TransferID != batchID || envelope.TransferGeneration != generation || envelope.ManifestDigest != hex.EncodeToString(visibleDigest[:]) {
		t.Fatalf("manifest envelope=%+v err=%v", envelope, err)
	}
	manifest, err := transfercrypto.DecryptManifest(material, recordContextDirection(peer, batchID, generation, transfercrypto.DirectionFromMachine), ciphertext)
	if err != nil || len(manifest.Files) != 1 || manifest.Files[0].Name != "private-name.txt" || manifest.Files[0].TransferID != resourceID || manifest.Files[0].Size != uint64(len(plaintext)) {
		t.Fatalf("manifest=%+v err=%v", manifest, err)
	}

	request = transferRequest(http.MethodGet, "http://helper.test/v1/file-transfers/"+resourceID+"/chunks/0", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("chunk=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
	chunkContext := transfercrypto.ChunkContext{AccountID: peer.AccountID, DeviceID: peer.DeviceID, MachineID: peer.MachineID, InitiatorCertificateHash: peer.InitiatorCertificateHash, ResponderCertificateHash: peer.ResponderCertificateHash, OperationID: peer.OperationID, TransferID: batchID, Direction: transfercrypto.DirectionFromMachine, TransferGeneration: generation, FileOrdinal: 0, ChunkOrdinal: 0, Final: true}
	opened, err := transfercrypto.DecryptChunk(material, chunkContext, response.Body.Bytes())
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened=%q err=%v", opened, err)
	}
	clear(opened)
	manifestHash, err := manifest.Hash()
	if err != nil {
		t.Fatal(err)
	}
	receiptRecord := transfercrypto.FinalReceipt{ManifestHash: manifestHash, Files: []transfercrypto.ReceiptFile{{FileOrdinal: 0, Result: transfercrypto.CollisionOriginal, RelativePath: "Paperboat Inbox/private-name.txt"}}}
	receiptCiphertext, err := transfercrypto.EncryptFinalReceipt(material, recordContextDirection(peer, batchID, generation, transfercrypto.DirectionFromMachine), receiptRecord)
	if err != nil {
		t.Fatal(err)
	}
	receiptDigest := sha256.Sum256(receiptCiphertext)
	receiptPayload, _ := json.Marshal(map[string]string{"encrypted_receipt": base64.RawURLEncoding.EncodeToString(receiptCiphertext), "receipt_digest": hex.EncodeToString(receiptDigest[:])})
	if bytes.Contains(receiptPayload, []byte("private-name.txt")) || bytes.Contains(receiptPayload, []byte("Paperboat Inbox")) {
		t.Fatalf("receipt exposed plaintext metadata: %s", receiptPayload)
	}
	for attempt := 0; attempt < 2; attempt++ {
		request = transferRequest(http.MethodPost, "http://helper.test/v1/file-transfers/"+resourceID+"/receipt", receiptPayload)
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("receipt attempt=%d status=%d body=%s", attempt, response.Code, response.Body.String())
		}
	}
	delivered, err := handler.config.Service.Get(context.Background(), resourceID)
	if err != nil || delivered.State != "delivered" || delivered.ReceiptPath != "Paperboat Inbox/private-name.txt" {
		t.Fatalf("delivered=%+v err=%v", delivered, err)
	}
	if _, err := vault.Load(batchID, generation); !errors.Is(err, transfercrypto.ErrKeyUnavailable) {
		t.Fatalf("sender key retained after receipt: %v", err)
	}
}

func TestFileTransferHTTPRejectsUnknownOrPathBearingFailureReceipt(t *testing.T) {
	for _, input := range []struct{ code, path string }{
		{"made_up", ""},
		{"storage_unavailable", "Paperboat Inbox/x"},
		{"stored", "/absolute/x"},
	} {
		if validReceipt(input.code, input.path) {
			t.Fatalf("accepted receipt %#v", input)
		}
	}
}

func TestFileTransferHTTPAgentCreatePinsResolvedWriter(t *testing.T) {
	handler, _ := fileTransferTestHandler(t)
	handler.config.ResolveDeliveryClient = func(_ Authorization, request CreateFileTransferRequest) (string, error) {
		if request.SourceMachineID != "machine_host" || request.DestinationMachineID != "machine_client" || request.SessionID != "ses_1" {
			return "", errors.New("invalid")
		}
		return "cli_writer", nil
	}
	handler.config.AuthorizeCreate = func(_ Authorization, request CreateFileTransferRequest) bool {
		return request.SourceMachineID == "machine_host"
	}
	input, _ := json.Marshal(CreateFileTransferRequest{BatchID: "fb_agent", SourceMachineID: "machine_host", DestinationMachineID: "machine_client", InitiatingUserID: "user_1", SessionID: "ses_1", Files: []filetransfer.File{{Basename: "x", Size: 0, SHA256: transferDigest(nil)}}})
	request := transferRequest(http.MethodPost, "http://helper.test/v1/file-transfers", input)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if bytes.Contains(response.Body.Bytes(), []byte("client_id")) {
		t.Fatalf("response exposed internal recipient: %s", response.Body.String())
	}
	var result createFileTransferResponse
	_ = json.Unmarshal(response.Body.Bytes(), &result)
	persisted, err := handler.config.Service.Get(context.Background(), result.Transfers[0].ID)
	if err != nil || persisted.DeliveryClientID != "cli_writer" {
		t.Fatalf("persisted=%#v err=%v", persisted, err)
	}
	handler.config.ResolveDeliveryClient = func(Authorization, CreateFileTransferRequest) (string, error) {
		return "", errors.New("writer changed")
	}
	request = transferRequest(http.MethodPost, "http://helper.test/v1/file-transfers", input)
	request.Header.Set(HeaderOperationID, "operation_ft_recovered")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get(HeaderReplayed) != "true" {
		t.Fatalf("recovery status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var recovered createFileTransferResponse
	_ = json.Unmarshal(response.Body.Bytes(), &recovered)
	if recovered.Transfers[0].ID != result.Transfers[0].ID {
		t.Fatalf("recovered=%#v", recovered)
	}
}

func TestFileTransferHTTPRevocationInterruptsBlockedUploadAndReleasesWatcher(t *testing.T) {
	handler, _ := fileTransferTestHandler(t)
	data := []byte("x")
	created, err := handler.config.Service.Create(context.Background(), filetransfer.CreateRequest{BatchID: "fb_revoke", SourceMachineID: "machine_client", DestinationMachineID: "machine_host", InitiatingUserID: "user_1", SessionID: "ses_1", Files: []filetransfer.File{{Basename: "x", Size: 1, SHA256: transferDigest(data)}}})
	if err != nil {
		t.Fatal(err)
	}
	revoked := &atomic.Bool{}
	signal := make(chan struct{})
	closed := &atomic.Int32{}
	handler.config.Authorizer = func(string) (Authorizer, error) {
		return &closingFileAuthorizer{authorization: Authorization{JournalBinding: "env:1:cli:1", EnvironmentID: "env_1", MachineID: "machine_host", UserID: "user_1", ClientID: "cli_1", SessionID: "ses_1", Revoked: revoked, RevokedSignal: signal}, closed: closed}, nil
	}
	body := &revocableBody{started: make(chan struct{}), closed: make(chan struct{})}
	request := transferRequest(http.MethodPatch, "http://helper.test/v1/file-transfers/"+created[0].ID+"/content", nil)
	request.Header.Set("Content-Type", "application/offset+octet-stream")
	request.Header.Set(HeaderUploadOffset, "0")
	request.Body = body
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()
	select {
	case <-body.started:
	case <-time.After(time.Second):
		t.Fatal("upload body was not read")
	}
	revoked.Store(true)
	close(signal)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("revocation did not interrupt upload")
	}
	if response.Code != 499 || closed.Load() != 1 {
		t.Fatalf("status=%d watcher closes=%d body=%s", response.Code, closed.Load(), response.Body.String())
	}
	manifest, err := handler.config.Service.Get(context.Background(), created[0].ID)
	if err != nil || manifest.CommittedOffset != 0 {
		t.Fatalf("manifest=%#v err=%v", manifest, err)
	}
}

func TestFileTransferHTTPDeleteInterruptsBlockedUpload(t *testing.T) {
	handler, _ := fileTransferTestHandler(t)
	created, err := handler.config.Service.Create(context.Background(), filetransfer.CreateRequest{BatchID: "fb_cancel_active", SourceMachineID: "machine_client", DestinationMachineID: "machine_host", InitiatingUserID: "user_1", SessionID: "ses_1", Files: []filetransfer.File{{Basename: "x", Size: 1, SHA256: transferDigest([]byte("x"))}}})
	if err != nil {
		t.Fatal(err)
	}
	id := created[0].ID
	body := &revocableBody{started: make(chan struct{}), closed: make(chan struct{})}
	patchRequest := transferRequest(http.MethodPatch, "http://helper.test/v1/file-transfers/"+id+"/content", nil)
	patchRequest.Header.Set("Content-Type", "application/offset+octet-stream")
	patchRequest.Header.Set(HeaderUploadOffset, "0")
	patchRequest.Body = body
	patchResponse := httptest.NewRecorder()
	patchDone := make(chan struct{})
	go func() {
		handler.ServeHTTP(patchResponse, patchRequest)
		close(patchDone)
	}()
	select {
	case <-body.started:
	case <-time.After(time.Second):
		t.Fatal("upload body was not read")
	}
	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, transferRequest(http.MethodDelete, "http://helper.test/v1/file-transfers/"+id, nil))
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}
	select {
	case <-patchDone:
	case <-time.After(time.Second):
		t.Fatal("delete did not interrupt upload")
	}
	select {
	case <-body.closed:
	default:
		t.Fatal("delete completed before it closed the blocked upload body")
	}
	if patchResponse.Code != 499 {
		t.Fatalf("patch status=%d body=%s", patchResponse.Code, patchResponse.Body.String())
	}
	transfer, err := handler.config.Service.Get(context.Background(), id)
	if err != nil || transfer.State != "canceled" {
		t.Fatalf("transfer=%#v err=%v", transfer, err)
	}
}
