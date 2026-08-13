package filetransfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

func TestLocalSenderStagesKeyAndResumesFromAuthoritativeOffset(t *testing.T) {
	var mu sync.Mutex
	var content []byte
	completed := false
	expires := time.Now().UTC().Truncate(time.Second).Add(time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 43) {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v1/local-file-transfers":
			var input struct {
				BatchID     string `json:"batch_id"`
				KeyMaterial string `json:"key_material"`
			}
			if json.NewDecoder(request.Body).Decode(&input) != nil || input.BatchID != "local_batch" {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			encoded, err := base64.RawURLEncoding.Strict().DecodeString(input.KeyMaterial)
			material, parseErr := transfercrypto.ParseKeyMaterial(encoded)
			clear(encoded)
			if err != nil || parseErr != nil || !material.Valid() {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			material.Destroy()
			writeJSONTest(writer, http.StatusCreated, map[string]any{"batch_id": "local_batch", "transfers": []Manifest{{TransferID: "local_batch.0", BatchID: "local_batch", Basename: "data.bin", Size: 12, CommittedOffset: int64(len(content)), State: "created", ExpiresAt: expires}}})
		case request.Method == http.MethodGet && request.URL.Path == "/v1/local-file-transfers/local_batch.0":
			state, code, receiptPath := "uploading", "", ""
			if completed {
				state, code, receiptPath = "delivered", "stored", "Paperboat Inbox/data.bin"
			}
			writeJSONTest(writer, http.StatusOK, Manifest{TransferID: "local_batch.0", BatchID: "local_batch", Basename: "data.bin", Size: 12, SHA256: strings.Repeat("a", 64), CommittedOffset: int64(len(content)), State: state, ResultCode: code, ReceiptPath: receiptPath, ExpiresAt: expires})
		case request.Method == http.MethodPatch && request.URL.Path == "/v1/local-file-transfers/local_batch.0/content":
			if request.Header.Get("Upload-Offset") != "4" {
				writer.WriteHeader(http.StatusConflict)
				return
			}
			body, _ := io.ReadAll(request.Body)
			content = append(content, body...)
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPost && request.URL.Path == "/v1/local-file-transfers/local_batch.0/complete":
			completed = true
			writeJSONTest(writer, http.StatusOK, Manifest{TransferID: "local_batch.0", State: "pending"})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	content = append(content, []byte("data")...)
	plaintext := []byte("data-private")
	digest := sha256.Sum256(plaintext)
	sender := &LocalSender{Endpoint: server.URL + "/v1/local-file-transfers", Token: strings.Repeat("t", 43), HTTPClient: server.Client()}
	batch, err := sender.SendBatch(context.Background(), "local_batch", "machine_host", "machine_cli", "user_1", "ses_1", []Source{{Basename: "data.bin", Size: int64(len(plaintext)), SHA256: digest, Reader: bytes.NewReader(plaintext)}}, 1, expires)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, plaintext) || len(batch.Transfers) != 1 || batch.Transfers[0].State != "delivered" || batch.Paths[0] != "Paperboat Inbox/data.bin" {
		t.Fatalf("content=%q batch=%+v", content, batch)
	}
}

func writeJSONTest(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
