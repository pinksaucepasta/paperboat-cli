package filetransfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func source(data []byte) Source {
	sum := sha256.Sum256(data)
	return Source{Basename: "data.bin", Size: int64(len(data)), SHA256: sum, Reader: bytes.NewReader(data)}
}
func sourceDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func TestUploadBatchResumesAndRefreshesWithoutChangingTransferID(t *testing.T) {
	data := []byte("abcdefgh")
	var mu sync.Mutex
	committed := int64(3)
	content := append([]byte(nil), data[:3]...)
	patches := 0
	refreshes := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v1/file-transfers":
			_ = json.NewEncoder(writer).Encode(Batch{BatchID: "fb_1", Transfers: []Manifest{{TransferID: "ft_1", BatchID: "fb_1", Direction: "pb_to_pbh", SessionID: "ses_1", Basename: "data.bin", Size: int64(len(data)), SHA256: sourceDigest(data), CommittedOffset: 0, State: "created"}}})
		case request.Method == http.MethodHead && strings.HasSuffix(request.URL.Path, "/content"):
			writer.Header().Set("Upload-Offset", strconv.FormatInt(committed, 10))
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPatch:
			patches++
			if patches == 1 {
				writer.WriteHeader(http.StatusUnauthorized)
				_, _ = writer.Write([]byte(`{"code":"unauthorized"}`))
				return
			}
			if request.Header.Get("Authorization") != "Bearer fresh" {
				t.Errorf("authorization=%q", request.Header.Get("Authorization"))
			}
			offset, _ := strconv.ParseInt(request.Header.Get("Upload-Offset"), 10, 64)
			if offset != committed {
				t.Errorf("offset=%d committed=%d", offset, committed)
			}
			chunk, _ := io.ReadAll(request.Body)
			content = append(content, chunk...)
			committed += int64(len(chunk))
			writer.Header().Set("Upload-Offset", strconv.FormatInt(committed, 10))
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/complete"):
			_ = json.NewEncoder(writer).Encode(map[string]any{"transfer": Manifest{TransferID: "ft_1", BatchID: "fb_1", State: "published", Size: int64(len(data)), SHA256: sourceDigest(data)}, "result": map[string]any{"code": "published", "path": "/remote/ft_1.content"}})
		default:
			t.Errorf("unexpected %s %s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := NewClient(server.URL+"/v1/file-transfers", Auth{Token: "old"}, server.Client())
	client.RefreshAuth = func(context.Context) (Auth, error) {
		refreshes++
		return Auth{Token: "fresh", ExpiresAt: time.Now().Add(time.Minute)}, nil
	}
	batch, err := client.UploadBatch(context.Background(), "fb_1", "ses_1", []Source{source(data)})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Transfers) != 1 || batch.Transfers[0].TransferID != "ft_1" || len(batch.Paths) != 1 || batch.Paths[0] != "/remote/ft_1.content" || !bytes.Equal(content, data) || patches != 2 || refreshes != 1 {
		t.Fatalf("batch=%#v content=%q patches=%d refreshes=%d", batch, content, patches, refreshes)
	}
}

func TestUploadBatchCancelsEveryManifestAfterFailure(t *testing.T) {
	var canceled []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodPost:
			_ = json.NewEncoder(writer).Encode(Batch{BatchID: "fb", Transfers: []Manifest{{TransferID: "ft_1", Size: 1}, {TransferID: "ft_2", Size: 1}}})
		case http.MethodHead:
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte(`{"code":"storage_unavailable"}`))
		case http.MethodDelete:
			canceled = append(canceled, path.Base(request.URL.Path))
			writer.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	client := NewClient(server.URL, Auth{Token: "token"}, server.Client())
	_, err := client.UploadBatch(context.Background(), "fb", "ses", []Source{source([]byte("a")), source([]byte("b"))})
	if err == nil {
		t.Fatal("expected failure")
	}
	if len(canceled) != 2 {
		t.Fatalf("canceled=%v", canceled)
	}
}

func TestUploadBatchCancelsEveryManifestAfterInvalidCompletion(t *testing.T) {
	var canceled []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v1/file-transfers":
			_ = json.NewEncoder(writer).Encode(Batch{BatchID: "fb", Transfers: []Manifest{{TransferID: "ft_1", Size: 0, SHA256: sourceDigest(nil)}, {TransferID: "ft_2", Size: 0, SHA256: sourceDigest(nil)}}})
		case request.Method == http.MethodHead:
			writer.Header().Set("Upload-Offset", "0")
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/complete"):
			_ = json.NewEncoder(writer).Encode(map[string]any{"transfer": Manifest{TransferID: path.Base(path.Dir(request.URL.Path)), State: "published"}, "result": map[string]any{"code": "pending"}})
		case request.Method == http.MethodDelete:
			canceled = append(canceled, path.Base(request.URL.Path))
			writer.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := NewClient(server.URL+"/v1/file-transfers", Auth{Token: "token"}, server.Client())
	_, err := client.UploadBatch(context.Background(), "fb", "ses", []Source{source(nil), source(nil)})
	if err == nil {
		t.Fatal("expected invalid completion failure")
	}
	if len(canceled) != 2 {
		t.Fatalf("canceled=%v", canceled)
	}
}

func TestProactiveRefreshAppliesToBodyAndHeaderOnlyOperations(t *testing.T) {
	policy := Policy{Revision: "file-transfer-v1", MaxFileBytes: 50 << 20, MaxBatchFiles: 10, MaxBatchBytes: 500 << 20, MaxConcurrentTransfers: 2, RetentionSeconds: 604800, DeliveryTimeoutSeconds: 600, MaxPendingSpoolBytes: 1 << 30}
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Authorization") != "Bearer fresh" {
			t.Errorf("authorization=%q", request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.URL.Path == "/healthz":
			_ = json.NewEncoder(writer).Encode(map[string]any{"file_transfer_policy": policy})
		case strings.HasSuffix(request.URL.Path, "/receipt"):
			writer.WriteHeader(http.StatusNoContent)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := NewClient(server.URL+"/v1/file-transfers", Auth{Token: "expiring", ExpiresAt: time.Now().Add(10 * time.Second)}, server.Client())
	refreshes := 0
	client.RefreshAuth = func(context.Context) (Auth, error) {
		refreshes++
		return Auth{Token: "fresh", ExpiresAt: time.Now().Add(time.Minute)}, nil
	}
	if err := client.VerifyPolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if err := client.Receipt(context.Background(), "ft_1", "stored", "Paperboat Inbox/a"); err != nil {
		t.Fatal(err)
	}
	if refreshes != 1 || requests != 2 {
		t.Fatalf("refreshes=%d requests=%d", refreshes, requests)
	}
}

func TestCreateRetriesResponseLossWithSameOperationAndBody(t *testing.T) {
	calls := 0
	var operation string
	client := NewClient("https://route.example/v1/file-transfers", Auth{Token: "token"}, &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			operation = request.Header.Get("X-Paperboat-Operation-ID")
		} else if request.Header.Get("X-Paperboat-Operation-ID") != operation {
			t.Errorf("operation changed from %q to %q", operation, request.Header.Get("X-Paperboat-Operation-ID"))
		}
		body, _ := io.ReadAll(request.Body)
		if string(body) != `{"batch_id":"fb_test"}` {
			t.Errorf("body=%q", body)
		}
		if calls == 1 {
			return nil, &net.OpError{Op: "read", Net: "tcp", Err: errors.New("response lost")}
		}
		return &http.Response{StatusCode: http.StatusCreated, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"batch_id":"fb_test","transfers":[]}`)), Request: request}, nil
	})})
	var batch Batch
	if err := client.retryJSONRequest(context.Background(), http.MethodPost, client.Endpoint, operationID("create", "fb_test"), "application/json", 0, []byte(`{"batch_id":"fb_test"}`), &batch); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || batch.BatchID != "fb_test" {
		t.Fatalf("calls=%d batch=%#v", calls, batch)
	}
}

func TestEveryFileOperationRefreshesOnceAfterUnauthorized(t *testing.T) {
	operations := []string{"create", "head", "pending", "download", "complete", "status", "receipt"}
	for _, operation := range operations {
		t.Run(operation, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests++
				if request.Header.Get("Authorization") != "Bearer fresh" {
					writer.Header().Set("Content-Type", "application/json")
					writer.WriteHeader(http.StatusUnauthorized)
					_, _ = writer.Write([]byte(`{"code":"unauthorized"}`))
					return
				}
				writer.Header().Set("Content-Type", "application/json")
				switch operation {
				case "create":
					_ = json.NewEncoder(writer).Encode(Batch{BatchID: "fb_auth", Transfers: []Manifest{}})
				case "head":
					writer.Header().Set("Upload-Offset", "0")
					writer.WriteHeader(http.StatusNoContent)
				case "pending":
					_, _ = writer.Write([]byte(`{"transfers":[]}`))
				case "download":
					writer.WriteHeader(http.StatusOK)
				case "complete":
					_, _ = writer.Write([]byte(`{"transfer":{"transfer_id":"ft_1","state":"published"},"result":{"code":"published","path":"/remote/ft_1"}}`))
				case "status":
					_, _ = writer.Write([]byte(`{"transfer_id":"ft_1","state":"delivered"}`))
				case "receipt":
					writer.WriteHeader(http.StatusNoContent)
				}
			}))
			defer server.Close()
			client := NewClient(server.URL+"/v1/file-transfers", Auth{Token: "expired"}, server.Client())
			refreshes := 0
			client.RefreshAuth = func(context.Context) (Auth, error) {
				refreshes++
				return Auth{Token: "fresh", ExpiresAt: time.Now().Add(time.Minute)}, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var err error
			switch operation {
			case "create":
				var batch Batch
				err = client.retryJSONRequest(ctx, http.MethodPost, client.Endpoint, "op_create", "application/json", 0, []byte(`{}`), &batch)
			case "head":
				_, err = client.Offset(ctx, "ft_1")
			case "pending":
				_, err = client.Pending(ctx, "ses_1", 0)
			case "download":
				var response *http.Response
				response, err = client.Content(ctx, Manifest{TransferID: "ft_1", Size: 0, SHA256: strings.Repeat("a", 64)}, 0)
				if response != nil {
					_ = response.Body.Close()
				}
			case "complete":
				var completed completion
				err = client.retryJSONRequest(ctx, http.MethodPost, client.Endpoint+"/ft_1/complete", "op_complete", "", 0, nil, &completed)
			case "status":
				_, err = client.WaitReceipt(ctx, "ft_1")
			case "receipt":
				err = client.Receipt(ctx, "ft_1", "stored", "Paperboat Inbox/file")
			}
			if err != nil || refreshes != 1 || requests != 2 {
				t.Fatalf("err=%v refreshes=%d requests=%d", err, refreshes, requests)
			}
		})
	}
}
