package upload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/telemetry"
)

type eventSink struct{ events []telemetry.Event }

func (s *eventSink) Record(e telemetry.Event) { s.events = append(s.events, e) }

func TestUploadRecordsMetadataOnlyResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"path":"/workspace/.staged/image.png"}`))
	}))
	defer srv.Close()

	sink := &eventSink{}
	times := []time.Time{time.Unix(10, 0), time.Unix(10, 12_000_000)}
	u := NewHTTPUploader(srv.URL, "/upload", Auth{Method: "bearer", Token: "secret"})
	u.ConfigureTelemetry(sink, "prj_1", "env_1")
	u.Now = func() time.Time { v := times[0]; times = times[1:]; return v }
	_, err := u.Upload(context.Background(), Image{Name: "private.png", Bytes: []byte("abc"), MimeType: "image/png"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("events = %d", len(sink.events))
	}
	e := sink.events[0]
	if e.Name != "upload.result" || e.ProjectID != "prj_1" || e.EnvironmentID != "env_1" || e.Outcome != "success" || e.SizeBytes != 3 || e.LatencyMS != 12 {
		t.Fatalf("event = %+v", e)
	}
}

func TestHTTPUploaderUploadsAndReturnsVMPath(t *testing.T) {
	var gotAuth string
	var gotBody = map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/project/api/files/staged-images" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		mr, err := r.MultipartReader()
		if err != nil {
			t.Fatal(err)
		}
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(part)
			gotBody[part.FormName()] = string(data)
		}
		if gotBody["file"] != "image-bytes" {
			t.Fatalf("multipart body = %#v", gotBody)
		}
		for _, header := range []string{"X-Paperboat-Request-ID", "X-Paperboat-Operation-ID", "X-Paperboat-Deadline-Ms", "X-Paperboat-File-Name", "X-Paperboat-File-Mime", "X-Paperboat-File-Size", "X-Paperboat-File-Sha256"} {
			if r.Header.Get(header) == "" {
				t.Fatalf("missing canonical upload header %s", header)
			}
		}
		digest := sha256.Sum256([]byte("image-bytes"))
		if r.Header.Get("X-Paperboat-File-Name") != "image.png" || r.Header.Get("X-Paperboat-File-Mime") != "image/png" || r.Header.Get("X-Paperboat-File-Size") != "11" || r.Header.Get("X-Paperboat-File-Sha256") != hex.EncodeToString(digest[:]) {
			t.Fatalf("canonical upload metadata changed: %#v", r.Header)
		}
		if _, ok := gotBody["display_filename"]; ok {
			t.Fatalf("optional display_filename must be omitted: %#v", gotBody)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"path":"/workspace/project/.paperboat/uploads/image.png","mime_type":"image/png","size_bytes":11,"sha256":"abc","expires_at":"2026-07-17T12:00:00Z"}`))
	}))
	defer srv.Close()

	u := NewHTTPUploader(srv.URL, "/project/api/files/staged-images", Auth{Method: "bearer", Token: "upload-token"})
	got, err := u.Upload(context.Background(), Image{
		Name:     "image.png",
		MimeType: "image/png",
		Bytes:    []byte("image-bytes"),
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if got != "/workspace/project/.paperboat/uploads/image.png" {
		t.Fatalf("path = %q", got)
	}
	if gotAuth != "Bearer upload-token" {
		t.Fatalf("auth = %q", gotAuth)
	}
	_ = gotBody
}

func TestHTTPUploaderSerializesConcurrentAuthRefresh(t *testing.T) {
	var oldRequests atomic.Int32
	var refreshes atomic.Int32
	oldRequestsReady := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "Bearer old-token" {
			if oldRequests.Add(1) == 2 {
				close(oldRequestsReady)
			}
			<-oldRequestsReady
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"unauthenticated","message":"expired"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"path":"/workspace/staged.png"}`))
	}))
	defer srv.Close()

	u := NewHTTPUploader(srv.URL, "/upload", Auth{Method: "bearer", Token: "old-token"})
	u.RefreshAuth = func(context.Context) (Auth, error) {
		refreshes.Add(1)
		return Auth{Method: "bearer", Token: "new-token"}, nil
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := u.Upload(context.Background(), Image{Name: "image.png", Bytes: []byte("bytes")})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if refreshes.Load() != 1 {
		t.Fatalf("refreshes = %d, want 1", refreshes.Load())
	}
}

func TestHTTPUploaderRequiresAbsoluteVMPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"path":"relative.png"}`))
	}))
	defer srv.Close()

	_, err := NewHTTPUploader(srv.URL, "/api/files/staged-images", Auth{}).Upload(context.Background(), Image{Name: "image.png"})
	if err == nil {
		t.Fatal("expected absolute VM path error")
	}
}

func TestHTTPUploaderReturnsStructuredError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		_, _ = w.Write([]byte(`{"error":{"code":"unsupported_media_type","message":"only PNG is allowed"}}`))
	}))
	defer srv.Close()

	_, err := NewHTTPUploader(srv.URL, "/api/files/staged-images", Auth{Method: "bearer", Token: "token"}).Upload(context.Background(), Image{Name: "x.png", Bytes: []byte("x")})
	var stagedErr *Error
	if !errors.As(err, &stagedErr) {
		t.Fatalf("error type = %T, want *upload.Error", err)
	}
	if stagedErr.Code != "unsupported_media_type" {
		t.Fatalf("code = %q", stagedErr.Code)
	}
}

func TestHTTPUploaderReturnsCanonicalHelperError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"invalid_request","message":"Bad Request","requestId":"req_123","retryable":false,"details":{"stage":"multipart_metadata"}}`))
	}))
	defer srv.Close()

	_, err := NewHTTPUploader(srv.URL, "/api/files/staged-images", Auth{Method: "bearer", Token: "token"}).Upload(context.Background(), Image{Name: "x.png", MimeType: "image/png", Bytes: []byte("x")})
	var stagedErr *Error
	if !errors.As(err, &stagedErr) {
		t.Fatalf("error type = %T, want *upload.Error", err)
	}
	if stagedErr.Code != "invalid_request" || stagedErr.Message != "Bad Request" || stagedErr.RequestID != "req_123" || stagedErr.Stage != "multipart_metadata" || stagedErr.Retryable {
		t.Fatalf("error = %+v", stagedErr)
	}
}

func TestHTTPUploaderRejectsTerminalTicket(t *testing.T) {
	_, err := NewHTTPUploader("https://example.test", "/api/files/staged-images", Auth{Method: "websocket_ticket", Ticket: "ticket"}).Upload(context.Background(), Image{Name: "x.png", Bytes: []byte("x")})
	if err == nil {
		t.Fatal("expected auth scope error")
	}
}
