package upload

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
		if gotBody["image"] != "image-bytes" || gotBody["display_filename"] != "image.png" {
			t.Fatalf("multipart body = %#v", gotBody)
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

func TestHTTPUploaderRejectsTerminalTicket(t *testing.T) {
	_, err := NewHTTPUploader("https://example.test", "/api/files/staged-images", Auth{Method: "websocket_ticket", Ticket: "ticket"}).Upload(context.Background(), Image{Name: "x.png", Bytes: []byte("x")})
	if err == nil {
		t.Fatal("expected auth scope error")
	}
}
