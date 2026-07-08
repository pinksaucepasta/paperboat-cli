package upload

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPUploaderUploadsAndReturnsVMPath(t *testing.T) {
	var gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/project/api/paperboat/terminal-upload" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"vm_path":"/workspace/.paperboat/attachments/image.png"}}`))
	}))
	defer srv.Close()

	u := NewHTTPUploader(srv.URL+"/project", Auth{Method: "bearer", Token: "upload-token"})
	got, err := u.Upload(context.Background(), Image{
		Name:     "image.png",
		MimeType: "image/png",
		DataURL:  "data:image/png;base64,abc",
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if got != "/workspace/.paperboat/attachments/image.png" {
		t.Fatalf("path = %q", got)
	}
	if gotAuth != "Bearer upload-token" {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotBody["name"] != "image.png" || gotBody["mime_type"] != "image/png" || gotBody["data_url"] != "data:image/png;base64,abc" {
		t.Fatalf("body = %#v", gotBody)
	}
}

func TestHTTPUploaderRequiresAbsoluteVMPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"path":"relative.png"}`))
	}))
	defer srv.Close()

	_, err := NewHTTPUploader(srv.URL, Auth{}).Upload(context.Background(), Image{Name: "image.png"})
	if err == nil {
		t.Fatal("expected absolute VM path error")
	}
}
