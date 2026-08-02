package serve

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSingleFileSupportsRangeAndDisposition(t *testing.T) {
	file := filepath.Join(t.TempDir(), "report.bin")
	if err := os.WriteFile(file, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := ResolveSource(file)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(HandlerConfig{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Range", "bytes=2-5")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusPartialContent || recorder.Body.String() != "2345" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Content-Disposition") != "attachment" || recorder.Header().Get("X-Robots-Tag") == "" {
		t.Fatalf("headers = %#v", recorder.Header())
	}
}

func TestDirectoryIndexNoListingAndSPA(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "index.html"), "home")
	mustWrite(t, filepath.Join(root, "app.js"), "asset")
	mustWrite(t, filepath.Join(root, "empty", "hidden.txt"), "hidden")
	source, _ := ResolveSource(root)
	handler, err := NewHandler(HandlerConfig{Source: source, SPA: true})
	if err != nil {
		t.Fatal(err)
	}
	assertResponse(t, handler, "/", "", http.StatusOK, "home")
	assertResponse(t, handler, "/dashboard", "text/html", http.StatusOK, "home")
	assertResponse(t, handler, "/missing.js", "text/html", http.StatusNotFound, "404 page not found\n")
	plainHandler, err := NewHandler(HandlerConfig{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	assertResponse(t, plainHandler, "/empty/", "", http.StatusNotFound, "404 page not found\n")
}

func TestDirectoryDeniesDotfilesTraversalAndSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	mustWrite(t, filepath.Join(root, "index.html"), "home")
	mustWrite(t, filepath.Join(root, ".secret"), "dotfile")
	mustWrite(t, filepath.Join(root, "secret.txt"), "inside-but-traversal-must-still-fail")
	mustWrite(t, outside, "outside")
	if err := os.Symlink(outside, filepath.Join(root, "escape.txt")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}
	source, _ := ResolveSource(root)
	handler, err := NewHandler(HandlerConfig{Source: source})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/.secret", "/../secret.txt", "/escape.txt", "/.well-known/value"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound || strings.Contains(recorder.Body.String(), "outside") || strings.Contains(recorder.Body.String(), "dotfile") {
			t.Errorf("%s response = %d %q", target, recorder.Code, recorder.Body.String())
		}
	}
}

func TestSingleFileSupportsConditionalRequest(t *testing.T) {
	file := filepath.Join(t.TempDir(), "report.txt")
	mustWrite(t, file, "report")
	source, _ := ResolveSource(file)
	handler, _ := NewHandler(HandlerConfig{Source: source})
	info, _ := os.Stat(file)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("If-Modified-Since", info.ModTime().UTC().Format(http.TimeFormat))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotModified || recorder.Body.Len() != 0 {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestSourceReplacementReturnsGone(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "page.html")
	mustWrite(t, file, "original")
	source, _ := ResolveSource(file)
	handler, _ := NewHandler(HandlerConfig{Source: source})
	if err := os.Rename(file, file+".old"); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, file, "replacement")
	assertResponse(t, handler, "/", "", http.StatusGone, "source unavailable\n")
}

func TestResolvePinnedSourceRejectsReplacement(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "page.html")
	mustWrite(t, file, "original")
	source, _ := ResolveSource(file)
	identity, err := source.Identity()
	if err != nil || identity == "" {
		t.Fatalf("identity=%q err=%v", identity, err)
	}
	if _, err := ResolvePinnedSource(source.Path, source.Kind, identity); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(file, file+".old"); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, file, "replacement")
	if _, err := ResolvePinnedSource(source.Path, source.Kind, identity); !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("error = %v", err)
	}
}

func TestServerBindsLoopbackAndServes(t *testing.T) {
	server, err := Start(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, "ok") }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(nil) })
	response, err := http.Get("http://" + server.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if string(body) != "ok" || server.Port() == 0 {
		t.Fatalf("port=%d body=%q", server.Port(), body)
	}
}

func assertResponse(t *testing.T, handler http.Handler, target, accept string, status int, body string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != status || recorder.Body.String() != body {
		t.Fatalf("%s response = %d %q", target, recorder.Code, recorder.Body.String())
	}
}

func mustWrite(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
