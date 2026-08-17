//go:build darwin || linux

package selfupdate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveBuildsPlatformDescriptor(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/current.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"schema":"paperboat.release-current/v1","version":"2026.08.18.1"}`))
	}))
	defer server.Close()
	target, err := Resolve(context.Background(), server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if target.Version != "2026.08.18.1" || target.Platform != runtime.GOOS || target.Architecture != runtime.GOARCH || target.RepositoryURL != server.URL+"/tuf" || target.TargetPath != "pb-"+runtime.GOOS+"-"+runtime.GOARCH {
		t.Fatalf("target=%+v", target)
	}
}

func TestResolveRejectsMalformedManifest(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"schema":"paperboat.release-current/v1","version":"latest"}`))
	}))
	defer server.Close()
	if _, err := Resolve(context.Background(), server.URL, server.Client()); err == nil {
		t.Fatal("malformed release version was accepted")
	}
}

func TestCompareVersions(t *testing.T) {
	if comparison, err := CompareVersions("2026.08.18.1", "2026.08.18.0"); err != nil || comparison != 1 {
		t.Fatalf("comparison=%d error=%v", comparison, err)
	}
	if _, err := CompareVersions("latest", "2026.08.18.0"); err == nil {
		t.Fatal("malformed version was accepted")
	}
}

func TestInstallCLIAtomicallyReplacesExecutable(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	current := filepath.Join(directory, "pb")
	staged := filepath.Join(directory, "verified")
	copyExecutable(t, executable, current)
	copyExecutable(t, executable, staged)
	if err := InstallCLI(current, staged); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(current + ".update-rollback"); err != nil {
		t.Fatalf("rollback binary missing: %v", err)
	}
}

func copyExecutable(t *testing.T, source, destination string) {
	t.Helper()
	body, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, body, 0o755); err != nil {
		t.Fatal(err)
	}
}
