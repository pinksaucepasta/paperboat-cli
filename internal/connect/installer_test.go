package connect

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExtractTarGzRejectsTraversalAndPreservesExecutableMode(t *testing.T) {
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "papercode", Mode: 0o700, Size: 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("exec")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := extractTarGz(archive.Bytes(), destination); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(destination, "papercode"))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("info=%v err=%v", info, err)
	}
}

func TestInstallerVerifiesAndInstallsAllComponents(t *testing.T) {
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	files := map[string][]byte{"paperboat-connect": []byte("connector"), "papercode": []byte("papercode"), "agentunnel": []byte("agentunnel")}
	server := signedReleaseServer(t, private, files)
	defer server.Close()
	installed := t.TempDir()
	manifest, err := (Installer{HTTP: server.Client(), PublicKey: pub, OS: runtime.GOOS, Arch: runtime.GOARCH}).Install(context.Background(), InstallRequest{ManifestURL: server.URL + "/manifest.json", InstallDir: installed, Components: []string{"paperboat-connect", "papercode", "agentunnel"}})
	if err != nil || manifest.Version != "1.2.3" {
		t.Fatalf("manifest=%+v err=%v", manifest, err)
	}
	for component, contents := range files {
		got, readErr := os.ReadFile(filepath.Join(installed, component))
		if readErr != nil || string(got) != string(contents) {
			t.Fatalf("%s=%q err=%v", component, got, readErr)
		}
	}
}

func TestInstallerRestoresPreviousReleaseAfterActivationFailure(t *testing.T) {
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	server := signedReleaseServer(t, private, map[string][]byte{"paperboat-connect": []byte("new")})
	defer server.Close()
	installed := t.TempDir()
	if err := os.WriteFile(filepath.Join(installed, "paperboat-connect"), []byte("old"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := (Installer{HTTP: server.Client(), PublicKey: pub, OS: runtime.GOOS, Arch: runtime.GOARCH}).Install(context.Background(), InstallRequest{ManifestURL: server.URL + "/manifest.json", InstallDir: installed, Components: []string{"paperboat-connect"}, Activate: func() error { return errors.New("activation failed") }})
	if !errors.Is(err, ErrInstallationFailed) {
		t.Fatalf("err=%v", err)
	}
	got, readErr := os.ReadFile(filepath.Join(installed, "paperboat-connect"))
	if readErr != nil || string(got) != "old" {
		t.Fatalf("restored=%q err=%v", got, readErr)
	}
}

func signedReleaseServer(t *testing.T, private ed25519.PrivateKey, files map[string][]byte) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest.json" {
			artifacts := make([]Artifact, 0, len(files))
			for component, contents := range files {
				sum := sha256.Sum256(contents)
				artifacts = append(artifacts, Artifact{Component: component, OS: runtime.GOOS, Arch: runtime.GOARCH, URL: server.URL + "/" + component, SHA256: hex.EncodeToString(sum[:])})
			}
			payload, _ := json.Marshal(struct {
				Version   string     `json:"version"`
				Artifacts []Artifact `json:"artifacts"`
			}{Version: "1.2.3", Artifacts: artifacts})
			envelope, _ := json.Marshal(Manifest{Version: "1.2.3", Artifacts: artifacts, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))})
			_, _ = w.Write(envelope)
			return
		}
		if contents, ok := files[r.URL.Path[1:]]; ok {
			_, _ = w.Write(contents)
			return
		}
		http.NotFound(w, r)
	}))
	return server
}
