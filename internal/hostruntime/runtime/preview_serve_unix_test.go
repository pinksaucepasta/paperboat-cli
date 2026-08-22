//go:build darwin || linux

package runtime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	servepkg "github.com/pinksaucepasta/paperboat/internal/serve"
)

func TestServeRuntimeDescriptorRoundTrip(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "site")
	if err := os.Mkdir(sourcePath, 0o700); err != nil {
		t.Fatal(err)
	}
	source, err := servepkg.ResolveSource(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := source.Identity()
	expires := time.Now().UTC().Add(time.Hour)
	descriptor := PreviewRuntimeDescriptor{
		Schema: "paperboat.preview-runtime/v1", Name: "docs", Indefinite: false, ExpiresAt: &expires,
		BindAddress:       "127.0.0.1",
		ServiceGeneration: 1,
		ServiceDefinition: filepath.Join(root, "paperboat-preview.service"),
		Serve:             &ServeRuntimeDescriptor{SourcePath: source.Path, SourceKind: source.Kind, SourceIdentity: identity, SPA: true, OwnerMode: "detached", Visibility: "private"},
	}
	path := filepath.Join(root, "descriptor.json")
	if err := writePreviewRuntimeDescriptor(path, descriptor); err != nil {
		t.Fatal(err)
	}
	loaded, err := readPreviewRuntimeDescriptor(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Schema != descriptor.Schema || loaded.Port != 0 || loaded.Serve == nil || loaded.Serve.SourcePath != source.Path || loaded.Serve.SourceIdentity != identity || !loaded.Serve.SPA {
		t.Fatalf("loaded = %#v", loaded)
	}
}

func TestServeRuntimeDescriptorRequiresCurrentSchemaFields(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "site")
	if err := os.Mkdir(sourcePath, 0o700); err != nil {
		t.Fatal(err)
	}
	source, err := servepkg.ResolveSource(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	identityValue, err := source.Identity()
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	for _, descriptor := range []PreviewRuntimeDescriptor{
		{Schema: "paperboat.preview-runtime/v1", Name: "docs", ExpiresAt: &expires, ServiceGeneration: 1, Serve: &ServeRuntimeDescriptor{SourcePath: source.Path, SourceKind: source.Kind, SourceIdentity: identityValue, OwnerMode: "detached", Visibility: "private"}},
		{Schema: "paperboat.preview-runtime/v1", Name: "docs", ExpiresAt: &expires, BindAddress: "127.0.0.1", Serve: &ServeRuntimeDescriptor{SourcePath: source.Path, SourceKind: source.Kind, SourceIdentity: identityValue, OwnerMode: "detached", Visibility: "private"}},
	} {
		path := filepath.Join(root, fmt.Sprintf("descriptor-%d.json", descriptor.ServiceGeneration))
		if err := writePreviewRuntimeDescriptor(path, descriptor); err != nil {
			t.Fatal(err)
		}
		if _, err := readPreviewRuntimeDescriptor(path); !errors.Is(err, ErrProductionInvalid) {
			t.Fatalf("descriptor=%#v error=%v", descriptor, err)
		}
	}
}

func TestDetachedServeShutdownStopsListenerAndRemovesDescriptor(t *testing.T) {
	root := t.TempDir()
	descriptorPath, expires := writeTestServeDescriptor(t, root, "docs", time.Now().UTC().Add(time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	port := make(chan uint16, 1)
	go func() {
		done <- RunProductionServeWorker(ctx, ProductionServeWorkerConfig{
			ControlURL: "https://api.paperboat.test", StateRoot: root, Name: "docs", ExpiresAt: &expires, DescriptorPath: descriptorPath,
			PreviewRunner: func(previewCtx context.Context, run servepkg.PreviewRunConfig) error {
				port <- run.Port
				if err := run.Ready(preview.ControlRecord{ID: "prv_docs", PreviewKey: "p-abcdefghijklmnopqrstuvwxyz", URL: "https://docs.preview.test", State: "ready", ExpiresAt: &expires}); err != nil {
					return err
				}
				<-previewCtx.Done()
				return previewCtx.Err()
			},
		})
	}()
	listenerPort := <-port
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(listenerPort)), 100*time.Millisecond); err == nil {
		t.Fatal("listener remains after shutdown")
	}
	if _, err := os.Stat(descriptorPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("descriptor remains after shutdown: %v", err)
	}
}

func TestDetachedPrivateServePublishesOnlyLoopbackURL(t *testing.T) {
	root := t.TempDir()
	descriptorPath, expires := writeTestServeDescriptor(t, root, "private-docs", time.Now().UTC().Add(time.Hour))
	readyPath := filepath.Join(root, "previews", "active", previewServiceInstance("private-docs")+".json")
	if err := os.Rename(descriptorPath, readyPath); err != nil {
		t.Fatal(err)
	}
	descriptorPath = readyPath
	descriptor, err := readPreviewRuntimeDescriptor(descriptorPath)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.Serve.Visibility = "private"
	descriptor.Serve.ListenPort = 0
	if err := writePreviewRuntimeDescriptor(descriptorPath, descriptor); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunProductionServeWorker(ctx, ProductionServeWorkerConfig{StateRoot: root, Name: "private-docs", ExpiresAt: &expires, DescriptorPath: descriptorPath})
	}()
	readyCtx, cancelReady := context.WithTimeout(context.Background(), 5*time.Second)
	record, err := WaitPreviewServiceReady(readyCtx, root, "private-docs")
	cancelReady()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if !strings.HasPrefix(record.URL, "http://127.0.0.1:") {
		cancel()
		t.Fatalf("URL = %q", record.URL)
	}
	response, err := http.Get(record.URL)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	response.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(descriptorPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("descriptor remains after shutdown: %v", err)
	}
}

func TestDetachedServeRevocationStopsListenerAndRemovesDescriptor(t *testing.T) {
	root := t.TempDir()
	descriptorPath, expires := writeTestServeDescriptor(t, root, "docs", time.Now().UTC().Add(time.Hour))
	revoke := make(chan struct{})
	ready := make(chan struct{})
	port := make(chan uint16, 1)
	done := make(chan error, 1)
	go func() {
		done <- RunProductionServeWorker(context.Background(), ProductionServeWorkerConfig{
			ControlURL: "https://api.paperboat.test", StateRoot: root, Name: "docs", ExpiresAt: &expires, DescriptorPath: descriptorPath,
			PreviewRunner: func(_ context.Context, run servepkg.PreviewRunConfig) error {
				port <- run.Port
				if err := run.Ready(preview.ControlRecord{ID: "prv_docs", PreviewKey: "p-abcdefghijklmnopqrstuvwxyz", URL: "https://docs.preview.test", State: "ready", ExpiresAt: &expires}); err != nil {
					return err
				}
				close(ready)
				<-revoke
				return os.Remove(descriptorPath)
			},
		})
	}()
	listenerPort := <-port
	<-ready
	close(revoke)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(listenerPort)), 100*time.Millisecond); err == nil {
		t.Fatal("listener remains after revocation")
	}
	if _, err := os.Stat(descriptorPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("descriptor remains after revocation: %v", err)
	}
}

func TestDetachedServeExpiryStopsListenerAtOriginalDeadline(t *testing.T) {
	root := t.TempDir()
	expiresAt := time.Now().UTC().Add(250 * time.Millisecond)
	descriptorPath, expires := writeTestServeDescriptor(t, root, "docs", expiresAt)
	port := make(chan uint16, 1)
	done := make(chan error, 1)
	go func() {
		done <- RunProductionServeWorker(context.Background(), ProductionServeWorkerConfig{
			ControlURL: "https://api.paperboat.test", StateRoot: root, Name: "docs", ExpiresAt: &expires, DescriptorPath: descriptorPath,
			PreviewRunner: func(previewCtx context.Context, run servepkg.PreviewRunConfig) error {
				port <- run.Port
				if err := run.Ready(preview.ControlRecord{ID: "prv_docs", PreviewKey: "p-abcdefghijklmnopqrstuvwxyz", URL: "https://docs.preview.test", State: "ready", ExpiresAt: &expires}); err != nil {
					return err
				}
				<-previewCtx.Done()
				_ = os.Remove(descriptorPath)
				return previewCtx.Err()
			},
		})
	}()
	listenerPort := <-port
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if time.Now().Before(expiresAt.Add(-30 * time.Millisecond)) {
		t.Fatal("serve stopped before its original expiry")
	}
	if _, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(listenerPort)), 100*time.Millisecond); err == nil {
		t.Fatal("listener remains after expiry")
	}
	if _, err := os.Stat(descriptorPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("descriptor remains after expiry: %v", err)
	}
}

func writeTestServeDescriptor(t *testing.T, root, name string, expires time.Time) (string, time.Time) {
	t.Helper()
	sourcePath := filepath.Join(root, "site")
	if err := os.Mkdir(sourcePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "index.html"), []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := servepkg.ResolveSource(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	identityValue, err := source.Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "previews", "active", name+".json")
	descriptor := PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: name, BindAddress: "127.0.0.1", ServiceGeneration: 1, ExpiresAt: &expires, Serve: &ServeRuntimeDescriptor{SourcePath: source.Path, SourceKind: source.Kind, SourceIdentity: identityValue, OwnerMode: "detached", Visibility: "public"}}
	if err := writePreviewRuntimeDescriptor(path, descriptor); err != nil {
		t.Fatal(err)
	}
	return path, expires
}

func TestRevokeProductionPreviewByNameUsesAuthenticatedControlFlow(t *testing.T) {
	root := t.TempDir()
	removed := false
	machineToken := strings.Repeat("m", 40)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/previews/credentials":
			if r.Header.Get("Authorization") != "Bearer "+machineToken || r.Header.Get("X-Paperboat-Machine-Proof") == "" {
				t.Error("preview credential request was not machine-authenticated")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"credential": strings.Repeat("p", 40), "expires_at": time.Now().UTC().Add(time.Hour)}})
		case "/v1/previews/operations":
			if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("p", 40) || r.Header.Get("X-Paperboat-Machine-Identity") != machineToken || r.Header.Get("X-Paperboat-Machine-Proof") == "" {
				t.Error("preview operation was not authenticated")
			}
			var input map[string]any
			_ = json.NewDecoder(r.Body).Decode(&input)
			record := map[string]any{"id": "prv_docs", "environment_id": "env_local", "logical_name": "docs", "preview_key": "p-abcdefghijklmnopqrstuvwxyz", "url": "https://docs.preview.test", "target_port": 3000, "state": "ready"}
			if input["action"] == "list" {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{record}})
				return
			}
			if input["action"] != "remove" || input["logical_name"] != "docs" {
				t.Errorf("unexpected operation: %#v", input)
			}
			removed = true
			record["state"] = "removed"
			_ = json.NewEncoder(w).Encode(map[string]any{"data": record})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	store, err := identity.Open(identity.Config{StateRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	key := store.Current()
	if err := store.SaveRegistration(identity.Registration{ServerURL: server.URL, MachineID: "machine_local", EnvironmentID: "env_local", PublicKeyID: key.ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(key.Public()), InboxPath: filepath.Join(root, "Inbox"), InstallationGeneration: 1, SetupMode: "client", UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveMachineControl(identity.MachineControl{MachineID: "machine_local", EnvironmentID: "env_local", InstallationGeneration: 1, Credential: machineToken, ExpiresAt: time.Now().UTC().Add(time.Hour), KeyID: key.ID}); err != nil {
		t.Fatal(err)
	}
	if err := revokeProductionPreviewByName(context.Background(), server.URL, root, "docs", server.Client().Transport); err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("active preview was not revoked")
	}
}

func TestServeWorkerRejectsReplacedSourceBeforeListener(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "report.html")
	if err := os.WriteFile(sourcePath, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, _ := servepkg.ResolveSource(sourcePath)
	identity, _ := source.Identity()
	expires := time.Now().UTC().Add(time.Hour)
	descriptorPath := filepath.Join(root, "descriptor.json")
	descriptor := PreviewRuntimeDescriptor{
		Schema: "paperboat.preview-runtime/v1", Name: "report", BindAddress: "127.0.0.1", ServiceGeneration: 1, ExpiresAt: &expires,
		Serve: &ServeRuntimeDescriptor{SourcePath: source.Path, SourceKind: source.Kind, SourceIdentity: identity, OwnerMode: "detached", Visibility: "private"},
	}
	if err := writePreviewRuntimeDescriptor(descriptorPath, descriptor); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(sourcePath, sourcePath+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := RunProductionServeWorker(context.Background(), ProductionServeWorkerConfig{
		ControlURL: "https://api.paperboat.test", StateRoot: root, Name: "report", ExpiresAt: &expires, DescriptorPath: descriptorPath,
	})
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Stat(descriptorPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("descriptor remains after invalid source cleanup: %v", err)
	}
}
