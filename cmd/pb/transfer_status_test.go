package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	clienttransfer "github.com/pinksaucepasta/paperboat/internal/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

func TestTransferStatusJSONPreservesSourceVisibleEncryptedManifest(t *testing.T) {
	createdAt := time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC)
	want := clienttransfer.Manifest{
		TransferID: "fb_cli_status.0", BatchID: "fb_cli_status", SourceMachineID: "machine_source", DestinationMachineID: "machine_host", InitiatingUserID: "user_1", SessionID: "session_1",
		Basename: "payload.txt", Size: 17, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CommittedOffset: 17, CommittedChunk: 1, State: "published", ResultCode: "published", ReceiptPath: "Paperboat Inbox/payload (2).txt", CreatedAt: createdAt, ExpiresAt: createdAt.Add(7 * 24 * time.Hour),
	}
	transferServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/file-transfers/"+want.TransferID || request.Header.Get("Authorization") != "Bearer transfer-token" {
			t.Errorf("unexpected transfer request: %s %s auth=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(want)
	}))
	defer transferServer.Close()

	previousTransferClient := newTransferClient
	newTransferClient = func(target *resolver.FileTransferTarget) *clienttransfer.Client {
		if target == nil || target.SourceMachineID != "machine_source" || target.DestinationMachineID != "machine_host" || target.InitiatingUserID != "user_1" || target.Auth.Token != "transfer-token" {
			t.Errorf("transfer target=%+v", target)
			return nil
		}
		return clienttransfer.NewClient(transferServer.URL+"/v1/file-transfers", clienttransfer.Auth{Token: target.Auth.Token}, clienttransfer.Binding{SourceMachineID: target.SourceMachineID, DestinationMachineID: target.DestinationMachineID, InitiatingUserID: target.InitiatingUserID}, transferServer.Client())
	}
	t.Cleanup(func() { newTransferClient = previousTransferClient })

	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method + " " + request.URL.Path {
		case "GET /v1/machines":
			writeAPIData(t, writer, api.UserMachinePage{Items: []api.UserMachine{{ID: "machine_host", EnvironmentID: "environment_host", DisplayName: "hn", Alias: "hn", State: "ready", Online: true, Platform: "linux", Architecture: "amd64", WorkspaceRoot: "/root", InstallationGeneration: 1}}, Pagination: api.Pagination{}})
		case "POST /v1/machines/machine_host/file-transfer-descriptor":
			body, _ := io.ReadAll(request.Body)
			if !bytes.Contains(body, []byte(`"source_machine_id":"machine_source"`)) {
				t.Errorf("descriptor body=%s", body)
			}
			writeAPIData(t, writer, api.FileTransfer{Endpoint: "https://machine.example.test/v1/file-transfers", SourceMachineID: "machine_source", DestinationMachineID: "machine_host", InitiatingUserID: "user_1", Auth: api.AuthMaterial{Method: "bearer", Token: "transfer-token", ExpiresAt: time.Now().Add(time.Hour)}})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer backend.Close()

	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	writeTestProfile(t, root, configPath, backend.URL)
	runtimeRoot := filepath.Join(root, "runtime")
	t.Setenv("PAPERBOAT_RUNTIME_STATE_ROOT", runtimeRoot)
	identityStore, err := identity.Open(identity.Config{StateRoot: runtimeRoot})
	if err != nil {
		t.Fatal(err)
	}
	inboxPath := filepath.Join(root, "Paperboat Inbox")
	if err := os.MkdirAll(inboxPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := identityStore.SaveRegistration(identity.Registration{ServerURL: backend.URL, MachineID: "machine_source", EnvironmentID: "environment_source", PublicKeyID: identityStore.Current().ID, PublicIdentityKey: base64.RawURLEncoding.EncodeToString(identityStore.Current().Public()), InboxPath: inboxPath, InstallationGeneration: 1, SetupRoles: []string{"interactive"}, UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--config", configPath, "transfer", "status", want.TransferID, "--on", "hn", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var output struct {
		SchemaVersion string                  `json:"schema_version"`
		OK            bool                    `json:"ok"`
		Data          clienttransfer.Manifest `json:"data"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil || output.SchemaVersion != "1.0" || !output.OK || output.Data != want {
		t.Fatalf("output=%q decoded=%+v err=%v", stdout.String(), output, err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr=%q", stderr.String())
	}
}
