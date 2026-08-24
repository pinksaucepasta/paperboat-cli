package localdaemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/localapi"
)

type rotatingAuthSource struct {
	mu    sync.Mutex
	calls int
}

func (s *rotatingAuthSource) Refresh() (config.Credential, error) {
	return s.Credential()
}

func (s *rotatingAuthSource) Credential() (config.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return config.Credential{AccessToken: fmt.Sprintf("token-%d", s.calls)}, nil
}

func TestAuthenticatedMachineSourceLoadsCredentialForEveryRefresh(t *testing.T) {
	var mu sync.Mutex
	var authorizations []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		authorizations = append(authorizations, request.Header.Get("Authorization"))
		mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"items":[],"pagination":{"limit":200,"offset":0,"total":0,"next_offset":null}}}`))
	}))
	defer server.Close()
	auth := &rotatingAuthSource{}
	source := AuthenticatedMachineSource{ServerURL: server.URL, Auth: auth}
	for range 2 {
		if _, err := source.ListUserMachines(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(authorizations) != 2 || authorizations[0] != "Bearer token-1" || authorizations[1] != "Bearer token-2" {
		t.Fatalf("authorizations=%v", authorizations)
	}
}

func TestAuthenticatedMachineSourceRunsAutomaticPeerApprovalBeforePublishing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/machines" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"items":[],"pagination":{"limit":200,"offset":0,"total":0,"next_offset":null}}}`))
	}))
	defer server.Close()

	wantErr := errors.New("automatic approval failed")
	calls := 0
	source := AuthenticatedMachineSource{
		ServerURL: server.URL,
		Auth:      &rotatingAuthSource{},
		AutoApprovePeerEnrollments: func(ctx context.Context, client *api.Client, machines []api.UserMachine) error {
			calls++
			if ctx == nil || client == nil || machines == nil || len(machines) != 0 {
				t.Fatalf("callback context=%v client=%v machines=%v", ctx, client, machines)
			}
			return wantErr
		},
	}
	if _, err := source.ListUserMachines(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("automatic approval error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("automatic approval calls = %d", calls)
	}
}

func TestIssuePeerStreamRefreshesRejectedCredentialOnce(t *testing.T) {
	expires := time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	var operations []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			OperationID string `json:"operation_id"`
		}
		_ = json.NewDecoder(request.Body).Decode(&body)
		operations = append(operations, body.OperationID)
		writer.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") == "Bearer token-1" {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = writer.Write([]byte(`{"error":{"code":"unauthenticated","message":"expired"}}`))
			return
		}
		_, _ = fmt.Fprintf(writer, `{"data":{"operation_id":"operation_1","environment":{"id":"environment_1","kind":"byod","resource_id":"machine_1","state":"ready","root":"/root"},"endpoints":{"quic":"quic://example.test:443","wss":"wss://example.test/v1/runtime"},"auth":{"method":"bearer","token":"operation-token","expires_at":%q,"scopes":["exec:operate"]},"expires_at":%q}}`, expires, expires)
	}))
	defer server.Close()
	source := AuthenticatedMachineSource{ServerURL: server.URL, Auth: &rotatingAuthSource{}, SourceMachineID: "source_1"}
	request := localapi.PeerStreamRequest{Schema: localapi.PeerStreamSchemaV1, Consumer: "exec", MachineID: "machine_1", EnvironmentID: "environment_1", MachineGeneration: 1, OperationID: "operation_1", Deadline: time.Now().UTC().Add(time.Minute), MaximumBytes: 1024, Transport: "a", Payload: json.RawMessage(`{"operation_id":"operation_1"}`)}
	result, err := source.IssuePeerStream(context.Background(), request)
	if err != nil || result.Credential != "operation-token" || !reflect.DeepEqual(operations, []string{"operation_1", "operation_1"}) {
		t.Fatalf("result=%+v operations=%v err=%v", result, operations, err)
	}
}

func TestAuthenticatedMachineSourceReconcilesSSHAuthority(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/machines":
			_, _ = writer.Write([]byte(`{"data":{"items":[{"id":"machine_1","display_name":"Studio","alias":"studio","state":"active","online":true,"installation_generation":4}],"pagination":{"limit":200,"offset":0,"total":1,"next_offset":null}}}`))
		case "/v1/machines/machine_1/ssh-target":
			_, _ = writer.Write([]byte(`{"data":{"type":"machine_target","version":1,"machine_id":"machine_1","machine_generation":4,"os_user":"deploy","port":22,"reconciliation_version":2}}`))
		case "/v1/machines/machine_1/ssh-host-keys":
			_, _ = writer.Write([]byte(`{"data":{"type":"host_key_set","version":1,"set_id":"sshks_test","machine_id":"machine_1","machine_generation":4,"observation_generation":3,"fingerprint":"SHA256:test","keys":["ssh-ed25519 AAAA test"],"state":"active","reconciliation_version":5}}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	machines, err := (AuthenticatedMachineSource{ServerURL: server.URL, Auth: &rotatingAuthSource{}}).ListUserMachines(context.Background())
	if err != nil || len(machines) != 1 || machines[0].SSHAuthority.TargetGeneration != 4 || machines[0].SSHAuthority.HostKeyGeneration != 4 {
		t.Fatalf("machines=%+v err=%v", machines, err)
	}
}
