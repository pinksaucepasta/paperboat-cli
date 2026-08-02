package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	runtimeconfig "github.com/pinksaucepasta/paperboat/internal/hostruntime/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
)

type receiveServiceStub struct{}

func (receiveServiceStub) Start(context.Context) error    { return nil }
func (receiveServiceStub) Shutdown(context.Context) error { return nil }
func (receiveServiceStub) Capabilities() []string         { return nil }

type receivePreviewLauncher struct{}

func (receivePreviewLauncher) Launch(context.Context, server.PreviewLaunchRequest) (preview.ControlRecord, error) {
	return preview.ControlRecord{}, nil
}

func TestReceiveCoordinatorExposesOnlyReceiveRoutes(t *testing.T) {
	root := t.TempDir()
	host, err := NewReceiveCoordinator(context.Background(), HostConfig{
		Runtime:       runtimeconfig.Config{Profile: runtimeconfig.BYOD, StateRoot: root, Version: "test", Limits: runtimeconfig.DefaultLimits, Resources: runtimeconfig.DefaultResources},
		ListenAddress: "127.0.0.1:0", WorkspaceRoot: root, InboxPath: filepath.Join(root, "Inbox"), MachineID: "machine_test",
	}, HostDependencies{
		Authorizer: func(string) (server.Authorizer, error) { return hostAuthorizer{}, nil },
		Connector:  receiveServiceStub{}, RuntimeObservationService: receiveServiceStub{},
		PreviewLauncher: receivePreviewLauncher{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodPost, "/v1/file-transfers", http.StatusUnauthorized},
		{http.MethodPost, "/v1/preview-launches", http.StatusUnauthorized},
		{http.MethodGet, "/v1/runtime", http.StatusNotFound},
		{http.MethodPost, "/v1/codex-sessions/session_1", http.StatusNotFound},
		{http.MethodGet, "/v1/codex-sessions/session_1/ws", http.StatusNotFound},
	} {
		response := httptest.NewRecorder()
		host.handler.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, nil))
		if response.Code != tc.want {
			t.Errorf("%s %s status=%d, want %d", tc.method, tc.path, response.Code, tc.want)
		}
	}
	if host.sessions != nil {
		t.Fatal("receive coordinator initialized terminal sessions")
	}
}
