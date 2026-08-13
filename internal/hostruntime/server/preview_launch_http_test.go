package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
)

type previewLauncherFunc func(context.Context, PreviewLaunchRequest) (preview.ControlRecord, error)

func (f previewLauncherFunc) Launch(ctx context.Context, input PreviewLaunchRequest) (preview.ControlRecord, error) {
	return f(ctx, input)
}

func previewLaunchHandler(t *testing.T, machineID string, launcher previewLauncherFunc) http.Handler {
	t.Helper()
	handler, err := NewPreviewLaunchHandler(PreviewLaunchHandlerConfig{
		MachineID: machineID,
		Authorizer: func(token string) (Authorizer, error) {
			if token != "valid" {
				return nil, errors.New("invalid token")
			}
			return authorizerFunc(func(_ context.Context, frame protocol.Frame) (Authorization, error) {
				if frame.Capability != "preview.launch.v1" {
					return Authorization{}, errors.New("wrong capability")
				}
				return Authorization{MachineID: "machine_1", UserID: "user_1", ClientID: "cli_1"}, nil
			}), nil
		},
		Launcher: launcher,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestPreviewLaunchHTTPAuthorizesAndReturnsConfirmedRecord(t *testing.T) {
	called := false
	handler := previewLaunchHandler(t, "machine_1", func(_ context.Context, input PreviewLaunchRequest) (preview.ControlRecord, error) {
		called = true
		if input.Name != "docs" || input.Port != 3000 || input.Duration != 3600 || input.Indefinite {
			t.Fatalf("input=%#v", input)
		}
		return preview.ControlRecord{LogicalName: input.Name, URL: "https://docs.preview.test", State: "active"}, nil
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/preview-launches", bytes.NewBufferString(`{"operation_id":"preview-op-1","name":"docs","port":3000,"duration_seconds":3600}`))
	request.Header.Set("Authorization", "Bearer valid")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !called || !bytes.Contains(response.Body.Bytes(), []byte("https://docs.preview.test")) {
		t.Fatalf("status=%d called=%v body=%s", response.Code, called, response.Body.String())
	}
	var record preview.ControlRecord
	if err := json.Unmarshal(response.Body.Bytes(), &record); err != nil || record.OperationID != "preview-op-1" {
		t.Fatalf("record=%+v error=%v", record, err)
	}
}

func TestPreviewLaunchHTTPFailsClosed(t *testing.T) {
	launcher := previewLauncherFunc(func(context.Context, PreviewLaunchRequest) (preview.ControlRecord, error) {
		t.Fatal("launcher must not be called")
		return preview.ControlRecord{}, nil
	})
	for name, tc := range map[string]struct {
		machineID string
		token     string
		body      string
		want      int
	}{
		"missing auth":  {"machine_1", "", `{"operation_id":"preview-op-1","name":"docs","port":3000,"duration_seconds":60}`, http.StatusUnauthorized},
		"wrong machine": {"machine_2", "valid", `{"operation_id":"preview-op-1","name":"docs","port":3000,"duration_seconds":60}`, http.StatusForbidden},
		"bad name":      {"machine_1", "valid", `{"operation_id":"preview-op-1","name":"../docs","port":3000,"duration_seconds":60}`, http.StatusBadRequest},
		"bad lifetime":  {"machine_1", "valid", `{"operation_id":"preview-op-1","name":"docs","port":3000}`, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			handler := previewLaunchHandler(t, tc.machineID, launcher)
			request := httptest.NewRequest(http.MethodPost, "/v1/preview-launches", bytes.NewBufferString(tc.body))
			if tc.token != "" {
				request.Header.Set("Authorization", "Bearer "+tc.token)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.want {
				t.Fatalf("status=%d want=%d", response.Code, tc.want)
			}
		})
	}
}

func TestPreviewLaunchHTTPReportsLauncherConflict(t *testing.T) {
	handler := previewLaunchHandler(t, "machine_1", func(context.Context, PreviewLaunchRequest) (preview.ControlRecord, error) {
		return preview.ControlRecord{}, errors.New("duplicate preview")
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/preview-launches", bytes.NewBufferString(`{"operation_id":"preview-op-1","name":"docs","port":3000,"indefinite":true}`))
	request.Header.Set("Authorization", "Bearer valid")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d", response.Code)
	}
}
