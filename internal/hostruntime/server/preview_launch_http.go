package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
)

var previewLaunchName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

type PreviewLaunchRequest struct {
	OperationID string `json:"operation_id"`
	Name        string `json:"name"`
	Port        uint16 `json:"port"`
	Duration    int64  `json:"duration_seconds,omitempty"`
	Indefinite  bool   `json:"indefinite,omitempty"`
}

type PreviewLaunchError struct {
	Code         string `json:"code"`
	Message      string `json:"message"`
	Retryable    bool   `json:"retryable"`
	MachineID    string `json:"machine_id,omitempty"`
	Name         string `json:"name,omitempty"`
	Port         uint16 `json:"port,omitempty"`
	StateCreated bool   `json:"state_created"`
	Cleanup      string `json:"cleanup"`
	Recovery     string `json:"recovery"`
}

func (e *PreviewLaunchError) Error() string { return e.Message }

type PreviewLauncher interface {
	Launch(context.Context, PreviewLaunchRequest) (preview.ControlRecord, error)
}

type PreviewLaunchHandlerConfig struct {
	Authorizer AuthorizerFactory
	Launcher   PreviewLauncher
	MachineID  string
}

func NewPreviewLaunchHandler(config PreviewLaunchHandlerConfig) (http.Handler, error) {
	if config.Authorizer == nil || config.Launcher == nil || config.MachineID == "" {
		return nil, errors.New("invalid preview launch handler configuration")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		token, ok := bearerToken(r.Header.Values("Authorization"))
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authorizer, err := config.Authorizer(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if closer, ok := authorizer.(interface{ CloseAuthorization() }); ok {
			defer closer.CloseAuthorization()
		}
		authz, err := authorizer.Authorize(r.Context(), protocol.Frame{Capability: "preview.launch.v1"})
		if err != nil || authz.MachineID != config.MachineID || authz.UserID == "" || authz.ClientID == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var input PreviewLaunchRequest
		decoder := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(input.OperationID) < 8 || len(input.OperationID) > 128 || !previewLaunchName.MatchString(input.Name) || input.Port == 0 || input.Indefinite == (input.Duration > 0) || input.Duration < 0 || input.Duration > int64((365*24*time.Hour)/time.Second) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		launchCtx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		record, err := config.Launcher.Launch(launchCtx, input)
		if err != nil {
			launchError := &PreviewLaunchError{Code: "preview_runner_launch_failure", Message: "Preview runner failed to launch.", Retryable: true, Cleanup: "complete", Recovery: "Retry the preview launch.", MachineID: config.MachineID, Name: input.Name, Port: input.Port}
			if errors.As(err, &launchError) {
				launchError.MachineID, launchError.Name, launchError.Port = config.MachineID, input.Name, input.Port
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": launchError})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(record)
	}), nil
}
