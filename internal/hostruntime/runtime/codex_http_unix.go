//go:build darwin || linux || windows

package runtime

import (
	"net/http"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/codexsession"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/server"
)

func hostCodexHTTPHandler(manager *codexsession.Manager, authorizer server.AuthorizerFactory) (http.Handler, error) {
	if manager == nil {
		return nil, nil
	}
	mux := http.NewServeMux()
	handler, err := codexsession.NewHandler(codexsession.HandlerConfig{Manager: manager, Authorizer: authorizer})
	if err != nil {
		return nil, err
	}
	management, err := codexsession.NewManagementHandler(manager, authorizer)
	if err != nil {
		return nil, err
	}
	mux.Handle("/v1/codex-sessions/{session_id}/ws", handler)
	mux.Handle("POST /v1/codex-sessions/{session_id}", management)
	mux.Handle("POST /v1/codex-sessions/{session_id}/renew", management)
	mux.Handle("GET /v1/codex-sessions/{session_id}/directories", management)
	mux.Handle("DELETE /v1/codex-sessions/{session_id}", management)
	return mux, nil
}
