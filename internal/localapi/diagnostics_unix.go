package localapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

func (s *Server) serveDiagnostics(writer http.ResponseWriter, request *http.Request, requestID string) {
	if s.config.Diagnostics == nil {
		writeError(writer, http.StatusNotImplemented, requestID, "capability_required", "diagnostics are unavailable")
		return
	}
	requestCtx, cancel := context.WithTimeout(request.Context(), s.config.Timeout)
	defer cancel()
	request = request.WithContext(requestCtx)
	switch request.URL.Path {
	case "/v1/diagnostics":
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			writeError(writer, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "diagnostic snapshot method not allowed")
			return
		}
		if request.URL.RawQuery != "" || request.ContentLength != 0 || request.Header.Get("Content-Type") != "" {
			writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "diagnostic snapshot request is invalid")
			return
		}
		snapshot, err := s.config.Diagnostics.Diagnostics(request.Context())
		if err != nil || snapshot.Validate() != nil {
			writeError(writer, http.StatusServiceUnavailable, requestID, "diagnostics_unavailable", "diagnostics are unavailable")
			return
		}
		writeDiagnosticJSON(writer, requestID, snapshot)
	case "/v1/diagnostics/bugreport-marker":
		if request.Method != http.MethodPost {
			writer.Header().Set("Allow", http.MethodPost)
			writeError(writer, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "bugreport marker method not allowed")
			return
		}
		if request.URL.RawQuery != "" || request.Header.Get("Content-Type") != "application/json" || request.ContentLength < 0 || request.ContentLength > maxJSONBytes {
			writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "bugreport marker request is invalid")
			return
		}
		var marker BugreportMarker
		if err := decodeStrictJSON(io.LimitReader(request.Body, maxJSONBytes+1), &marker); err != nil || marker.Validate() != nil {
			writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "bugreport marker is invalid")
			return
		}
		if err := s.config.Diagnostics.RecordBugreportMarker(request.Context(), marker.Phase); err != nil {
			writeError(writer, http.StatusServiceUnavailable, requestID, "diagnostics_unavailable", "bugreport marker could not be recorded")
			return
		}
		writer.Header().Set("X-Paperboat-Protocol", ProtocolV1)
		writer.WriteHeader(http.StatusNoContent)
	case "/v1/bugreports":
		if request.Method != http.MethodPost {
			writer.Header().Set("Allow", http.MethodPost)
			writeError(writer, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "bugreport method not allowed")
			return
		}
		if request.URL.RawQuery != "" || request.ContentLength != 0 || request.Header.Get("Content-Type") != "" {
			writeError(writer, http.StatusBadRequest, requestID, "invalid_request", "bugreport request is invalid")
			return
		}
		bundle, err := s.config.Diagnostics.CreateBugreport(request.Context())
		if err != nil || bundle.Validate() != nil {
			writeError(writer, http.StatusServiceUnavailable, requestID, "bugreport_unavailable", "bugreport could not be created")
			return
		}
		writeDiagnosticJSON(writer, requestID, bundle)
	default:
		writeError(writer, http.StatusNotFound, requestID, "not_found", "local API resource not found")
	}
}

func writeDiagnosticJSON(writer http.ResponseWriter, requestID string, value any) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maxJSONBytes {
		writeError(writer, http.StatusServiceUnavailable, requestID, "diagnostics_unavailable", "diagnostic response is unavailable")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Paperboat-Protocol", ProtocolV1)
	_, _ = writer.Write(append(encoded, '\n'))
}
