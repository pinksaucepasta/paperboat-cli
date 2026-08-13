package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DiagnosticUploadIntentRequestSchemaV1 = "paperboat.diagnostic-upload-intent-request/v1"
const DiagnosticUploadIntentSchemaV1 = "paperboat.diagnostic-upload-intent/v1"

type DiagnosticUploadIntentRequest struct {
	Schema        string   `json:"schema"`
	CorrelationID string   `json:"correlation_id"`
	Bytes         int64    `json:"bytes"`
	SHA256        string   `json:"sha256"`
	Categories    []string `json:"categories"`
}

type DiagnosticUploadIntent struct {
	Schema        string            `json:"schema"`
	IntentID      string            `json:"intent_id"`
	CorrelationID string            `json:"correlation_id"`
	State         string            `json:"state"`
	ExpiresAt     time.Time         `json:"expires_at"`
	UploadMethod  string            `json:"upload_method,omitempty"`
	UploadURL     string            `json:"upload_url,omitempty"`
	UploadHeaders map[string]string `json:"upload_headers,omitempty"`
}

func (c *Client) CreateDiagnosticUploadIntent(ctx context.Context, operationKey string, request DiagnosticUploadIntentRequest) (DiagnosticUploadIntent, error) {
	var result DiagnosticUploadIntent
	if request.Schema != DiagnosticUploadIntentRequestSchemaV1 || strings.TrimSpace(operationKey) == "" {
		return result, errors.New("invalid diagnostic upload intent request")
	}
	err := c.doWithHeaders(ctx, http.MethodPost, "/v1/diagnostic-upload-intents", request, &result, http.Header{"Idempotency-Key": []string{operationKey}})
	if err != nil {
		return DiagnosticUploadIntent{}, err
	}
	if err := result.validate(true); err != nil {
		return DiagnosticUploadIntent{}, err
	}
	return result, nil
}

func (c *Client) CompleteDiagnosticUploadIntent(ctx context.Context, intentID string) (DiagnosticUploadIntent, error) {
	var result DiagnosticUploadIntent
	if strings.TrimSpace(intentID) == "" {
		return result, errors.New("invalid diagnostic upload intent")
	}
	err := c.doStrict(ctx, http.MethodPost, "/v1/diagnostic-upload-intents/"+url.PathEscape(intentID)+"/complete", struct{}{}, &result)
	if err != nil {
		return DiagnosticUploadIntent{}, err
	}
	if err := result.validate(false); err != nil || result.State != "uploaded" {
		return DiagnosticUploadIntent{}, errors.New("paperboat-server returned an invalid diagnostic upload completion")
	}
	return result, nil
}

func (c *Client) UploadDiagnosticBundle(ctx context.Context, intent DiagnosticUploadIntent, content io.Reader, bytes int64) error {
	if err := intent.validate(true); err != nil || intent.State != "pending" || content == nil || bytes <= 0 {
		return errors.New("invalid diagnostic upload")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, intent.UploadURL, content)
	if err != nil {
		return err
	}
	request.ContentLength = bytes
	for name, value := range intent.UploadHeaders {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if canonical == "" || strings.ContainsAny(value, "\r\n") || forbiddenUploadHeader(canonical) {
			return errors.New("paperboat-server returned an unsafe diagnostic upload header")
		}
		if canonical == "Content-Length" {
			continue
		}
		request.Header.Set(canonical, value)
	}
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("upload diagnostic bundle: %w", err)
	}
	defer response.Body.Close()
	_, drainErr := io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("object storage rejected diagnostic bundle with HTTP %d", response.StatusCode)
	}
	return drainErr
}

func (value DiagnosticUploadIntent) validate(requireUpload bool) error {
	if value.Schema != DiagnosticUploadIntentSchemaV1 || !strings.HasPrefix(value.IntentID, "diag_") || len(value.CorrelationID) != 35 || !strings.HasPrefix(value.CorrelationID, "pb-") || value.ExpiresAt.IsZero() || value.ExpiresAt.Location() != time.UTC || value.State != "pending" && value.State != "uploaded" {
		return errors.New("paperboat-server returned an invalid diagnostic upload intent")
	}
	if requireUpload && value.State == "pending" {
		u, err := url.Parse(value.UploadURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || value.UploadMethod != http.MethodPut || len(value.UploadHeaders) == 0 || len(value.UploadHeaders) > 8 {
			return errors.New("paperboat-server returned invalid diagnostic upload authority")
		}
	}
	if value.State == "uploaded" && (value.UploadMethod != "" || value.UploadURL != "" || len(value.UploadHeaders) != 0) {
		return errors.New("paperboat-server returned upload authority for a completed diagnostic upload")
	}
	return nil
}

func forbiddenUploadHeader(name string) bool {
	switch name {
	case "Authorization", "Cookie", "Proxy-Authorization", "Proxy-Authenticate", "Set-Cookie", "Host", "Connection", "Transfer-Encoding", "Trailer", "Upgrade":
		return true
	default:
		return strings.HasPrefix(name, "X-Paperboat-")
	}
}
