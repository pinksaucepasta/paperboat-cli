package upload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pujan-modha/paperboat-cli/internal/telemetry"
)

type Auth struct {
	Method string
	Token  string
	Ticket string
}

type HTTPUploader struct {
	BaseURL       string
	Path          string
	HTTPClient    *http.Client
	RefreshAuth   func(context.Context) (Auth, error)
	Now           func() time.Time
	authMu        sync.RWMutex
	refreshMu     sync.Mutex
	auth          Auth
	telemetry     telemetry.Sink
	projectID     string
	environmentID string
}

func (u *HTTPUploader) ConfigureTelemetry(sink telemetry.Sink, projectID, environmentID string) {
	u.telemetry = sink
	u.projectID = projectID
	u.environmentID = environmentID
}

// Error is the structured error envelope returned by papercode's staged-image
// endpoint. Code lets callers distinguish retryable workspace/storage failures
// from user input and authorization failures without parsing text.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return "upload failed: " + e.Code
	}
	if e.Code == "" {
		return "upload failed: " + e.Message
	}
	return "upload failed (" + e.Code + "): " + e.Message
}

func NewHTTPUploader(baseURL, uploadPath string, auth Auth) *HTTPUploader {
	return &HTTPUploader{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Path:    uploadPath,
		auth:    auth,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (u *HTTPUploader) Upload(ctx context.Context, img Image) (string, error) {
	started := u.now()
	key := fmt.Sprintf("sha256:%x", sha256.Sum256(img.Bytes))
	for attempt := 0; attempt < 2; attempt++ {
		auth := u.currentAuth()
		path, err := u.uploadOnce(ctx, img, key, auth)
		if err == nil {
			u.recordUpload("success", int64(len(img.Bytes)), started)
			return path, nil
		}
		var stagedErr *Error
		if attempt == 0 && u.RefreshAuth != nil && errors.As(err, &stagedErr) && (stagedErr.Code == "unauthenticated" || stagedErr.Code == "insufficient_scope") {
			u.refreshMu.Lock()
			if u.currentAuth() != auth {
				u.refreshMu.Unlock()
				continue
			}
			refreshed, refreshErr := u.RefreshAuth(ctx)
			if refreshErr == nil {
				u.setAuth(refreshed)
			}
			u.refreshMu.Unlock()
			if refreshErr == nil {
				continue
			}
			err = errors.Join(err, fmt.Errorf("refresh upload authorization: %w", refreshErr))
		}
		u.recordUpload("failure", int64(len(img.Bytes)), started)
		return "", err
	}
	u.recordUpload("failure", int64(len(img.Bytes)), started)
	return "", fmt.Errorf("upload retry exhausted")
}

func (u *HTTPUploader) currentAuth() Auth {
	u.authMu.RLock()
	defer u.authMu.RUnlock()
	return u.auth
}

func (u *HTTPUploader) setAuth(auth Auth) {
	u.authMu.Lock()
	u.auth = auth
	u.authMu.Unlock()
}

func (u *HTTPUploader) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *HTTPUploader) recordUpload(outcome string, size int64, started time.Time) {
	if u.telemetry == nil {
		return
	}
	ended := u.now()
	e := telemetry.Event{Name: "upload.result", At: ended, ProjectID: u.projectID, EnvironmentID: u.environmentID, Outcome: outcome, SizeBytes: size, LatencyMS: ended.Sub(started).Milliseconds()}
	if e.Validate() == nil {
		u.telemetry.Record(e)
	}
}

func (u *HTTPUploader) uploadOnce(ctx context.Context, img Image, idempotencyKey string, auth Auth) (string, error) {
	endpoint, err := uploadURL(u.BaseURL, u.Path)
	if err != nil {
		return "", err
	}
	if auth.Method != "bearer" || auth.Token == "" {
		return "", fmt.Errorf("staged-image upload requires bearer file:stage auth")
	}
	pipeReader, pipeWriter := io.Pipe()
	mw := multipart.NewWriter(pipeWriter)
	contentType := mw.FormDataContentType()
	done := make(chan struct{})
	go func() {
		defer close(done)
		part, err := mw.CreateFormFile("image", img.Name)
		if err == nil {
			_, err = io.Copy(part, bytes.NewReader(img.Bytes))
		}
		if err == nil && img.Name != "" {
			err = mw.WriteField("display_filename", img.Name)
		}
		if err == nil {
			err = mw.Close()
		}
		if err != nil {
			_ = pipeWriter.CloseWithError(err)
			return
		}
		_ = pipeWriter.Close()
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = pipeWriter.CloseWithError(ctx.Err())
		case <-done:
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, pipeReader)
	if err != nil {
		_ = pipeWriter.CloseWithError(err)
		_ = pipeReader.Close()
		<-done
		return "", err
	}
	defer func() {
		_ = pipeReader.Close()
		<-done
	}()
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Idempotency-Key", idempotencyKey)
	client := u.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		Path  string `json:"path"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("decode upload response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if out.Error.Code != "" || out.Error.Message != "" {
			return "", &Error{Code: out.Error.Code, Message: out.Error.Message}
		}
		return "", fmt.Errorf("upload failed with status %d", resp.StatusCode)
	}
	if strings.HasPrefix(out.Path, "/") {
		return out.Path, nil
	}
	return "", fmt.Errorf("upload response did not include an absolute VM path")
}

func uploadURL(base, uploadPath string) (string, error) {
	if strings.TrimSpace(base) == "" {
		return "", ErrUnavailable
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse upload URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("upload URL must use http or https, got %q", u.Scheme)
	}
	if strings.TrimSpace(uploadPath) == "" {
		return "", fmt.Errorf("upload descriptor did not include a path")
	}
	reference, err := url.Parse(uploadPath)
	if err != nil {
		return "", fmt.Errorf("parse upload path: %w", err)
	}
	if reference.IsAbs() || reference.Host != "" || reference.RawQuery != "" || reference.Fragment != "" || !strings.HasPrefix(reference.Path, "/") {
		return "", fmt.Errorf("upload path must be an absolute URL path, got %q", uploadPath)
	}
	return u.ResolveReference(reference).String(), nil
}

var _ Uploader = (*HTTPUploader)(nil)
