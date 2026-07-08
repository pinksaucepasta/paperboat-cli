package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type Auth struct {
	Method string
	Token  string
	Ticket string
}

type HTTPUploader struct {
	BaseURL    string
	Auth       Auth
	HTTPClient *http.Client
}

func NewHTTPUploader(baseURL string, auth Auth) *HTTPUploader {
	return &HTTPUploader{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Auth:    auth,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (u *HTTPUploader) Upload(ctx context.Context, img Image) (string, error) {
	endpoint, err := uploadURL(u.BaseURL)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]any{
		"name":      img.Name,
		"mime_type": img.MimeType,
		"data_url":  img.DataURL,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	switch u.Auth.Method {
	case "bearer":
		if u.Auth.Token != "" {
			req.Header.Set("Authorization", "Bearer "+u.Auth.Token)
		}
	case "websocket_ticket":
		if u.Auth.Ticket != "" {
			req.Header.Set("Authorization", "Bearer "+u.Auth.Ticket)
		}
	}
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
		VMPath string `json:"vm_path"`
		Path   string `json:"path"`
		Data   struct {
			VMPath string `json:"vm_path"`
			Path   string `json:"path"`
		} `json:"data"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode upload response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if out.Error.Message != "" {
			return "", fmt.Errorf("upload failed: %s", out.Error.Message)
		}
		return "", fmt.Errorf("upload failed with status %d", resp.StatusCode)
	}
	for _, candidate := range []string{out.VMPath, out.Path, out.Data.VMPath, out.Data.Path} {
		if strings.HasPrefix(candidate, "/") {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("upload response did not include an absolute VM path")
}

func uploadURL(base string) (string, error) {
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
	if strings.HasSuffix(u.Path, "/api/paperboat/terminal-upload") {
		return u.String(), nil
	}
	u.Path = path.Join(u.Path, "/api/paperboat/terminal-upload")
	return u.String(), nil
}

var _ Uploader = (*HTTPUploader)(nil)
