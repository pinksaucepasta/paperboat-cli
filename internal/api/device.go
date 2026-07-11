package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const ClientID = "paperboat-cli"

var ClientScopes = []string{"account:read", "clients:revoke", "projects:read", "projects:connect", "session:refresh"}

type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type TokenSet struct {
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope"`
	ClientSessionID string `json:"client_session_id"`
}

func DeviceAuthorize(ctx context.Context, baseURL, label, deviceType, osName string, hc *http.Client) (DeviceAuthorization, error) {
	var out DeviceAuthorization
	err := publicCall(ctx, baseURL, "/api/auth/device/authorize", map[string]any{"client_id": ClientID, "client_label": label, "device_type": deviceType, "os": osName, "scopes": ClientScopes}, "", &out, hc)
	return out, err
}

func DeviceToken(ctx context.Context, baseURL, code string, hc *http.Client) (TokenSet, error) {
	var out TokenSet
	err := publicCall(ctx, baseURL, "/api/auth/device/token", map[string]any{"client_id": ClientID, "device_code": code}, "", &out, hc)
	return out, err
}
func RevokeToken(ctx context.Context, baseURL, token string, hc *http.Client) error {
	return publicCall(ctx, baseURL, "/api/auth/token/revoke", nil, token, nil, hc)
}

func RefreshToken(ctx context.Context, baseURL, refreshToken string, hc *http.Client) (TokenSet, error) {
	var out TokenSet
	err := publicCall(ctx, baseURL, "/api/auth/token/refresh", nil, refreshToken, &out, hc)
	return out, err
}

func publicCall(ctx context.Context, baseURL, path string, body any, bearer string, out any, hc *http.Client) error {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env struct {
		Data  json.RawMessage `json:"data"`
		Error struct {
			Code    string         `json:"code"`
			Message string         `json:"message"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("decode auth response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Code: env.Error.Code, Message: env.Error.Message, Details: env.Error.Details}
	}
	if out != nil {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}
