package connect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// PreparePapercodeState pins Papercode's persistent environment identity to
// the server-authoritative connected-machine environment before it starts.
func PreparePapercodeState(dir string, enrollment Enrollment) (string, error) {
	if strings.TrimSpace(enrollment.EnvironmentID) == "" {
		return "", ErrEnrollmentUnavailable
	}
	baseDir := filepath.Join(dir, "papercode-state")
	stateDir := filepath.Join(baseDir, "userdata")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	if err := atomicWrite(filepath.Join(stateDir, "environment-id"), []byte(enrollment.EnvironmentID+"\n"), 0o600); err != nil {
		return "", err
	}
	return baseDir, nil
}

// BootstrapPapercode installs the server-issued Paperboat trust bundle through
// Papercode's local administrative API. The administrative bearer is revoked
// immediately after the one-time configuration request succeeds or fails.
func BootstrapPapercode(ctx context.Context, executable, baseDir string, enrollment Enrollment) error {
	if enrollment.PapercodeBootstrap.invalid() || !filepath.IsAbs(baseDir) {
		return ErrEnrollmentUnavailable
	}
	local, err := absoluteHTTPURL(enrollment.PapercodeLocalURL)
	if err != nil {
		return err
	}
	if err := waitForHTTP(ctx, local.String()); err != nil {
		return err
	}
	output, err := exec.CommandContext(ctx, executable, papercodeSessionIssueArgs(baseDir)...).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("issue local papercode bootstrap session: %w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return fmt.Errorf("issue local papercode bootstrap session: %w", err)
	}
	var session struct {
		SessionID string `json:"sessionId"`
		Token     string `json:"token"`
	}
	if err := json.Unmarshal(output, &session); err != nil || session.SessionID == "" || session.Token == "" {
		return ErrEnrollmentUnavailable
	}
	defer exec.CommandContext(context.Background(), executable, papercodeSessionRevokeArgs(baseDir, session.SessionID)...).Run()
	body, err := json.Marshal(map[string]any{"relayUrl": enrollment.PapercodeBootstrap.RelayURL, "relayIssuer": enrollment.PapercodeBootstrap.RelayIssuer, "cloudUserId": enrollment.PapercodeBootstrap.CloudUserID, "environmentCredential": enrollment.PapercodeBootstrap.EnvironmentCredential, "cloudMintPublicKey": enrollment.PapercodeBootstrap.CloudMintPublicKey, "endpointRuntime": nil})
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(local.String(), "/") + "/api/connect/relay-config"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+session.Token)
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 15 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		return fmt.Errorf("apply papercode bootstrap: unexpected status %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	return nil
}

func papercodeSessionIssueArgs(baseDir string) []string {
	return []string{"auth", "session", "issue", "--base-dir", baseDir, "--ttl", "2m", "--label", "paperboat-connect-bootstrap", "--json"}
}

func papercodeSessionRevokeArgs(baseDir, sessionID string) []string {
	return []string{"auth", "session", "revoke", "--base-dir", baseDir, sessionID}
}

func waitForHTTP(ctx context.Context, raw string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if request != nil {
			if response, err := client.Do(request); err == nil {
				response.Body.Close()
				if response.StatusCode < 500 {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("papercode did not become ready")
		case <-time.After(250 * time.Millisecond):
		}
	}
}
