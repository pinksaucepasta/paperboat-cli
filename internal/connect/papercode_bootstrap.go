package connect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// BootstrapPapercode installs the server-issued Paperboat trust bundle through
// Papercode's local administrative API. The administrative bearer is revoked
// immediately after the one-time configuration request succeeds or fails.
func BootstrapPapercode(ctx context.Context, executable string, enrollment Enrollment) error {
	if enrollment.PapercodeBootstrap.invalid() {
		return ErrEnrollmentUnavailable
	}
	local, err := absoluteHTTPURL(enrollment.PapercodeLocalURL)
	if err != nil {
		return err
	}
	if err := waitForHTTP(ctx, local.String()); err != nil {
		return err
	}
	output, err := exec.CommandContext(ctx, executable, "auth", "session", "issue", "--ttl", "2m", "--label", "paperboat-connect-bootstrap", "--json").Output()
	if err != nil {
		return fmt.Errorf("issue local papercode bootstrap session: %w", err)
	}
	var session struct {
		SessionID string `json:"sessionId"`
		Token     string `json:"token"`
	}
	if err := json.Unmarshal(output, &session); err != nil || session.SessionID == "" || session.Token == "" {
		return ErrEnrollmentUnavailable
	}
	defer exec.CommandContext(context.Background(), executable, "auth", "session", "revoke", session.SessionID).Run()
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
		return fmt.Errorf("apply papercode bootstrap: unexpected status %d", response.StatusCode)
	}
	return nil
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
