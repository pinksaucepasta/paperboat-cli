package connect

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// WriteAgentunnelMachineConfig writes the standard Agentunnel unattended-client
// configuration. The only secret is kept in the adjacent 0600 token file.
func WriteAgentunnelMachineConfig(dir string, enrollment Enrollment) (string, error) {
	if strings.TrimSpace(enrollment.Agentunnel) == "" || strings.TrimSpace(enrollment.MachineID) == "" || strings.TrimSpace(enrollment.AgentunnelRouteID) == "" {
		return "", ErrEnrollmentUnavailable
	}
	if _, err := absoluteHTTPURL(enrollment.AgentunnelServerURL); err != nil {
		return "", err
	}
	if _, err := papercodeServeArgs(enrollment.PapercodeLocalURL); err != nil {
		return "", err
	}
	tokenPath := filepath.Join(dir, "agentunnel-client.token")
	configPath := filepath.Join(dir, "agentunnel-client.json")
	statusPath := filepath.Join(dir, "agentunnel-client-status.json")
	if err := atomicWrite(tokenPath, []byte(enrollment.Agentunnel+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write agentunnel token: %w", err)
	}
	value, err := json.Marshal(struct {
		ServerURL       string `json:"server_url"`
		ClientTokenFile string `json:"client_token_file"`
		MachineID       string `json:"machine_id"`
		StatusFile      string `json:"status_file"`
		ServeHTTP       []struct {
			TunnelID string `json:"tunnel_id"`
			LocalURL string `json:"local_url"`
		} `json:"serve_http_tunnels"`
	}{
		ServerURL: enrollment.AgentunnelServerURL, ClientTokenFile: tokenPath, MachineID: enrollment.MachineID, StatusFile: statusPath,
		ServeHTTP: []struct {
			TunnelID string `json:"tunnel_id"`
			LocalURL string `json:"local_url"`
		}{{TunnelID: enrollment.AgentunnelRouteID, LocalURL: enrollment.PapercodeLocalURL}},
	})
	if err != nil {
		return "", fmt.Errorf("encode agentunnel config: %w", err)
	}
	if err := atomicWrite(configPath, append(value, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("write agentunnel config: %w", err)
	}
	return configPath, nil
}

func PapercodeServeArgs(raw string) ([]string, error) { return papercodeServeArgs(raw) }

func papercodeServeArgs(raw string) ([]string, error) {
	u, err := absoluteHTTPURL(raw)
	if err != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.Port() == "" {
		return nil, ErrEnrollmentUnavailable
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, ErrEnrollmentUnavailable
	}
	return []string{"serve", "--no-browser", "--host", u.Hostname(), "--port", strconv.Itoa(port)}, nil
}

func absoluteHTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return nil, ErrEnrollmentUnavailable
	}
	return u, nil
}
