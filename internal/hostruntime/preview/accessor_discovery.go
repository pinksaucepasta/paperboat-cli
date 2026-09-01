package preview

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/httptransport"
	"github.com/pinksaucepasta/paperboat/internal/privatepreviewproxy"
)

const (
	privateAccessRoutesPath        = "/v1/private-access/routes"
	privateAccessMaximumAdmissions = 4096
)

var (
	accessorConfigHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	accessorNamePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

type accessorAdmission struct {
	Schema                               string    `json:"schema"`
	Kind                                 string    `json:"kind"`
	AccountID                            string    `json:"account_id"`
	DeviceID                             string    `json:"device_id"`
	InstallationGeneration               uint64    `json:"installation_generation"`
	AccessorPublicKey                    string    `json:"accessor_public_key"`
	AccessorThumbprint                   string    `json:"accessor_thumbprint"`
	ResourceKind                         string    `json:"resource_kind"`
	ResourceID                           string    `json:"resource_id"`
	TunnelName                           string    `json:"tunnel_name,omitempty"`
	RouteName                            string    `json:"route_name,omitempty"`
	OperationID                          string    `json:"operation_id,omitempty"`
	ConnectorID                          string    `json:"connector_id,omitempty"`
	CarrierSessionID                     string    `json:"carrier_session_id"`
	RouteID                              string    `json:"route_id"`
	RouteGeneration                      uint64    `json:"route_generation"`
	SessionGeneration                    uint64    `json:"session_generation"`
	ProcessGeneration                    uint64    `json:"process_generation"`
	ConfigGeneration                     uint64    `json:"config_generation"`
	AssignmentGeneration                 uint64    `json:"assignment_generation"`
	AssignmentID                         string    `json:"assignment_id"`
	ConfigContentHash                    string    `json:"config_content_hash"`
	EdgeNodeID                           string    `json:"edge_node_id"`
	EdgeProcessEpoch                     string    `json:"edge_process_epoch"`
	EdgeCarrierServerSPKISHA256          string    `json:"edge_carrier_server_spki_sha256"`
	EdgeCarrierServerCertificateChainPEM string    `json:"edge_carrier_server_certificate_chain_pem"`
	Protocol                             string    `json:"protocol"`
	Hostname                             string    `json:"hostname"`
	MatchType                            string    `json:"match_type"`
	WildcardSuffix                       string    `json:"wildcard_suffix,omitempty"`
	EdgeEndpoints                        []string  `json:"edge_endpoints"`
	ExpiresAt                            time.Time `json:"expires_at"`
	TunnelID                             string    `json:"tunnel_id"`
	CarrierConnectorID                   string    `json:"carrier_connector_id"`
}

func (a accessorAdmission) validate(now time.Time) error {
	for _, value := range []string{a.AccountID, a.DeviceID, a.ResourceID, a.CarrierSessionID, a.RouteID, a.AssignmentID, a.EdgeNodeID, a.TunnelID, a.CarrierConnectorID} {
		if connectorprotocol.ValidateIdentifier(value) != nil {
			return ErrPrivateAccessInvalid
		}
	}
	if connectorprotocol.ValidateOpaqueEpoch(a.EdgeProcessEpoch) != nil || a.InstallationGeneration == 0 || a.RouteGeneration == 0 || a.SessionGeneration == 0 || a.ProcessGeneration == 0 || a.ConfigGeneration == 0 || a.AssignmentGeneration == 0 || !a.ExpiresAt.After(now) || !accessorConfigHashPattern.MatchString(a.ConfigContentHash) || !validEdgeCarrierServerCertificateChainPEM(a.EdgeCarrierServerCertificateChainPEM, a.EdgeCarrierServerSPKISHA256) || len(a.EdgeEndpoints) != 2 {
		return ErrPrivateAccessInvalid
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(a.AccessorPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return ErrPrivateAccessInvalid
	}
	thumb, err := connectorprotocol.IdentityThumbprint(ed25519.PublicKey(key))
	if err != nil || thumb != a.AccessorThumbprint {
		return ErrPrivateAccessInvalid
	}
	for index, scheme := range []string{"tls", "quic"} {
		u, err := url.Parse(a.EdgeEndpoints[index])
		port, portErr := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || u.Scheme != scheme || u.Hostname() == "" || portErr != nil || port == 0 || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return ErrPrivateAccessInvalid
		}
	}
	if !validAccessorMatch(a.Protocol, a.Hostname, a.MatchType, a.WildcardSuffix) {
		return ErrPrivateAccessInvalid
	}
	if a.ResourceKind == "preview" {
		if a.TunnelName != "" || a.RouteName != "" || connectorprotocol.ValidateIdentifier(a.OperationID) != nil || a.ConnectorID != "" || a.Protocol != "http" {
			return ErrPrivateAccessInvalid
		}
	} else if a.ResourceKind != "tunnel" || !validAccessorName(a.TunnelName, 63) || !validAccessorName(a.RouteName, 80) || connectorprotocol.ValidateIdentifier(a.ConnectorID) != nil || a.OperationID != "" {
		return ErrPrivateAccessInvalid
	}
	return nil
}

func validAccessorName(value string, maximum int) bool {
	return value == strings.TrimSpace(value) && len(value) >= 1 && len(value) <= maximum && accessorNamePattern.MatchString(value)
}

func validAccessorMatch(protocol, hostname, matchType, suffix string) bool {
	if protocol == "private_tcp" {
		return hostname == "" && matchType == "catch_all" && suffix == ""
	}
	if protocol != "http" || hostname == "" {
		return false
	}
	switch matchType {
	case "exact", "managed_exact":
		normalized, err := privateAccessEndpointHost("https://" + hostname)
		return err == nil && suffix == "" && normalized == hostname
	case "one_label_wildcard":
		normalized, err := privateAccessEndpointHost("https://" + suffix)
		return err == nil && normalized == suffix && strings.Contains(suffix, ".") && hostname == "*."+suffix
	default:
		return false
	}
}

type accessorSnapshot struct {
	Schema     string              `json:"schema"`
	Kind       string              `json:"kind"`
	Complete   bool                `json:"complete"`
	Admissions []accessorAdmission `json:"admissions"`
}

type accessorDiscoveryClient struct {
	endpoint *url.URL
	auth     privateAccessMachineAuth
	client   *http.Client
}

func newAccessorDiscoveryClient(controlURL string, auth privateAccessMachineAuth, transport http.RoundTripper) (*accessorDiscoveryClient, error) {
	u, err := url.Parse(strings.TrimSpace(controlURL))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrPrivateAccessInvalid
	}
	u.Path = strings.TrimRight(u.Path, "/") + privateAccessRoutesPath
	if transport == nil {
		transport = httptransport.Default()
	}
	return &accessorDiscoveryClient{endpoint: u, auth: auth, client: &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrPrivateAccessInvalid }}}, nil
}

func (c *accessorDiscoveryClient) snapshot(ctx context.Context) ([]accessorAdmission, error) {
	id, err := newPrivateAccessIdentifier()
	if err != nil {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	body, _ := json.Marshal(map[string]string{"idempotency_key": "routes_" + id})
	token, err := c.auth.Token(ctx)
	if err != nil {
		return nil, privatepreviewproxy.ErrAccessAuthentication
	}
	proof, err := c.auth.Proof(ctx, "routes_"+id, http.MethodPost, c.endpoint.Path, body)
	if err != nil {
		return nil, privatepreviewproxy.ErrAccessAuthentication
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Paperboat-Machine-Identity", token)
	r.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "routes_"+id)
	resp, err := c.client.Do(r)
	if err != nil {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return nil, privatepreviewproxy.ErrAccessAuthentication
	}
	if resp.StatusCode == 403 {
		return nil, privatepreviewproxy.ErrAccessForbidden
	}
	if resp.StatusCode != 200 {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	if values := resp.Header.Values("Content-Type"); len(values) != 1 || values[0] != "application/json" {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, privateAccessMaxBody+1))
	if err != nil || len(raw) == 0 || len(raw) > privateAccessMaxBody {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var out accessorSnapshot
	if d.Decode(&out) != nil || d.Decode(&struct{}{}) != io.EOF || !out.Complete || out.Schema != "paperboat.preview-tunnel/v1" || out.Kind != "private_access_carrier_snapshot" || out.Admissions == nil || len(out.Admissions) > privateAccessMaximumAdmissions {
		return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
	}
	seen := make(map[string]struct{}, len(out.Admissions))
	for _, admission := range out.Admissions {
		if admission.validate(time.Now().UTC()) != nil {
			return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
		}
		key := admission.DeviceID + "\x00" + admission.ResourceID + "\x00" + admission.RouteID + "\x00" + admission.AssignmentID
		if _, ok := seen[key]; ok {
			return nil, privatepreviewproxy.ErrAccessTemporarilyUnavailable
		}
		seen[key] = struct{}{}
	}
	return out.Admissions, nil
}
