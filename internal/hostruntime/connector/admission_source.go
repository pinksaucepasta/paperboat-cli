package connector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/httptransport"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/auth"
)

var ErrAdmissionSourceInvalid = errors.New("invalid connector admission source")

func connectorRouteBinding(routes []RouteHandoff) string {
	hash := sha256.New()
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(routes)))
	_, _ = hash.Write(size[:])
	for _, route := range routes {
		for _, value := range []string{route.RouteID, route.Kind, route.PublicHost, route.ProxyName, route.LocalTarget.Host} {
			binary.BigEndian.PutUint64(size[:], uint64(len(value)))
			_, _ = hash.Write(size[:])
			_, _ = io.WriteString(hash, value)
		}
		binary.BigEndian.PutUint64(size[:], route.Revision)
		_, _ = hash.Write(size[:])
		binary.BigEndian.PutUint64(size[:], uint64(route.LocalTarget.Port))
		_, _ = hash.Write(size[:])
	}
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

type IdentityTokenSource interface {
	Token(context.Context) (string, error)
}
type HelperProofSource interface {
	Proof(context.Context, string, string, string, []byte) ([]byte, error)
}
type CredentialVerifier interface {
	Verify(context.Context, string, auth.Policy) (auth.Claims, error)
}

type AdmissionSourceConfig struct {
	Endpoint         string
	AllowedHosts     []string
	Tokens           IdentityTokenSource
	Proofs           HelperProofSource
	Verifier         CredentialVerifier
	Clock            Clock
	Issuer           string
	EnvironmentID    string
	MachineID        string
	ConnectorID      string
	EdgePool         string
	OperationID      func() (string, error)
	Transport        http.RoundTripper
	MaxResponseBytes int64
}

type HTTPSAdmissionSource struct {
	config   AdmissionSourceConfig
	endpoint *url.URL
	client   *http.Client
}

type admissionRequest struct {
	OperationID     string `json:"operation_id"`
	EnvironmentID   string `json:"environment_id"`
	MachineID       string `json:"machine_id"`
	ConnectorID     string `json:"connector_id"`
	EdgePool        string `json:"edge_pool"`
	ProtocolVersion string `json:"protocol_version"`
}

type admissionResponse struct {
	OperationID        string                  `json:"operation_id"`
	EnvironmentID      string                  `json:"environment_id"`
	MachineID          string                  `json:"machine_id"`
	ConnectorID        string                  `json:"connector_id"`
	Generation         uint64                  `json:"connector_generation"`
	EdgePool           string                  `json:"edge_pool"`
	EdgeNodeID         string                  `json:"edge_node_id"`
	RelayHTTPEndpoint  string                  `json:"relay_http_endpoint"`
	EdgeEndpoint       EdgeEndpoint            `json:"edge_endpoint"`
	Routes             []RouteHandoff          `json:"routes"`
	ProtocolVersion    string                  `json:"protocol_version"`
	Capabilities       []string                `json:"capabilities,omitempty"`
	Credential         string                  `json:"credential"`
	FileTransferPolicy auth.FileTransferPolicy `json:"file_transfer_policy"`
}

func NewHTTPSAdmissionSource(config AdmissionSourceConfig) (*HTTPSAdmissionSource, error) {
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = 64 << 10
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Hostname() == "" || endpoint.Fragment != "" || config.Tokens == nil || config.Proofs == nil || config.Verifier == nil || config.Clock == nil || config.Issuer == "" || config.EnvironmentID == "" || config.MachineID == "" || config.ConnectorID == "" || config.EdgePool == "" || config.OperationID == nil || config.MaxResponseBytes < 1 || config.MaxResponseBytes > 64<<10 {
		return nil, ErrAdmissionSourceInvalid
	}
	allowed := false
	for _, host := range config.AllowedHosts {
		if strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(endpoint.Hostname(), ".")) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, ErrAdmissionSourceInvalid
	}
	transport := config.Transport
	if transport == nil {
		transport = httptransport.Default()
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrAdmissionSourceInvalid }}
	return &HTTPSAdmissionSource{config: config, endpoint: endpoint, client: client}, nil
}

func (s *HTTPSAdmissionSource) Admission(ctx context.Context) (Admission, error) {
	operationID, err := s.config.OperationID()
	if err != nil || len(operationID) < 8 || len(operationID) > 128 {
		return Admission{}, errors.Join(ErrAdmissionSourceInvalid, err)
	}
	token, err := s.config.Tokens.Token(ctx)
	if err != nil || token == "" || len(token) > 16<<10 {
		return Admission{}, errors.Join(ErrAdmissionSourceInvalid, err)
	}
	payload := admissionRequest{operationID, s.config.EnvironmentID, s.config.MachineID, s.config.ConnectorID, s.config.EdgePool, "1.0"}
	encoded, _ := json.Marshal(payload)
	proof, err := s.config.Proofs.Proof(ctx, operationID, http.MethodPost, s.endpoint.Path, encoded)
	if err != nil || len(proof) == 0 || len(proof) > 16<<10 {
		return Admission{}, errors.Join(ErrAdmissionSourceInvalid, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.String(), bytes.NewReader(encoded))
	if err != nil {
		return Admission{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return Admission{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, s.config.MaxResponseBytes))
		return Admission{}, ErrUnavailable
	}
	limited := io.LimitReader(response.Body, s.config.MaxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return Admission{}, err
	}
	if int64(len(body)) > s.config.MaxResponseBytes {
		return Admission{}, ErrAdmissionSourceInvalid
	}
	var document admissionResponse
	if strictJSON(body, &document) != nil || document.OperationID != operationID || document.EnvironmentID != s.config.EnvironmentID || document.MachineID != s.config.MachineID || document.ConnectorID != s.config.ConnectorID || document.EdgePool != s.config.EdgePool || !identifierPattern.MatchString(document.EdgeNodeID) || document.ProtocolVersion != "1.0" || document.Generation == 0 || len(document.Credential) < 32 || len(document.Credential) > 8192 || !validCapabilities(document.Capabilities) || !validEndpoint(document.EdgeEndpoint) || !validRelayHTTPEndpoint(document.RelayHTTPEndpoint) || !validRoutes(document.Routes) || !validFileTransferPolicy(document.FileTransferPolicy) {
		return Admission{}, ErrAdmissionSourceInvalid
	}
	claims, err := s.config.Verifier.Verify(ctx, document.Credential, auth.Policy{Issuer: s.config.Issuer, Audience: "paperboat-edge", CredentialClass: "connector_admission", Scopes: []string{"connector:admit"}, EnvironmentID: s.config.EnvironmentID, MachineID: s.config.MachineID, ConnectorID: s.config.ConnectorID, ConnectorGeneration: document.Generation, EdgePool: s.config.EdgePool, EdgeNodeID: document.EdgeNodeID, MaxLifetime: 5 * time.Minute, SingleUse: true})
	if err != nil {
		return Admission{}, err
	}
	expires := time.Unix(claims.ExpiresAt, 0).UTC()
	if claims.JTI == "" || claims.EdgePool != s.config.EdgePool || claims.RouteBinding != connectorRouteBinding(document.Routes) || !expires.After(s.config.Clock.Now()) || claims.FileTransferPolicy == nil || *claims.FileTransferPolicy != document.FileTransferPolicy {
		return Admission{}, ErrAdmissionSourceInvalid
	}
	return Admission{OperationID: document.OperationID, JTI: claims.JTI, Credential: document.Credential, EnvironmentID: document.EnvironmentID, MachineID: document.MachineID, ConnectorID: document.ConnectorID, Generation: document.Generation, EdgePool: claims.EdgePool, EdgeNodeID: claims.EdgeNodeID, RelayHTTPEndpoint: document.RelayHTTPEndpoint, Endpoint: document.EdgeEndpoint, Routes: append([]RouteHandoff(nil), document.Routes...), ProtocolVersion: document.ProtocolVersion, ExpiresAt: expires, FileTransferPolicy: document.FileTransferPolicy}, nil
}

func validRelayHTTPEndpoint(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validFileTransferPolicy(policy auth.FileTransferPolicy) bool {
	return policy.Revision != "" && policy.MaxFileBytes > 0 && policy.MaxFileBytes <= 50<<20 && policy.MaxBatchFiles > 0 && policy.MaxBatchFiles <= 10 && policy.MaxBatchBytes >= policy.MaxFileBytes && policy.MaxBatchBytes <= 500<<20 && policy.MaxConcurrentTransfers > 0 && policy.MaxConcurrentTransfers <= 2 && policy.RetentionSeconds > 0 && policy.DeliveryTimeoutSeconds > 0 && policy.MaxPendingSpoolBytes >= policy.MaxBatchBytes
}

func strictJSON(data []byte, target any) error {
	if err := rejectDuplicateJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrAdmissionSourceInvalid
	}
	return nil
}

func rejectDuplicateJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return ErrAdmissionSourceInvalid
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return ErrAdmissionSourceInvalid
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrAdmissionSourceInvalid
	}
	return nil
}

var capabilityPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,63}$`)

func validCapabilities(values []string) bool {
	if len(values) > 64 {
		return false
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if !capabilityPattern.MatchString(value) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,127}$`)

func validEndpoint(endpoint EdgeEndpoint) bool {
	if endpoint.Port == 0 || len(endpoint.Host) == 0 || len(endpoint.Host) > 253 {
		return false
	}
	if ip := net.ParseIP(endpoint.Host); ip != nil {
		return !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast()
	}
	parsed, err := url.Parse("https://" + endpoint.Host)
	return err == nil && parsed.Hostname() == endpoint.Host && !strings.Contains(endpoint.Host, "_")
}

func validRoutes(routes []RouteHandoff) bool {
	if len(routes) == 0 || len(routes) > 128 {
		return false
	}
	seenRoutes := make(map[string]bool, len(routes))
	seenProxies := make(map[string]bool, len(routes))
	seenHosts := make(map[string]bool, len(routes))
	for _, route := range routes {
		if !identifierPattern.MatchString(route.RouteID) || !identifierPattern.MatchString(route.ProxyName) || route.Revision == 0 || seenRoutes[route.RouteID] || seenProxies[route.ProxyName] || seenHosts[route.PublicHost] || !validPublicHost(route.PublicHost) || route.LocalTarget.Port == 0 || route.LocalTarget.Host != "127.0.0.1" && route.LocalTarget.Host != "::1" || route.Kind != "runtime_https_wss" && route.Kind != "preview_public_https_wss" {
			return false
		}
		seenRoutes[route.RouteID] = true
		seenProxies[route.ProxyName] = true
		seenHosts[route.PublicHost] = true
	}
	return true
}

func validPublicHost(host string) bool {
	if len(host) == 0 || len(host) > 253 || net.ParseIP(host) != nil || strings.Contains(host, "_") {
		return false
	}
	parsed, err := url.Parse("https://" + host)
	return err == nil && parsed.Hostname() == host && parsed.Port() == "" && parsed.Path == ""
}
