package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/buildinfo"
)

const TunnelV1Schema = "paperboat.preview-tunnel/v1"

var tunnelEndpointUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

var (
	ErrUnsafeTunnelResponse = errors.New("paperboat-server returned an unsafe tunnel response")
	// ErrTunnelRedirect is returned before a redirected request is issued. A
	// tunnel response can contain credentials or control data, so following a
	// Location header would be an unsafe cross-origin data exfiltration path.
	ErrTunnelRedirect = errors.New("paperboat-server tunnel request was redirected")
)

const (
	// The v1 resource projections are deliberately bounded. Keep enough room
	// for a full page and nested safe metadata while refusing accidental or
	// hostile multi-megabyte responses.
	maxTunnelResponseBytes = 2 << 20
	maxTunnelRequestBytes  = 1 << 20
)

type TunnelOperation struct {
	Schema        string                 `json:"schema"`
	Kind          string                 `json:"kind"`
	ID            string                 `json:"id"`
	ResourceKind  string                 `json:"resource_kind"`
	ResourceID    string                 `json:"resource_id"`
	Phase         string                 `json:"phase"`
	State         string                 `json:"state"`
	Progress      int                    `json:"progress"`
	Retrying      bool                   `json:"retrying"`
	NextRetryAt   *time.Time             `json:"next_retry_at,omitempty"`
	Error         *PreviewTunnelAPIError `json:"error,omitempty"`
	CorrelationID string                 `json:"correlation_id"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}
type Tunnel struct {
	Schema           string     `json:"schema"`
	Kind             string     `json:"kind"`
	ID               string     `json:"id"`
	AccountID        string     `json:"account_id"`
	Name             string     `json:"name"`
	DesiredState     string     `json:"desired_state"`
	AccessMode       string     `json:"access_mode"`
	Generation       int64      `json:"generation"`
	ETag             string     `json:"etag"`
	StableEndpointID string     `json:"stable_endpoint_id"`
	StableEndpoint   string     `json:"stable_endpoint"`
	CreatedByHostID  string     `json:"created_by_host_id"`
	CreatedByActorID string     `json:"created_by_actor_id"`
	ExpiresAt        *time.Time `json:"expires_at"`
	SummaryCode      string     `json:"summary_code"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}
type TunnelPage struct {
	Items      []Tunnel `json:"items"`
	NextCursor string   `json:"next_cursor,omitempty"`
}
type TunnelOriginInput struct {
	Scheme       string  `json:"scheme"`
	Address      string  `json:"address"`
	PreserveHost *bool   `json:"preserve_host,omitempty"`
	HostOverride *string `json:"host_override,omitempty"`
}
type TunnelCreateInput struct {
	Name       string            `json:"name"`
	AccessMode string            `json:"access_mode,omitempty"`
	Origin     TunnelOriginInput `json:"origin"`
	ExpiresAt  *time.Time        `json:"expires_at,omitempty"`
}
type TunnelPatchInput struct {
	Name       *string    `json:"name,omitempty"`
	AccessMode *string    `json:"access_mode,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}
type TunnelMutation struct {
	Tunnel    Tunnel          `json:"tunnel"`
	Operation TunnelOperation `json:"operation"`
	Replayed  bool            `json:"replayed"`
	Changed   bool            `json:"changed"`
}

type TunnelRouteHostMatch struct {
	Type           string `json:"type"`
	Hostname       string `json:"hostname,omitempty"`
	WildcardLabels *int   `json:"wildcard_labels,omitempty"`
}
type TunnelRouteTLS struct {
	Verification              string  `json:"verification"`
	ServerName                *string `json:"server_name,omitempty"`
	CAReference               *string `json:"ca_reference,omitempty"`
	ClientCredentialReference *string `json:"client_credential_reference,omitempty"`
}
type TunnelRouteOrigin struct {
	Scheme       string          `json:"scheme"`
	Address      string          `json:"address"`
	PreserveHost bool            `json:"preserve_host"`
	HostOverride *string         `json:"host_override,omitempty"`
	TLS          *TunnelRouteTLS `json:"tls,omitempty"`
}
type TunnelRoute struct {
	Schema               string               `json:"schema"`
	Kind                 string               `json:"kind"`
	ID                   string               `json:"id"`
	TunnelID             string               `json:"tunnel_id"`
	Name                 string               `json:"name"`
	Protocol             string               `json:"protocol"`
	HostMatch            TunnelRouteHostMatch `json:"host_match"`
	PathPrefix           *string              `json:"path_prefix,omitempty"`
	Origin               TunnelRouteOrigin    `json:"origin"`
	Priority             int32                `json:"priority"`
	ConnectTimeoutMS     int32                `json:"connect_timeout_ms"`
	IdleTimeoutMS        int32                `json:"idle_timeout_ms"`
	MaxConcurrentStreams int32                `json:"max_concurrent_streams"`
	DesiredState         string               `json:"desired_state"`
	Generation           int64                `json:"generation"`
	ETag                 string               `json:"etag"`
}
type TunnelRoutePage struct {
	Items      []TunnelRoute `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}
type TunnelRouteInput struct {
	Name                 string               `json:"name"`
	Protocol             string               `json:"protocol"`
	HostMatch            TunnelRouteHostMatch `json:"host_match"`
	PathPrefix           *string              `json:"path_prefix,omitempty"`
	Origin               TunnelRouteOrigin    `json:"origin"`
	Priority             int32                `json:"priority,omitempty"`
	ConnectTimeoutMS     int32                `json:"connect_timeout_ms,omitempty"`
	IdleTimeoutMS        int32                `json:"idle_timeout_ms,omitempty"`
	MaxConcurrentStreams int32                `json:"max_concurrent_streams,omitempty"`
}
type TunnelRoutePatch struct {
	Name                 *string               `json:"name,omitempty"`
	Protocol             *string               `json:"protocol,omitempty"`
	HostMatch            *TunnelRouteHostMatch `json:"host_match,omitempty"`
	PathPrefix           *string               `json:"-"`
	PathPrefixSet        bool                  `json:"-"`
	Origin               *TunnelRouteOrigin    `json:"origin,omitempty"`
	Priority             *int32                `json:"priority,omitempty"`
	ConnectTimeoutMS     *int32                `json:"connect_timeout_ms,omitempty"`
	IdleTimeoutMS        *int32                `json:"idle_timeout_ms,omitempty"`
	MaxConcurrentStreams *int32                `json:"max_concurrent_streams,omitempty"`
	DesiredState         *string               `json:"desired_state,omitempty"`
}

// MarshalJSON preserves the distinction between an omitted path_prefix and
// an explicit null, which clears an existing route path without inventing a
// sentinel string value.
func (p TunnelRoutePatch) MarshalJSON() ([]byte, error) {
	type alias TunnelRoutePatch
	encoded, err := json.Marshal(alias(p))
	if err != nil {
		return nil, err
	}
	if !p.PathPrefixSet && p.PathPrefix == nil {
		return encoded, nil
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return nil, err
	}
	if p.PathPrefix == nil {
		fields["path_prefix"] = nil
	} else {
		fields["path_prefix"] = *p.PathPrefix
	}
	return json.Marshal(fields)
}

type TunnelRouteMutation struct {
	Route     TunnelRoute     `json:"route"`
	Operation TunnelOperation `json:"operation"`
	Replayed  bool            `json:"replayed"`
	Changed   bool            `json:"changed"`
}

type TunnelDomain struct {
	Schema              string                  `json:"schema"`
	Kind                string                  `json:"kind"`
	ID                  string                  `json:"id"`
	TargetKind          string                  `json:"target_kind,omitempty"`
	AccountID           string                  `json:"account_id"`
	TunnelID            string                  `json:"tunnel_id"`
	RouteID             string                  `json:"route_id"`
	Hostname            string                  `json:"hostname"`
	MatchType           string                  `json:"match_type"`
	WildcardLabels      *int                    `json:"wildcard_labels,omitempty"`
	CertificateStrategy string                  `json:"certificate_strategy,omitempty"`
	State               string                  `json:"state"`
	DNS                 TunnelDomainDNS         `json:"dns"`
	Certificate         TunnelDomainCertificate `json:"certificate"`
	Generation          int64                   `json:"generation"`
	ETag                string                  `json:"etag"`
}
type TunnelDomainDNS struct {
	Target          string     `json:"target"`
	ObservedRecords []string   `json:"observed_records,omitempty"`
	LastCheckedAt   *time.Time `json:"last_checked_at,omitempty"`
}
type TunnelDomainCertificate struct {
	State     string         `json:"state"`
	Reference string         `json:"reference,omitempty"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	Failure   map[string]any `json:"failure,omitempty"`
}
type TunnelDomainPage struct {
	Items      []TunnelDomain `json:"items"`
	NextCursor string         `json:"next_cursor,omitempty"`
}
type TunnelDomainInput struct {
	Hostname            string `json:"hostname"`
	RouteID             string `json:"route_id"`
	Provider            string `json:"provider,omitempty"`
	CertificateStrategy string `json:"certificate_strategy,omitempty"`
}
type TunnelDomainMutation struct {
	Domain    TunnelDomain    `json:"domain"`
	Operation TunnelOperation `json:"operation"`
	Replayed  bool            `json:"replayed"`
	Changed   bool            `json:"changed"`
}
type TunnelDNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}
type TunnelDNSInstructions struct {
	Schema              string            `json:"schema"`
	Kind                string            `json:"kind"`
	TunnelID            string            `json:"tunnel_id"`
	DomainID            string            `json:"domain_id"`
	Hostname            string            `json:"hostname"`
	Provider            string            `json:"provider"`
	Records             []TunnelDNSRecord `json:"records"`
	CertificateStrategy string            `json:"certificate_strategy"`
	VerificationState   string            `json:"verification_state"`
	Note                string            `json:"note"`
}

type TunnelConnector struct {
	Schema                      string     `json:"schema"`
	Kind                        string     `json:"kind"`
	ID                          string     `json:"id"`
	TunnelID                    string     `json:"tunnel_id"`
	HostID                      string     `json:"host_id"`
	CredentialReference         string     `json:"credential_reference"`
	RotationGeneration          int64      `json:"rotation_generation"`
	DesiredState                string     `json:"desired_state"`
	ProtocolVersion             string     `json:"protocol_version"`
	SoftwareVersion             string     `json:"software_version,omitempty"`
	OperatingSystem             string     `json:"operating_system,omitempty"`
	Architecture                string     `json:"architecture,omitempty"`
	LastSessionID               string     `json:"last_session_id,omitempty"`
	LastHeartbeatAt             *time.Time `json:"last_heartbeat_at,omitempty"`
	ReadyAt                     *time.Time `json:"ready_at,omitempty"`
	LastAppliedConfigGeneration int64      `json:"last_applied_config_generation,omitempty"`
	DrainState                  string     `json:"drain_state"`
	Generation                  int64      `json:"generation"`
	ETag                        string     `json:"etag"`
}
type TunnelConnectorPage struct {
	Items      []TunnelConnector `json:"items"`
	NextCursor string            `json:"next_cursor,omitempty"`
}
type TunnelConnectorMutation struct {
	Connector  TunnelConnector            `json:"connector"`
	Operation  TunnelOperation            `json:"operation"`
	Activation *TunnelConnectorActivation `json:"activation,omitempty"`
	Replayed   bool                       `json:"replayed"`
	Changed    bool                       `json:"changed"`
}

// TunnelConnectorEnrollment is returned once when a host enrollment is
// issued. EnrollmentToken is write-only on the wire and must never be logged.
type TunnelConnectorEnrollment struct {
	Schema          string          `json:"schema"`
	Kind            string          `json:"kind"`
	ID              string          `json:"id"`
	TunnelID        string          `json:"tunnel_id"`
	HostID          string          `json:"host_id"`
	Operation       TunnelOperation `json:"operation"`
	EnrollmentToken string          `json:"enrollment_token"`
	ExpiresAt       time.Time       `json:"expires_at"`
	Capabilities    []string        `json:"capabilities"`
	Replayed        bool            `json:"replayed"`
}

type TunnelConnectorEnrollmentInput struct {
	HostID       string   `json:"host_id"`
	Capabilities []string `json:"capabilities"`
	TTLSeconds   int      `json:"ttl_seconds,omitempty"`
}

// TunnelConnectorEnrollmentExchangeInput contains host-held write-only material. The
// client validates their shape but never places them in a response type.
type TunnelConnectorEnrollmentExchangeInput struct {
	Token                       string  `json:"token"`
	HostID                      string  `json:"host_id"`
	ProtocolVersion             string  `json:"protocol_version,omitempty"`
	SoftwareVersion             *string `json:"software_version,omitempty"`
	CredentialReference         string  `json:"credential_reference"`
	CredentialThumbprint        string  `json:"credential_thumbprint"`
	CredentialVerifierAlgorithm string  `json:"credential_verifier_algorithm"`
	CredentialVerifierPublicKey string  `json:"credential_verifier_public_key"`
	CredentialProof             string  `json:"credential_proof"`
	OperatingSystem             *string `json:"operating_system,omitempty"`
	Architecture                *string `json:"architecture,omitempty"`
}

type TunnelConnectorActivation struct {
	Schema               string          `json:"schema"`
	Kind                 string          `json:"kind"`
	AccountID            string          `json:"account_id"`
	TunnelID             string          `json:"tunnel_id"`
	ConnectorID          string          `json:"connector_id"`
	HostID               string          `json:"host_id"`
	CredentialGeneration int64           `json:"credential_generation"`
	ProcessGeneration    int64           `json:"process_generation"`
	Operation            TunnelOperation `json:"operation"`
}

type TunnelEventActor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type TunnelEvent struct {
	Schema        string           `json:"schema"`
	Kind          string           `json:"kind"`
	ID            string           `json:"id"`
	Cursor        string           `json:"cursor"`
	EventType     string           `json:"event_type"`
	ResourceKind  string           `json:"resource_kind"`
	ResourceID    string           `json:"resource_id"`
	OccurredAt    time.Time        `json:"occurred_at"`
	Actor         TunnelEventActor `json:"actor"`
	CorrelationID string           `json:"correlation_id"`
	SafeMetadata  map[string]any   `json:"safe_metadata"`
}

type TunnelEventPage struct {
	Items      []TunnelEvent `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

// TunnelPrivateAccessAdmission is the server-authoritative prerequisite set
// needed by a stable host before it can open a private route. It contains
// public routing and generation fences only, never a reusable grant.
type TunnelPrivateAccessAdmission struct {
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
	Hostname                             string    `json:"hostname,omitempty"`
	MatchType                            string    `json:"match_type"`
	WildcardSuffix                       string    `json:"wildcard_suffix,omitempty"`
	EdgeEndpoints                        []string  `json:"edge_endpoints"`
	ExpiresAt                            time.Time `json:"expires_at"`
	TunnelID                             string    `json:"tunnel_id"`
	CarrierConnectorID                   string    `json:"carrier_connector_id"`
}

type TunnelPrivateAccessSnapshot struct {
	Schema     string                         `json:"schema"`
	Kind       string                         `json:"kind"`
	Complete   bool                           `json:"complete"`
	Admissions []TunnelPrivateAccessAdmission `json:"admissions"`
}

type TunnelHealthDimension struct {
	Status string `json:"status"`
	Code   string `json:"code"`
}

type TunnelHealthDimensions struct {
	Service     TunnelHealthDimension `json:"service"`
	Edge        TunnelHealthDimension `json:"edge"`
	Config      TunnelHealthDimension `json:"config"`
	Route       TunnelHealthDimension `json:"route"`
	Origin      TunnelHealthDimension `json:"origin"`
	DNS         TunnelHealthDimension `json:"dns"`
	Certificate TunnelHealthDimension `json:"certificate"`
	Access      TunnelHealthDimension `json:"access"`
	Update      TunnelHealthDimension `json:"update"`
}

type TunnelHealth struct {
	Schema        string                 `json:"schema"`
	Kind          string                 `json:"kind"`
	ResourceKind  string                 `json:"resource_kind"`
	ResourceID    string                 `json:"resource_id"`
	OverallCode   string                 `json:"overall_code"`
	Dimensions    TunnelHealthDimensions `json:"dimensions"`
	Summary       string                 `json:"summary"`
	Since         time.Time              `json:"since"`
	Retrying      bool                   `json:"retrying"`
	NextRetryAt   *time.Time             `json:"next_retry_at,omitempty"`
	RepairAction  string                 `json:"repair_action"`
	CorrelationID string                 `json:"correlation_id"`
}

type TunnelLogEntry struct {
	Schema        string         `json:"schema"`
	Kind          string         `json:"kind"`
	ID            string         `json:"id"`
	TunnelID      string         `json:"tunnel_id"`
	PreviewID     string         `json:"preview_id,omitempty"`
	RouteID       string         `json:"route_id,omitempty"`
	ConnectorID   string         `json:"connector_id,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
	Level         string         `json:"level"`
	Component     string         `json:"component"`
	Code          string         `json:"code"`
	Message       string         `json:"message"`
	Metadata      map[string]any `json:"metadata"`
	CorrelationID string         `json:"correlation_id"`
	OccurredAt    time.Time      `json:"occurred_at"`
	Cursor        string         `json:"cursor"`
}

type TunnelLogPage struct {
	Items      []TunnelLogEntry `json:"items"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

func tunnelPath(parts ...string) (string, error) {
	path := "/v1"
	for _, part := range parts {
		if !validTunnelToken(part) {
			return "", errors.New("invalid tunnel resource identifier")
		}
		path += "/" + url.PathEscape(part)
	}
	return path, nil
}
func validTunnelToken(v string) bool {
	return v != "" && v == strings.TrimSpace(v) && len(v) <= 256 && !strings.ContainsAny(v, "\x00\r\n\t /\\?#%")
}

func containsTunnelControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r >= 0x7f && r <= 0x9f {
			return true
		}
	}
	return false
}

var tunnelNamePatternV1 = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
var tunnelRouteNamePatternV1 = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$`)

func validTunnelID(v string) bool {
	return len(v) >= 3 && len(v) <= 128 && validTunnelToken(v)
}

func validTunnelETag(v string) bool {
	return len(v) >= 3 && len(v) <= 512 && v[0] == '"' && v[len(v)-1] == '"' && !strings.ContainsAny(v[1:len(v)-1], "\"\r\n\x00")
}

func validateTunnelName(value string) error {
	if !tunnelNamePatternV1.MatchString(value) {
		return errors.New("tunnel name must be 1-63 ASCII letters, digits, '.', '_' or '-' and cannot start with punctuation")
	}
	return nil
}

func validateDomainHostname(value string) error {
	if value != strings.TrimSpace(value) || len(value) < 1 || len(value) > 253 || strings.ContainsAny(value, "\x00\r\n\t /?#@:") {
		return errors.New("invalid hostname")
	}
	value = strings.TrimPrefix(value, "*.")
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return errors.New("hostname must contain a DNS suffix")
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid hostname")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return errors.New("invalid hostname")
			}
		}
	}
	return nil
}

func validateTunnelOrigin(scheme, address string) error {
	if address == "" || address != strings.TrimSpace(address) || len(address) > 512 || strings.ContainsAny(address, "\x00\r\n\t") {
		return errors.New("origin address is not canonical")
	}
	switch scheme {
	case "http", "https", "h2c", "tcp":
		host, portText, err := net.SplitHostPort(address)
		if err != nil || host == "" || portText == "" || !validTunnelOriginHost(host) {
			return errors.New("origin address must contain a host and numeric port")
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
			return errors.New("origin port must be between 1 and 65535")
		}
	case "unix":
		if !strings.HasPrefix(address, "/") || path.Clean(address) != address {
			return errors.New("Unix origin must be a clean absolute path")
		}
	default:
		return errors.New("origin scheme must be http, https, h2c, unix, or tcp")
	}
	return nil
}

func validTunnelOriginHost(host string) bool {
	if host == "" || len(host) > 253 || host != strings.TrimSpace(host) || strings.ContainsAny(host, "\x00\r\n\t /?#@") {
		return false
	}
	if net.ParseIP(host) != nil || strings.EqualFold(host, "localhost") {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func validateTunnelCreateInput(in TunnelCreateInput) error {
	if err := validateTunnelName(in.Name); err != nil {
		return err
	}
	if in.AccessMode == "" {
		in.AccessMode = "public"
	}
	if in.AccessMode != "public" && in.AccessMode != "private" {
		return errors.New("access mode must be public or private")
	}
	if err := validateTunnelOrigin(in.Origin.Scheme, in.Origin.Address); err != nil {
		return err
	}
	if in.Origin.HostOverride != nil && !validTunnelOriginHost(*in.Origin.HostOverride) {
		return errors.New("origin host override is invalid")
	}
	if in.ExpiresAt != nil && in.ExpiresAt.IsZero() {
		return errors.New("expiry is invalid")
	}
	return nil
}

func validateHostMatch(match TunnelRouteHostMatch) error {
	switch match.Type {
	case "managed_exact", "exact":
		if match.WildcardLabels != nil || strings.HasPrefix(match.Hostname, "*.") {
			return errors.New("exact host match is invalid")
		}
		return validateDomainHostname(match.Hostname)
	case "one_label_wildcard":
		if match.WildcardLabels == nil || *match.WildcardLabels != 1 || !strings.HasPrefix(match.Hostname, "*.") {
			return errors.New("one-label wildcard match is invalid")
		}
		return validateDomainHostname(match.Hostname)
	case "catch_all":
		if match.Hostname != "" || match.WildcardLabels != nil {
			return errors.New("catch-all match cannot include a hostname")
		}
		return nil
	default:
		return errors.New("host match type is invalid")
	}
}

func validateRouteOrigin(origin TunnelRouteOrigin) error {
	if err := validateTunnelOrigin(origin.Scheme, origin.Address); err != nil {
		return err
	}
	if origin.HostOverride != nil && !validTunnelOriginHost(*origin.HostOverride) {
		return errors.New("host override is invalid")
	}
	if origin.Scheme != "https" {
		if origin.TLS != nil {
			return errors.New("TLS settings require an HTTPS origin")
		}
		return nil
	}
	if origin.TLS == nil {
		return errors.New("HTTPS origins require a TLS verification policy")
	}
	switch origin.TLS.Verification {
	case "system", "custom_ca", "insecure_development":
	default:
		return errors.New("TLS verification is invalid")
	}
	if origin.TLS.Verification == "custom_ca" && (origin.TLS.CAReference == nil || strings.TrimSpace(*origin.TLS.CAReference) == "") {
		return errors.New("custom CA reference is required")
	}
	if origin.TLS.Verification != "custom_ca" && origin.TLS.CAReference != nil {
		return errors.New("CA reference requires custom_ca verification")
	}
	if origin.TLS.ServerName != nil && !validTunnelOriginHost(*origin.TLS.ServerName) {
		return errors.New("TLS server name is invalid")
	}
	for _, reference := range []*string{origin.TLS.CAReference, origin.TLS.ClientCredentialReference} {
		if reference != nil && !validTunnelCredentialReference(*reference) {
			return errors.New("TLS credential reference is invalid")
		}
	}
	return nil
}

func validTunnelCredentialReference(value string) bool {
	if len(value) < 24 || len(value) > 512 || !strings.Contains(value, "://paperboat/") || strings.ContainsAny(value, "\x00\r\n\t ") {
		return false
	}
	prefix := strings.SplitN(value, "://", 2)[0]
	switch prefix {
	case "keychain", "credential-manager", "secret-service", "protected-file", "tpm":
		return true
	default:
		return false
	}
}

func validateTunnelRouteInput(in TunnelRouteInput, allowDefaults bool) error {
	if !tunnelRouteNamePatternV1.MatchString(in.Name) {
		return errors.New("route name is invalid")
	}
	if in.Protocol != "http" && in.Protocol != "tcp_private" {
		return errors.New("route protocol must be http or tcp_private")
	}
	if err := validateHostMatch(in.HostMatch); err != nil {
		return err
	}
	if in.PathPrefix != nil && (*in.PathPrefix == "" || len(*in.PathPrefix) > 2048 || !strings.HasPrefix(*in.PathPrefix, "/") || strings.ContainsAny(*in.PathPrefix, "\x00\r\n")) {
		return errors.New("path prefix is invalid")
	}
	if in.Protocol == "tcp_private" && (in.HostMatch.Type != "catch_all" || in.PathPrefix != nil || in.Origin.Scheme != "tcp") {
		return errors.New("private TCP routes require catch-all matching and a tcp origin")
	}
	if err := validateRouteOrigin(in.Origin); err != nil {
		return err
	}
	if !allowDefaults && in.Origin.Scheme == "https" && in.Origin.TLS == nil {
		return errors.New("HTTPS route response is missing TLS policy")
	}
	if in.Priority < 0 || in.Priority > 1000000 {
		return errors.New("priority is out of range")
	}
	if allowDefaults {
		if in.ConnectTimeoutMS != 0 && (in.ConnectTimeoutMS < 100 || in.ConnectTimeoutMS > 120000) {
			return errors.New("connect timeout is out of range")
		}
		if in.IdleTimeoutMS != 0 && (in.IdleTimeoutMS < 1000 || in.IdleTimeoutMS > 3600000) {
			return errors.New("idle timeout is out of range")
		}
		if in.MaxConcurrentStreams != 0 && (in.MaxConcurrentStreams < 1 || in.MaxConcurrentStreams > 10000) {
			return errors.New("stream limit is out of range")
		}
		return nil
	}
	if in.ConnectTimeoutMS < 100 || in.ConnectTimeoutMS > 120000 || in.IdleTimeoutMS < 1000 || in.IdleTimeoutMS > 3600000 || in.MaxConcurrentStreams < 1 || in.MaxConcurrentStreams > 10000 {
		return errors.New("route timeout or stream limit is out of range")
	}
	return nil
}

func validateTunnelDomainInput(in TunnelDomainInput) error {
	if err := validateDomainHostname(in.Hostname); err != nil {
		return err
	}
	if !validTunnelID(in.RouteID) {
		return errors.New("invalid route identifier")
	}
	if in.Provider == "" {
		in.Provider = "generic"
	}
	if in.Provider != "generic" && in.Provider != "cloudflare" && in.Provider != "route53" && in.Provider != "google_cloud_dns" && in.Provider != "digitalocean" && in.Provider != "namecheap" {
		return errors.New("invalid DNS provider")
	}
	if len(in.Provider) > 64 || strings.ContainsAny(in.Provider, "\x00\r\n") {
		return errors.New("invalid DNS provider")
	}
	if in.CertificateStrategy != "" && (len(in.CertificateStrategy) > 64 || strings.ContainsAny(in.CertificateStrategy, "\x00\r\n")) {
		return errors.New("invalid certificate strategy")
	}
	return nil
}

func validateOperation(v *TunnelOperation, resourceKind, resourceID string) error {
	if v == nil || v.Schema != TunnelV1Schema || v.Kind != "operation" || !validTunnelID(v.ID) || !validTunnelToken(v.ResourceKind) || !validTunnelID(v.ResourceID) || v.ResourceKind != resourceKind || v.ResourceID != resourceID || v.Phase == "" || v.State == "" || v.Progress < 0 || v.Progress > 100 || len(v.CorrelationID) > 256 || containsTunnelControl(v.Phase+v.State+v.CorrelationID) || v.CreatedAt.IsZero() || v.UpdatedAt.IsZero() || v.UpdatedAt.Before(v.CreatedAt) {
		return ErrUnsafeTunnelResponse
	}
	switch v.Phase {
	case "validating", "persisting", "waiting_for_dns", "issuing_certificate", "installing_service", "connecting", "checking_origin", "draining", "rolling_back", "ready", "failed":
	default:
		return ErrUnsafeTunnelResponse
	}
	switch v.State {
	case "pending", "running", "succeeded", "failed", "canceled":
	default:
		return ErrUnsafeTunnelResponse
	}
	if v.Error != nil {
		if v.Error.Schema != TunnelV1Schema || v.Error.Kind != "error" || v.Error.Code == "" || len(v.Error.Code) > 128 || len(v.Error.Message) > 1000 || len(v.Error.RepairAction) > 500 || containsTunnelControl(v.Error.Code+v.Error.Component+v.Error.Outcome+v.Error.RequestID+v.Error.CorrelationID+v.Error.Message+v.Error.RepairAction) {
			return ErrUnsafeTunnelResponse
		}
		v.Error.Message = redactTunnelText(v.Error.Message)
		v.Error.RepairAction = redactTunnelText(v.Error.RepairAction)
	}
	return nil
}
func pageQuery(cursor string, limit int) (string, error) {
	if limit < 1 || limit > 200 || len(cursor) > 4096 || strings.ContainsAny(cursor, "\x00\r\n") {
		return "", errors.New("invalid page request")
	}
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	return "?" + q.Encode(), nil
}
func validNextCursor(cursor string) bool {
	return len(cursor) <= 4096 && !strings.ContainsAny(cursor, "\x00\r\n")
}
func mutationHeaders(etag, key string) (http.Header, error) {
	if !validTunnelToken(key) {
		return nil, errors.New("invalid idempotency key")
	}
	h := http.Header{"Idempotency-Key": []string{key}}
	if etag != "" {
		if !validTunnelETag(etag) {
			return nil, errors.New("invalid ETag")
		}
		h.Set("If-Match", etag)
	}
	return h, nil
}

func requiredTunnelMutationHeaders(etag, key string) (http.Header, error) {
	if !validTunnelETag(etag) {
		return nil, errors.New("valid ETag is required for tunnel mutation")
	}
	return mutationHeaders(etag, key)
}
func validateTunnel(v Tunnel) error {
	if v.Schema != TunnelV1Schema || v.Kind != "tunnel" || !validTunnelID(v.ID) || !validTunnelID(v.AccountID) || !validTunnelID(v.CreatedByHostID) || !validTunnelID(v.CreatedByActorID) || !tunnelNamePatternV1.MatchString(v.Name) || (v.AccessMode != "public" && v.AccessMode != "private") || (v.DesiredState != "active" && v.DesiredState != "paused" && v.DesiredState != "deleted") || v.Generation < 1 || !validTunnelETag(v.ETag) || len(v.SummaryCode) > 128 || strings.ContainsAny(v.SummaryCode, "\x00\r\n") {
		return ErrUnsafeTunnelResponse
	}
	u, err := url.Parse(v.StableEndpoint)
	if err != nil || u == nil {
		return ErrUnsafeTunnelResponse
	}
	hostLabels := strings.Split(u.Hostname(), ".")
	if !tunnelEndpointUUIDPattern.MatchString(v.StableEndpointID) || u.Scheme != "https" || len(hostLabels) < 2 || hostLabels[0] != v.StableEndpointID || u.User != nil || u.Port() != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ErrUnsafeTunnelResponse
	}
	return nil
}
func validateRoute(v TunnelRoute) error {
	if v.Schema != TunnelV1Schema || v.Kind != "route" || !validTunnelID(v.ID) || !validTunnelID(v.TunnelID) || v.Generation < 1 || !validTunnelETag(v.ETag) || validateTunnelRouteInput(TunnelRouteInput{Name: v.Name, Protocol: v.Protocol, HostMatch: v.HostMatch, PathPrefix: v.PathPrefix, Origin: v.Origin, Priority: v.Priority, ConnectTimeoutMS: v.ConnectTimeoutMS, IdleTimeoutMS: v.IdleTimeoutMS, MaxConcurrentStreams: v.MaxConcurrentStreams}, false) != nil || (v.DesiredState != "active" && v.DesiredState != "disabled" && v.DesiredState != "deleted") {
		return ErrUnsafeTunnelResponse
	}
	return nil
}
func validateDomain(v *TunnelDomain) error {
	if v == nil || v.Schema != TunnelV1Schema || v.Kind != "domain_binding" || !validTunnelID(v.ID) || !validTunnelID(v.AccountID) || !validTunnelID(v.TunnelID) || !validTunnelID(v.RouteID) || v.Generation < 1 || !validTunnelETag(v.ETag) || validateDomainHostname(v.Hostname) != nil || v.DNS.Target == "" || len(v.DNS.Target) > 512 || len(v.DNS.ObservedRecords) > 64 || v.Certificate.State == "" || len(v.Certificate.Reference) > 512 {
		return ErrUnsafeTunnelResponse
	}
	if v.MatchType == "one_label_wildcard" {
		if v.WildcardLabels == nil || *v.WildcardLabels != 1 || !strings.HasPrefix(v.Hostname, "*.") {
			return ErrUnsafeTunnelResponse
		}
	} else if v.MatchType != "exact" || v.WildcardLabels != nil {
		return ErrUnsafeTunnelResponse
	}
	switch v.State {
	case "requested", "waiting_dns", "verified", "issuing_tls", "ready", "conflict", "dns_error", "tls_error", "expired", "quarantined":
	default:
		return ErrUnsafeTunnelResponse
	}
	switch v.Certificate.State {
	case "not_requested", "issuing", "ready", "renewing", "failed", "expired", "revoked":
	default:
		return ErrUnsafeTunnelResponse
	}
	if v.Certificate.Failure != nil {
		clean, err := redactTunnelMetadata(v.Certificate.Failure, 0)
		if err != nil {
			return err
		}
		v.Certificate.Failure = clean
	}
	return nil
}
func validateConnector(v TunnelConnector) error {
	if v.Schema != TunnelV1Schema || v.Kind != "connector" || !validTunnelID(v.ID) || !validTunnelID(v.TunnelID) || !validTunnelID(v.HostID) || v.Generation < 1 || v.RotationGeneration < 1 || !validTunnelETag(v.ETag) || v.ProtocolVersion != "1.0" || !validTunnelCredentialReference(v.CredentialReference) || (v.DesiredState != "active" && v.DesiredState != "draining" && v.DesiredState != "revoked") || (v.DrainState != "accepting" && v.DrainState != "draining" && v.DrainState != "drained" && v.DrainState != "forced_closed") {
		return ErrUnsafeTunnelResponse
	}
	return nil
}

func validateHealth(v *TunnelHealth, tunnelID string) error {
	if v == nil || v.Schema != TunnelV1Schema || v.Kind != "health" || v.ResourceKind != "tunnel" || v.ResourceID != tunnelID || v.OverallCode == "" || len(v.Summary) > 1000 || len(v.RepairAction) > 500 || len(v.CorrelationID) > 256 || containsTunnelControl(v.OverallCode+v.Summary+v.RepairAction+v.CorrelationID) {
		return ErrUnsafeTunnelResponse
	}
	for _, dimension := range []TunnelHealthDimension{v.Dimensions.Service, v.Dimensions.Edge, v.Dimensions.Config, v.Dimensions.Route, v.Dimensions.Origin, v.Dimensions.DNS, v.Dimensions.Certificate, v.Dimensions.Access, v.Dimensions.Update} {
		if dimension.Status == "" || len(dimension.Status) > 32 || len(dimension.Code) > 128 || containsTunnelControl(dimension.Status+dimension.Code) {
			return ErrUnsafeTunnelResponse
		}
	}
	v.Summary = redactTunnelText(v.Summary)
	v.RepairAction = redactTunnelText(v.RepairAction)
	return nil
}

func validateLogEntry(v *TunnelLogEntry, tunnelID string) error {
	if v == nil || v.Schema != TunnelV1Schema || v.Kind != "log_entry" || !validTunnelToken(v.ID) || v.TunnelID != tunnelID || v.Code == "" || len(v.Code) > 128 || len(v.Message) > 4096 || len(v.Metadata) > 64 || len(v.Cursor) > 4096 || containsTunnelControl(v.Code+v.Level+v.Component+v.Message) {
		return ErrUnsafeTunnelResponse
	}
	metadata, err := redactTunnelMetadata(v.Metadata, 0)
	if err != nil {
		return err
	}
	v.Metadata = metadata
	v.Message = redactTunnelText(v.Message)
	return nil
}

func redactTunnelMetadata(value map[string]any, depth int) (map[string]any, error) {
	if depth > 6 || len(value) > 64 {
		return nil, ErrUnsafeTunnelResponse
	}
	out := make(map[string]any, len(value))
	for key, item := range value {
		if key == "" || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n") {
			return nil, ErrUnsafeTunnelResponse
		}
		lower := strings.ToLower(key)
		if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "authorization") || strings.Contains(lower, "cookie") || strings.Contains(lower, "private_key") {
			out[key] = "[REDACTED]"
			continue
		}
		switch typed := item.(type) {
		case map[string]any:
			nested, err := redactTunnelMetadata(typed, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = nested
		case []any:
			if len(typed) > 128 {
				return nil, ErrUnsafeTunnelResponse
			}
			copyValue := make([]any, len(typed))
			for i, v := range typed {
				if nested, ok := v.(map[string]any); ok {
					clean, err := redactTunnelMetadata(nested, depth+1)
					if err != nil {
						return nil, err
					}
					copyValue[i] = clean
				} else if text, ok := v.(string); ok {
					if len(text) > 1000 {
						return nil, ErrUnsafeTunnelResponse
					}
					copyValue[i] = redactTunnelText(text)
				} else if number, ok := v.(float64); ok {
					if math.IsNaN(number) || math.IsInf(number, 0) {
						return nil, ErrUnsafeTunnelResponse
					}
					copyValue[i] = number
				} else if v == nil {
					copyValue[i] = nil
				} else if _, ok := v.(bool); ok {
					copyValue[i] = v
				} else {
					return nil, ErrUnsafeTunnelResponse
				}
			}
			out[key] = copyValue
		case string:
			if len(typed) > 1000 {
				return nil, ErrUnsafeTunnelResponse
			}
			out[key] = redactTunnelText(typed)
		case float64:
			if math.IsNaN(typed) || math.IsInf(typed, 0) {
				return nil, ErrUnsafeTunnelResponse
			}
			out[key] = item
		case bool, nil:
			out[key] = item
		default:
			return nil, ErrUnsafeTunnelResponse
		}
	}
	return out, nil
}

func redactTunnelText(value string) string {
	if len(value) > 4096 {
		return "[REDACTED]"
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"bearer ", "token", "secret", "password", "private_key", "authorization:", "cookie"} {
		if strings.Contains(lower, marker) {
			return "[REDACTED]"
		}
	}
	return value
}
func responseETag(headers http.Header, body string) error {
	h := headers.Get("ETag")
	if h == "" || h != body {
		return ErrUnsafeTunnelResponse
	}
	return nil
}

// tunnelWireError mirrors the complete v1 error envelope. Keep this separate
// from APIError so server-owned diagnostic fields never accidentally become
// part of a normal success response type.
type tunnelWireError struct {
	Schema        string         `json:"schema"`
	Kind          string         `json:"kind"`
	Code          string         `json:"code"`
	Component     string         `json:"component"`
	Message       string         `json:"message"`
	Outcome       string         `json:"outcome"`
	Retryable     *bool          `json:"retryable"`
	RetryAt       *time.Time     `json:"retry_at"`
	RepairAction  string         `json:"repair_action"`
	RequestID     string         `json:"request_id"`
	CorrelationID string         `json:"correlation_id"`
	Details       map[string]any `json:"details"`
}

type tunnelWireEnvelope struct {
	Data  json.RawMessage `json:"data"`
	Error tunnelWireError `json:"error"`
}

// decodeTunnelJSONStrict rejects duplicate object keys as well as unknown or
// trailing fields. encoding/json alone rejects unknown fields but silently
// accepts duplicates, which is unsafe for signed/idempotent request and
// response documents.
func decodeTunnelJSONStrict(raw []byte, out any) error {
	if err := rejectTunnelDuplicateJSON(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func rejectTunnelDuplicateJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				key, ok := (func() (string, bool) {
					token, err := decoder.Token()
					if err != nil {
						return "", false
					}
					value, ok := token.(string)
					return value, ok
				})()
				if !ok {
					return errors.New("invalid JSON object key")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON field %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("invalid JSON object")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("invalid JSON array")
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func decodeTunnelData(raw json.RawMessage, out any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return errors.New("empty response data")
	}
	return decodeTunnelJSONStrict(raw, out)
}

func (c *Client) doTunnelRequest(ctx context.Context, method, requestPath string, body any, out any, headers http.Header, responseHeaders *http.Header) error {
	if c == nil || strings.TrimSpace(c.baseURL) == "" {
		return errors.New("paperboat-server base URL is not configured")
	}
	if requestPath == "" || !strings.HasPrefix(requestPath, "/v1/") || strings.ContainsAny(requestPath, "\x00\r\n") || strings.Contains(requestPath, "://") {
		return errors.New("invalid tunnel API path")
	}
	var encodedBody []byte
	if body != nil {
		var err error
		encodedBody, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode tunnel request body: %w", err)
		}
		if len(encodedBody) > maxTunnelRequestBytes {
			return ErrUnsafeTunnelResponse
		}
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(encodedBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+requestPath, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "paperboat/"+buildinfo.Version)
	req.Header.Set("X-Paperboat-Client", "paperboat")
	req.Header.Set("X-Paperboat-Protocol", buildinfo.ProtocolVersion)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if c.machineAuth != nil && method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		token, tokenErr := c.machineAuth.Token(ctx)
		if tokenErr != nil {
			return fmt.Errorf("machine authentication token: %w", tokenErr)
		}
		if strings.TrimSpace(token) == "" {
			return errors.New("machine authentication token is empty")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Paperboat-Machine-Identity", token)
		operationID := strings.TrimSpace(req.Header.Get("Idempotency-Key"))
		if operationID == "" {
			return errors.New("machine-authenticated mutation requires Idempotency-Key")
		}
		proof, proofErr := c.machineAuth.Proof(ctx, operationID, method, requestPath, encodedBody)
		if proofErr != nil {
			return fmt.Errorf("machine authentication proof: %w", proofErr)
		}
		if len(proof) == 0 {
			return errors.New("machine authentication proof is empty")
		}
		req.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	}
	httpClient := c.http
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}
	// Clone the configured client so this request cannot inherit the default
	// redirect-following behavior, and never send auth headers to a Location.
	redirectSafeClient := *httpClient
	redirectSafeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return ErrTunnelRedirect }
	resp, err := redirectSafeClient.Do(req)
	if err != nil {
		if errors.Is(err, ErrTunnelRedirect) {
			return ErrTunnelRedirect
		}
		return fmt.Errorf("call %s %s: %w", method, requestPath, err)
	}
	defer resp.Body.Close()
	if responseHeaders != nil {
		*responseHeaders = resp.Header.Clone()
	}
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxTunnelResponseBytes+1))
	if readErr != nil {
		return fmt.Errorf("read %s %s response: %w", method, requestPath, readErr)
	}
	if len(raw) > maxTunnelResponseBytes {
		return ErrUnsafeTunnelResponse
	}
	if resp.StatusCode == http.StatusNoContent {
		if out != nil && len(bytes.TrimSpace(raw)) != 0 {
			return ErrUnsafeTunnelResponse
		}
		return nil
	}
	var envelope tunnelWireEnvelope
	if err := decodeTunnelJSONStrict(raw, &envelope); err != nil {
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return &APIError{Status: resp.StatusCode, Code: "invalid_server_response", Message: "paperboat-server returned an invalid error response", RequestID: responseRequestID(resp.Header)}
		}
		return fmt.Errorf("decode %s %s response: %w", method, requestPath, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusUpgradeRequired || envelope.Error.Code == "incompatible_client_version" {
			required, _ := envelope.Error.Details["required_protocol"].(string)
			return &ErrIncompatibleVersion{Required: required, Message: redactTunnelText(envelope.Error.Message)}
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return ErrUnauthenticated
		}
		details, detailsErr := redactTunnelMetadata(envelope.Error.Details, 0)
		if detailsErr != nil {
			details = nil
		}
		code := envelope.Error.Code
		if code == "" {
			code = "server_error"
		}
		return &APIError{Status: resp.StatusCode, Code: code, Message: redactTunnelText(envelope.Error.Message), RequestID: responseRequestID(resp.Header), Details: details}
	}
	if out == nil {
		return nil
	}
	if err := decodeTunnelData(envelope.Data, out); err != nil {
		return fmt.Errorf("decode %s %s data: %w", method, requestPath, err)
	}
	return nil
}

func tunnelResponseKind(raw json.RawMessage) (string, error) {
	var discriminator struct {
		Kind string `json:"kind"`
	}
	if err := rejectTunnelDuplicateJSON(raw); err != nil {
		return "", err
	}
	if err := json.Unmarshal(raw, &discriminator); err != nil {
		return "", err
	}
	return discriminator.Kind, nil
}

// UnmarshalJSON accepts the canonical resource or operation returned by the server.
// It retains the existing Go mutation result shape used by
// pb while accepting that wire union and the older test/integration wrapper.
func (m *TunnelMutation) UnmarshalJSON(raw []byte) error {
	*m = TunnelMutation{}
	kind, err := tunnelResponseKind(raw)
	if err != nil {
		return err
	}
	switch kind {
	case "tunnel":
		if err := decodeTunnelJSONStrict(raw, &m.Tunnel); err != nil {
			return err
		}
	case "operation":
		if err := decodeTunnelJSONStrict(raw, &m.Operation); err != nil {
			return err
		}
		m.Tunnel.ID = m.Operation.ResourceID
	default:
		type plain TunnelMutation
		var value plain
		if err := decodeTunnelJSONStrict(raw, &value); err != nil {
			return err
		}
		*m = TunnelMutation(value)
	}
	return nil
}

func (m *TunnelRouteMutation) UnmarshalJSON(raw []byte) error {
	*m = TunnelRouteMutation{}
	kind, err := tunnelResponseKind(raw)
	if err != nil {
		return err
	}
	switch kind {
	case "route":
		if err := decodeTunnelJSONStrict(raw, &m.Route); err != nil {
			return err
		}
	case "operation":
		if err := decodeTunnelJSONStrict(raw, &m.Operation); err != nil {
			return err
		}
		m.Route.ID = m.Operation.ResourceID
	default:
		type plain TunnelRouteMutation
		var value plain
		if err := decodeTunnelJSONStrict(raw, &value); err != nil {
			return err
		}
		*m = TunnelRouteMutation(value)
	}
	return nil
}

func (m *TunnelDomainMutation) UnmarshalJSON(raw []byte) error {
	*m = TunnelDomainMutation{}
	kind, err := tunnelResponseKind(raw)
	if err != nil {
		return err
	}
	switch kind {
	case "domain_binding":
		if err := decodeTunnelJSONStrict(raw, &m.Domain); err != nil {
			return err
		}
	case "operation":
		if err := decodeTunnelJSONStrict(raw, &m.Operation); err != nil {
			return err
		}
		m.Domain.ID = m.Operation.ResourceID
	default:
		type plain TunnelDomainMutation
		var value plain
		if err := decodeTunnelJSONStrict(raw, &value); err != nil {
			return err
		}
		*m = TunnelDomainMutation(value)
	}
	return nil
}

func (m *TunnelConnectorMutation) UnmarshalJSON(raw []byte) error {
	*m = TunnelConnectorMutation{}
	kind, err := tunnelResponseKind(raw)
	if err != nil {
		return err
	}
	switch kind {
	case "connector":
		if err := decodeTunnelJSONStrict(raw, &m.Connector); err != nil {
			return err
		}
	case "operation":
		if err := decodeTunnelJSONStrict(raw, &m.Operation); err != nil {
			return err
		}
		m.Connector.ID = m.Operation.ResourceID
	default:
		type plain TunnelConnectorMutation
		var value plain
		if err := decodeTunnelJSONStrict(raw, &value); err != nil {
			return err
		}
		*m = TunnelConnectorMutation(value)
	}
	return nil
}

func (c *Client) ListTunnelsV1(ctx context.Context, cursor string, limit int) (TunnelPage, error) {
	q, e := pageQuery(cursor, limit)
	if e != nil {
		return TunnelPage{}, e
	}
	var out TunnelPage
	e = c.doTunnelRequest(ctx, http.MethodGet, "/v1/tunnels"+q, nil, &out, nil, nil)
	if e == nil {
		if len(out.Items) > limit || !validNextCursor(out.NextCursor) {
			return TunnelPage{}, ErrUnsafeTunnelResponse
		}
		for _, v := range out.Items {
			if e = validateTunnel(v); e != nil {
				break
			}
		}
	}
	return out, e
}
func (c *Client) GetTunnelV1(ctx context.Context, id string) (Tunnel, error) {
	p, e := tunnelPath("tunnels", id)
	if e != nil {
		return Tunnel{}, e
	}
	var out Tunnel
	var h http.Header
	// The ETag is the strong OCC token for the exact tunnel projection. A
	// compression proxy may weaken it, so request the identity representation
	// before comparing the header to the body ETag.
	e = c.doTunnelRequest(ctx, http.MethodGet, p, nil, &out, http.Header{"Accept-Encoding": []string{"identity"}}, &h)
	if e == nil {
		e = validateTunnel(out)
	}
	if e == nil && out.ID != id {
		e = ErrUnsafeTunnelResponse
	}
	if e == nil {
		e = responseETag(h, out.ETag)
	}
	return out, e
}
func (c *Client) CreateTunnelV1(ctx context.Context, in TunnelCreateInput, key string) (TunnelMutation, error) {
	if err := validateTunnelCreateInput(in); err != nil {
		return TunnelMutation{}, err
	}
	h, e := mutationHeaders("", key)
	if e != nil {
		return TunnelMutation{}, e
	}
	var out TunnelMutation
	e = c.doTunnelRequest(ctx, http.MethodPost, "/v1/tunnels", in, &out, h, nil)
	if e != nil {
		return out, e
	}
	if out.Operation.Schema != "" {
		// An operation response carries the durable resource ID but not the
		// resource projection. Validate that identity before using it for the
		// follow-up read; this keeps an untrusted response from selecting an
		// arbitrary path.
		if e = validateOperation(&out.Operation, "tunnel", out.Tunnel.ID); e != nil {
			return out, e
		}
	}
	operationOnly := out.Tunnel.Schema == ""
	if operationOnly {
		if out.Operation.Schema == "" {
			return out, ErrUnsafeTunnelResponse
		}
		if c.machineAuth != nil && strings.TrimSpace(c.accessToken) == "" {
			return out, ErrMachineAuthReadRequiresClientSession
		}
		resolved, fetchErr := c.GetTunnelV1(ctx, out.Operation.ResourceID)
		if fetchErr != nil {
			return out, fmt.Errorf("fetch tunnel after operation %s: %w", out.Operation.ID, fetchErr)
		}
		if resolved.ID != out.Operation.ResourceID {
			return out, ErrUnsafeTunnelResponse
		}
		out.Tunnel = resolved
	}
	if e = validateTunnel(out.Tunnel); e != nil {
		return out, e
	}
	if operationOnly {
		if out.Tunnel.Name != in.Name {
			return out, ErrUnsafeTunnelResponse
		}
		wantAccessMode := in.AccessMode
		if wantAccessMode == "" {
			wantAccessMode = "public"
		}
		if out.Tunnel.AccessMode != wantAccessMode {
			return out, ErrUnsafeTunnelResponse
		}
	}
	if out.Operation.Schema != "" {
		if e = validateOperation(&out.Operation, "tunnel", out.Tunnel.ID); e != nil {
			return out, e
		}
	}
	return out, e
}
func (c *Client) PatchTunnelV1(ctx context.Context, id, etag, key string, in TunnelPatchInput) (TunnelMutation, error) {
	if in.Name == nil && in.AccessMode == nil && in.ExpiresAt == nil {
		return TunnelMutation{}, errors.New("tunnel patch must contain a field")
	}
	if in.Name != nil {
		if err := validateTunnelName(*in.Name); err != nil {
			return TunnelMutation{}, err
		}
	}
	if in.AccessMode != nil && *in.AccessMode != "public" && *in.AccessMode != "private" {
		return TunnelMutation{}, errors.New("access mode must be public or private")
	}
	return c.tunnelMutation(ctx, http.MethodPatch, id, "", etag, key, in)
}
func (c *Client) ChangeTunnelStateV1(ctx context.Context, id, action, etag, key string) (TunnelMutation, error) {
	if action != "pause" && action != "resume" && action != "delete" {
		return TunnelMutation{}, errors.New("invalid tunnel action")
	}
	method := http.MethodPost
	if action == "delete" {
		method = http.MethodDelete
	}
	return c.tunnelMutation(ctx, method, id, action, etag, key, struct{}{})
}
func (c *Client) tunnelMutation(ctx context.Context, method, id, action, etag, key string, body any) (TunnelMutation, error) {
	p, e := tunnelPath("tunnels", id)
	if action != "" && action != "delete" {
		p += "/" + action
	}
	if e != nil {
		return TunnelMutation{}, e
	}
	h, e := requiredTunnelMutationHeaders(etag, key)
	if e != nil {
		return TunnelMutation{}, e
	}
	var out TunnelMutation
	e = c.doTunnelRequest(ctx, method, p, body, &out, h, nil)
	if e == nil && out.Tunnel.Schema != "" {
		e = validateTunnel(out.Tunnel)
	}
	if e == nil && out.Operation.Schema != "" {
		e = validateOperation(&out.Operation, "tunnel", out.Tunnel.ID)
	}
	if e == nil && out.Tunnel.Schema == "" && out.Operation.Schema == "" {
		e = ErrUnsafeTunnelResponse
	}
	return out, e
}

func (c *Client) ListTunnelRoutesV1(ctx context.Context, tunnel, cursor string, limit int) (TunnelRoutePage, error) {
	p, e := tunnelPath("tunnels", tunnel, "routes")
	if e != nil {
		return TunnelRoutePage{}, e
	}
	q, e := pageQuery(cursor, limit)
	if e != nil {
		return TunnelRoutePage{}, e
	}
	var out TunnelRoutePage
	e = c.doTunnelRequest(ctx, http.MethodGet, p+q, nil, &out, nil, nil)
	if e == nil {
		if len(out.Items) > limit || !validNextCursor(out.NextCursor) {
			return TunnelRoutePage{}, ErrUnsafeTunnelResponse
		}
		for _, v := range out.Items {
			if e = validateRoute(v); e == nil && v.TunnelID != tunnel {
				e = ErrUnsafeTunnelResponse
			}
			if e != nil {
				break
			}
		}
	}
	return out, e
}
func (c *Client) GetTunnelRouteV1(ctx context.Context, tunnel, id string) (TunnelRoute, error) {
	p, e := tunnelPath("tunnels", tunnel, "routes", id)
	if e != nil {
		return TunnelRoute{}, e
	}
	var out TunnelRoute
	var h http.Header
	e = c.doTunnelRequest(ctx, http.MethodGet, p, nil, &out, nil, &h)
	if e == nil {
		e = validateRoute(out)
	}
	if e == nil && out.TunnelID != tunnel {
		e = ErrUnsafeTunnelResponse
	}
	if e == nil {
		e = responseETag(h, out.ETag)
	}
	return out, e
}
func (c *Client) CreateTunnelRouteV1(ctx context.Context, tunnel, key string, in TunnelRouteInput) (TunnelRouteMutation, error) {
	if err := validateTunnelRouteInput(in, true); err != nil {
		return TunnelRouteMutation{}, err
	}
	p, e := tunnelPath("tunnels", tunnel, "routes")
	if e != nil {
		return TunnelRouteMutation{}, e
	}
	return c.routeMutation(ctx, http.MethodPost, p, "", key, in)
}
func (c *Client) PatchTunnelRouteV1(ctx context.Context, tunnel, id, etag, key string, in TunnelRoutePatch) (TunnelRouteMutation, error) {
	if in.Name == nil && in.Protocol == nil && in.HostMatch == nil && !in.PathPrefixSet && in.PathPrefix == nil && in.Origin == nil && in.Priority == nil && in.ConnectTimeoutMS == nil && in.IdleTimeoutMS == nil && in.MaxConcurrentStreams == nil && in.DesiredState == nil {
		return TunnelRouteMutation{}, errors.New("route patch must contain a field")
	}
	if in.Name != nil && !tunnelRouteNamePatternV1.MatchString(*in.Name) {
		return TunnelRouteMutation{}, errors.New("route name is invalid")
	}
	if in.Protocol != nil && *in.Protocol != "http" && *in.Protocol != "tcp_private" {
		return TunnelRouteMutation{}, errors.New("route protocol must be http or tcp_private")
	}
	if in.HostMatch != nil {
		if err := validateHostMatch(*in.HostMatch); err != nil {
			return TunnelRouteMutation{}, err
		}
	}
	if in.Origin != nil {
		if err := validateRouteOrigin(*in.Origin); err != nil {
			return TunnelRouteMutation{}, err
		}
	}
	if in.PathPrefix != nil && (*in.PathPrefix == "" || len(*in.PathPrefix) > 2048 || !strings.HasPrefix(*in.PathPrefix, "/") || strings.ContainsAny(*in.PathPrefix, "\x00\r\n")) {
		return TunnelRouteMutation{}, errors.New("path prefix is invalid")
	}
	if in.Priority != nil && (*in.Priority < 0 || *in.Priority > 1000000) {
		return TunnelRouteMutation{}, errors.New("priority is out of range")
	}
	if in.ConnectTimeoutMS != nil && (*in.ConnectTimeoutMS < 100 || *in.ConnectTimeoutMS > 120000) {
		return TunnelRouteMutation{}, errors.New("connect timeout is out of range")
	}
	if in.IdleTimeoutMS != nil && (*in.IdleTimeoutMS < 1000 || *in.IdleTimeoutMS > 3600000) {
		return TunnelRouteMutation{}, errors.New("idle timeout is out of range")
	}
	if in.MaxConcurrentStreams != nil && (*in.MaxConcurrentStreams < 1 || *in.MaxConcurrentStreams > 10000) {
		return TunnelRouteMutation{}, errors.New("stream limit is out of range")
	}
	if in.DesiredState != nil && *in.DesiredState != "active" && *in.DesiredState != "disabled" {
		return TunnelRouteMutation{}, errors.New("route state must be active or disabled")
	}
	p, e := tunnelPath("tunnels", tunnel, "routes", id)
	if e != nil {
		return TunnelRouteMutation{}, e
	}
	return c.routeMutation(ctx, http.MethodPatch, p, etag, key, in)
}
func (c *Client) DeleteTunnelRouteV1(ctx context.Context, tunnel, id, etag, key string) (TunnelRouteMutation, error) {
	p, e := tunnelPath("tunnels", tunnel, "routes", id)
	if e != nil {
		return TunnelRouteMutation{}, e
	}
	return c.routeMutation(ctx, http.MethodDelete, p, etag, key, struct{}{})
}
func (c *Client) routeMutation(ctx context.Context, method, path, etag, key string, body any) (TunnelRouteMutation, error) {
	var h http.Header
	var e error
	if method == http.MethodPost && strings.HasSuffix(path, "/routes") {
		h, e = mutationHeaders("", key)
	} else {
		h, e = requiredTunnelMutationHeaders(etag, key)
	}
	if e != nil {
		return TunnelRouteMutation{}, e
	}
	var out TunnelRouteMutation
	e = c.doTunnelRequest(ctx, method, path, body, &out, h, nil)
	if e == nil && out.Route.Schema != "" {
		e = validateRoute(out.Route)
	}
	if e == nil && out.Route.Schema != "" && out.Route.TunnelID != strings.Split(strings.TrimPrefix(path, "/v1/tunnels/"), "/")[0] {
		e = ErrUnsafeTunnelResponse
	}
	if e == nil && out.Operation.Schema != "" {
		e = validateOperation(&out.Operation, "route", out.Operation.ResourceID)
	}
	if e == nil && out.Route.Schema == "" && out.Operation.Schema == "" {
		e = ErrUnsafeTunnelResponse
	}
	return out, e
}

func (c *Client) ListTunnelDomainsV1(ctx context.Context, tunnel, cursor string, limit int) (TunnelDomainPage, error) {
	p, e := tunnelPath("tunnels", tunnel, "domains")
	if e != nil {
		return TunnelDomainPage{}, e
	}
	q, e := pageQuery(cursor, limit)
	if e != nil {
		return TunnelDomainPage{}, e
	}
	var out TunnelDomainPage
	e = c.doTunnelRequest(ctx, http.MethodGet, p+q, nil, &out, nil, nil)
	if e == nil {
		if len(out.Items) > limit || !validNextCursor(out.NextCursor) {
			return TunnelDomainPage{}, ErrUnsafeTunnelResponse
		}
		for i := range out.Items {
			if e = validateDomain(&out.Items[i]); e == nil && out.Items[i].TunnelID != tunnel {
				e = ErrUnsafeTunnelResponse
			}
			if e != nil {
				break
			}
		}
	}
	return out, e
}
func (c *Client) GetTunnelDomainV1(ctx context.Context, tunnel, id string) (TunnelDomain, error) {
	p, e := tunnelPath("tunnels", tunnel, "domains", id)
	if e != nil {
		return TunnelDomain{}, e
	}
	var out TunnelDomain
	var h http.Header
	e = c.doTunnelRequest(ctx, http.MethodGet, p, nil, &out, nil, &h)
	if e == nil {
		e = validateDomain(&out)
	}
	if e == nil && out.TunnelID != tunnel {
		e = ErrUnsafeTunnelResponse
	}
	if e == nil {
		e = responseETag(h, out.ETag)
	}
	return out, e
}
func (c *Client) CreateTunnelDomainV1(ctx context.Context, tunnel, key string, in TunnelDomainInput) (TunnelDomainMutation, error) {
	if err := validateTunnelDomainInput(in); err != nil {
		return TunnelDomainMutation{}, err
	}
	p, e := tunnelPath("tunnels", tunnel, "domains")
	if e != nil {
		return TunnelDomainMutation{}, e
	}
	return c.domainMutation(ctx, http.MethodPost, p, "", key, in)
}
func (c *Client) MutateTunnelDomainV1(ctx context.Context, tunnel, id, action, etag, key string) (TunnelDomainMutation, error) {
	if action != "delete" && action != "verify" {
		return TunnelDomainMutation{}, errors.New("invalid domain action")
	}
	p, e := tunnelPath("tunnels", tunnel, "domains", id)
	if action == "verify" {
		p += "/verify"
	}
	if e != nil {
		return TunnelDomainMutation{}, e
	}
	method := http.MethodPost
	if action == "delete" {
		method = http.MethodDelete
	}
	return c.domainMutation(ctx, method, p, etag, key, struct{}{})
}
func (c *Client) domainMutation(ctx context.Context, method, path, etag, key string, body any) (TunnelDomainMutation, error) {
	var h http.Header
	var e error
	if method == http.MethodPost && strings.HasSuffix(path, "/domains") {
		h, e = mutationHeaders("", key)
	} else {
		h, e = requiredTunnelMutationHeaders(etag, key)
	}
	if e != nil {
		return TunnelDomainMutation{}, e
	}
	var out TunnelDomainMutation
	e = c.doTunnelRequest(ctx, method, path, body, &out, h, nil)
	if e == nil && out.Domain.Schema != "" {
		e = validateDomain(&out.Domain)
	}
	parts := strings.Split(strings.TrimPrefix(path, "/v1/tunnels/"), "/")
	if e == nil && out.Domain.Schema != "" && (len(parts) < 1 || out.Domain.TunnelID != parts[0]) {
		e = ErrUnsafeTunnelResponse
	}
	if e == nil && out.Operation.Schema != "" {
		e = validateOperation(&out.Operation, "domain_binding", out.Operation.ResourceID)
	}
	if e == nil && out.Domain.Schema == "" && out.Operation.Schema == "" {
		e = ErrUnsafeTunnelResponse
	}
	return out, e
}
func (c *Client) TunnelDomainInstructionsV1(ctx context.Context, tunnel, id string) (TunnelDNSInstructions, error) {
	p, e := tunnelPath("tunnels", tunnel, "domains", id)
	if e != nil {
		return TunnelDNSInstructions{}, e
	}
	var out TunnelDNSInstructions
	e = c.doStrict(ctx, http.MethodGet, p+"/instructions", nil, &out)
	if e == nil {
		if out.Schema != TunnelV1Schema || out.Kind != "dns_instructions" || out.TunnelID != tunnel || out.DomainID != id || validateDomainHostname(out.Hostname) != nil || out.Provider == "" || len(out.Provider) > 64 || out.CertificateStrategy == "" || len(out.CertificateStrategy) > 64 || out.VerificationState == "" || len(out.VerificationState) > 64 || len(out.Records) > 32 || len(out.Note) > 2000 || containsTunnelControl(out.Provider+out.CertificateStrategy+out.VerificationState+out.Note) {
			e = ErrUnsafeTunnelResponse
		}
		for _, record := range out.Records {
			if record.Name == "" || len(record.Name) > 253 || record.Type == "" || len(record.Type) > 16 || record.Value == "" || len(record.Value) > 2048 || record.TTL < 0 || record.TTL > 604800 || containsTunnelControl(record.Name+record.Type+record.Value) {
				e = ErrUnsafeTunnelResponse
				break
			}
		}
		out.Note = redactTunnelText(out.Note)
	}
	return out, e
}

func (c *Client) ListTunnelConnectorsV1(ctx context.Context, tunnel, cursor string, limit int) (TunnelConnectorPage, error) {
	p, e := tunnelPath("tunnels", tunnel, "connectors")
	if e != nil {
		return TunnelConnectorPage{}, e
	}
	q, e := pageQuery(cursor, limit)
	if e != nil {
		return TunnelConnectorPage{}, e
	}
	var out TunnelConnectorPage
	e = c.doTunnelRequest(ctx, http.MethodGet, p+q, nil, &out, nil, nil)
	if e == nil {
		if len(out.Items) > limit || !validNextCursor(out.NextCursor) {
			return TunnelConnectorPage{}, ErrUnsafeTunnelResponse
		}
		for _, v := range out.Items {
			if e = validateConnector(v); e == nil && v.TunnelID != tunnel {
				e = ErrUnsafeTunnelResponse
			}
			if e != nil {
				break
			}
		}
	}
	return out, e
}
func (c *Client) GetTunnelConnectorV1(ctx context.Context, tunnel, id string) (TunnelConnector, error) {
	p, e := tunnelPath("tunnels", tunnel, "connectors", id)
	if e != nil {
		return TunnelConnector{}, e
	}
	var out TunnelConnector
	var h http.Header
	e = c.doTunnelRequest(ctx, http.MethodGet, p, nil, &out, nil, &h)
	if e == nil {
		e = validateConnector(out)
	}
	if e == nil && out.TunnelID != tunnel {
		e = ErrUnsafeTunnelResponse
	}
	if e == nil {
		e = responseETag(h, out.ETag)
	}
	return out, e
}
func (c *Client) MutateTunnelConnectorV1(ctx context.Context, tunnel, id, action, etag, key string) (TunnelConnectorMutation, error) {
	if action != "drain" && action != "revoke" {
		return TunnelConnectorMutation{}, errors.New("invalid connector action")
	}
	p, e := tunnelPath("tunnels", tunnel, "connectors", id)
	if action == "drain" {
		p += "/drain"
	}
	if e != nil {
		return TunnelConnectorMutation{}, e
	}
	method := http.MethodPost
	if action == "revoke" {
		method = http.MethodDelete
	}
	h, e := requiredTunnelMutationHeaders(etag, key)
	if e != nil {
		return TunnelConnectorMutation{}, e
	}
	var out TunnelConnectorMutation
	e = c.doTunnelRequest(ctx, method, p, struct{}{}, &out, h, nil)
	if e == nil && out.Connector.Schema != "" {
		e = validateConnector(out.Connector)
	}
	if e == nil && out.Connector.Schema != "" && out.Connector.TunnelID != tunnel {
		e = ErrUnsafeTunnelResponse
	}
	if e == nil && out.Operation.Schema != "" {
		e = validateOperation(&out.Operation, "connector", out.Operation.ResourceID)
	}
	if e == nil && out.Connector.Schema == "" && out.Operation.Schema == "" {
		e = ErrUnsafeTunnelResponse
	}
	return out, e
}

func validateTunnelCapabilities(capabilities []string) error {
	if len(capabilities) < 1 || len(capabilities) > 16 {
		return errors.New("connector capabilities must contain 1-16 values")
	}
	seen := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if capability == "" || len(capability) > 64 || containsTunnelControl(capability) {
			return errors.New("connector capability is invalid")
		}
		if _, ok := seen[capability]; ok {
			return errors.New("connector capabilities must be unique")
		}
		seen[capability] = struct{}{}
	}
	return nil
}

func validateTunnelEnrollmentInput(in TunnelConnectorEnrollmentInput) error {
	if !validTunnelID(in.HostID) {
		return errors.New("invalid connector enrollment host identifier")
	}
	if in.TTLSeconds < 0 || in.TTLSeconds > 900 {
		return errors.New("connector enrollment TTL must be between 0 and 900 seconds")
	}
	return validateTunnelCapabilities(in.Capabilities)
}

func validTunnelBase64URL(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func validateTunnelEnrollmentExchangeInput(in TunnelConnectorEnrollmentExchangeInput) error {
	if in.Token == "" || len(in.Token) > 256 || strings.TrimSpace(in.Token) != in.Token || containsTunnelControl(in.Token) {
		return errors.New("connector enrollment token is invalid")
	}
	if !validTunnelID(in.HostID) {
		return errors.New("invalid connector enrollment host identifier")
	}
	if in.ProtocolVersion == "" {
		in.ProtocolVersion = "1.0"
	}
	if in.ProtocolVersion != "1.0" || len(in.ProtocolVersion) > 32 || containsTunnelControl(in.ProtocolVersion) {
		return errors.New("unsupported connector protocol version")
	}
	if !validTunnelCredentialReference(in.CredentialReference) {
		return errors.New("invalid connector credential reference")
	}
	if !validTunnelBase64URL(in.CredentialThumbprint, 43) || !validTunnelBase64URL(in.CredentialVerifierPublicKey, 43) || !validTunnelBase64URL(in.CredentialProof, 86) {
		return errors.New("invalid connector credential proof material")
	}
	if in.CredentialVerifierAlgorithm != "ed25519" {
		return errors.New("connector credential verifier must use ed25519")
	}
	for _, value := range []*string{in.SoftwareVersion, in.OperatingSystem, in.Architecture} {
		if value != nil && (len(*value) > 128 || containsTunnelControl(*value)) {
			return errors.New("connector metadata is invalid")
		}
	}
	return nil
}

func validateTunnelEnrollment(v *TunnelConnectorEnrollment, tunnel string) error {
	if v == nil || v.Schema != TunnelV1Schema || v.Kind != "connector_enrollment" || !validTunnelID(v.ID) || v.TunnelID != tunnel || !validTunnelID(v.HostID) || v.EnrollmentToken == "" || len(v.EnrollmentToken) > 256 || strings.TrimSpace(v.EnrollmentToken) != v.EnrollmentToken || containsTunnelControl(v.EnrollmentToken) || v.ExpiresAt.IsZero() {
		return ErrUnsafeTunnelResponse
	}
	if err := validateTunnelCapabilities(v.Capabilities); err != nil {
		return ErrUnsafeTunnelResponse
	}
	if err := validateOperation(&v.Operation, "connector", v.ID); err != nil {
		return err
	}
	return nil
}

func validateTunnelActivation(v *TunnelConnectorActivation, tunnel string) error {
	if v == nil || v.Schema != TunnelV1Schema || v.Kind != "connector_activation" || !validTunnelID(v.AccountID) || v.TunnelID != tunnel || !validTunnelID(v.ConnectorID) || !validTunnelID(v.HostID) || v.CredentialGeneration < 1 || v.ProcessGeneration < 1 {
		return ErrUnsafeTunnelResponse
	}
	return validateOperation(&v.Operation, "connector", v.ConnectorID)
}

// IssueTunnelConnectorEnrollmentV1 returns the one-time enrollment secret. The
// response is explicitly no-store and the token is never accepted by any
// read method in this client.
func (c *Client) IssueTunnelConnectorEnrollmentV1(ctx context.Context, tunnel, key string, in TunnelConnectorEnrollmentInput) (TunnelConnectorEnrollment, error) {
	if err := validateTunnelEnrollmentInput(in); err != nil {
		return TunnelConnectorEnrollment{}, err
	}
	p, err := tunnelPath("tunnels", tunnel, "connectors", "enrollments")
	if err != nil {
		return TunnelConnectorEnrollment{}, err
	}
	h, err := mutationHeaders("", key)
	if err != nil {
		return TunnelConnectorEnrollment{}, err
	}
	var out TunnelConnectorEnrollment
	var responseHeaders http.Header
	if err := c.doTunnelRequest(ctx, http.MethodPost, p, in, &out, h, &responseHeaders); err != nil {
		return TunnelConnectorEnrollment{}, err
	}
	if !strings.Contains(strings.ToLower(responseHeaders.Get("Cache-Control")), "no-store") {
		return TunnelConnectorEnrollment{}, ErrUnsafeTunnelResponse
	}
	if err := validateTunnelEnrollment(&out, tunnel); err != nil {
		return TunnelConnectorEnrollment{}, err
	}
	return out, nil
}

// CreateTunnelConnectorEnrollmentV1 is an explicit alias for callers that
// use create terminology for issuing a one-time connector enrollment.
func (c *Client) CreateTunnelConnectorEnrollmentV1(ctx context.Context, tunnel, key string, in TunnelConnectorEnrollmentInput) (TunnelConnectorEnrollment, error) {
	return c.IssueTunnelConnectorEnrollmentV1(ctx, tunnel, key, in)
}

func (c *Client) ExchangeTunnelConnectorEnrollmentV1(ctx context.Context, tunnel, key string, in TunnelConnectorEnrollmentExchangeInput) (TunnelConnectorActivation, error) {
	if err := validateTunnelEnrollmentExchangeInput(in); err != nil {
		return TunnelConnectorActivation{}, err
	}
	p, err := tunnelPath("tunnels", tunnel, "connectors", "enrollments", "exchange")
	if err != nil {
		return TunnelConnectorActivation{}, err
	}
	h, err := mutationHeaders("", key)
	if err != nil {
		return TunnelConnectorActivation{}, err
	}
	var out TunnelConnectorActivation
	var responseHeaders http.Header
	if err := c.doTunnelRequest(ctx, http.MethodPost, p, in, &out, h, &responseHeaders); err != nil {
		return TunnelConnectorActivation{}, err
	}
	if !strings.Contains(strings.ToLower(responseHeaders.Get("Cache-Control")), "no-store") {
		return TunnelConnectorActivation{}, ErrUnsafeTunnelResponse
	}
	if err := validateTunnelActivation(&out, tunnel); err != nil {
		return TunnelConnectorActivation{}, err
	}
	return out, nil
}

func (c *Client) EnrollTunnelConnectorV1(ctx context.Context, tunnel, key string, in TunnelConnectorEnrollmentExchangeInput) (TunnelConnectorActivation, error) {
	return c.ExchangeTunnelConnectorEnrollmentV1(ctx, tunnel, key, in)
}

func (c *Client) RotateTunnelCredentialsV1(ctx context.Context, tunnel, etag, key string) (TunnelOperation, error) {
	p, e := tunnelPath("tunnels", tunnel, "credentials")
	if e != nil {
		return TunnelOperation{}, e
	}
	h, e := requiredTunnelMutationHeaders(etag, key)
	if e != nil {
		return TunnelOperation{}, e
	}
	var out TunnelOperation
	e = c.doTunnelRequest(ctx, http.MethodPost, p+"/rotate", struct{}{}, &out, h, nil)
	if e == nil {
		e = validateOperation(&out, "tunnel", tunnel)
	}
	return out, e
}

// GetTunnelOperationV1 returns resumable progress for tunnel-family work. It
// accepts only resource kinds exposed by this client surface.
func (c *Client) GetTunnelOperationV1(ctx context.Context, id string) (TunnelOperation, error) {
	p, err := tunnelPath("operations", id)
	if err != nil {
		return TunnelOperation{}, err
	}
	var out TunnelOperation
	err = c.doTunnelRequest(ctx, http.MethodGet, p, nil, &out, nil, nil)
	if err != nil {
		return TunnelOperation{}, err
	}
	switch out.ResourceKind {
	case "tunnel", "route", "domain_binding", "connector":
	default:
		return TunnelOperation{}, ErrUnsafeTunnelResponse
	}
	if err = validateOperation(&out, out.ResourceKind, out.ResourceID); err != nil {
		return TunnelOperation{}, err
	}
	return out, nil
}

func (c *Client) TunnelStatusV1(ctx context.Context, tunnel string) (TunnelHealth, error) {
	p, err := tunnelPath("tunnels", tunnel)
	if err != nil {
		return TunnelHealth{}, err
	}
	var out TunnelHealth
	err = c.doTunnelRequest(ctx, http.MethodGet, p+"/status", nil, &out, nil, nil)
	if err == nil {
		err = validateHealth(&out, tunnel)
	}
	return out, err
}

func (c *Client) ListTunnelLogsV1(ctx context.Context, tunnel, cursor string, limit int) (TunnelLogPage, error) {
	p, err := tunnelPath("tunnels", tunnel, "logs")
	if err != nil {
		return TunnelLogPage{}, err
	}
	q, err := pageQuery(cursor, limit)
	if err != nil {
		return TunnelLogPage{}, err
	}
	var out TunnelLogPage
	err = c.doTunnelRequest(ctx, http.MethodGet, p+q, nil, &out, nil, nil)
	if err == nil {
		if len(out.Items) > limit || len(out.NextCursor) > 4096 {
			return TunnelLogPage{}, ErrUnsafeTunnelResponse
		}
		for i := range out.Items {
			if err = validateLogEntry(&out.Items[i], tunnel); err != nil {
				return TunnelLogPage{}, err
			}
		}
	}
	return out, err
}

func validateTunnelEvent(v *TunnelEvent, tunnel string) error {
	if v == nil || v.Schema != TunnelV1Schema || v.Kind != "event" || !validTunnelID(v.ID) || v.Cursor == "" || len(v.Cursor) > 2048 || v.ResourceKind == "" || v.ResourceID == "" || len(v.ResourceID) > 128 || v.OccurredAt.IsZero() || v.CorrelationID == "" || len(v.CorrelationID) > 128 || containsTunnelControl(v.ID+v.Cursor+v.EventType+v.ResourceKind+v.ResourceID+v.CorrelationID) {
		return ErrUnsafeTunnelResponse
	}
	switch v.ResourceKind {
	case "tunnel", "route", "domain_binding", "connector", "config_generation", "operation", "preview_lease":
	default:
		return ErrUnsafeTunnelResponse
	}
	if v.ResourceKind == "tunnel" && v.ResourceID != tunnel {
		return ErrUnsafeTunnelResponse
	}
	switch v.Actor.Type {
	case "user", "host", "system", "edge":
	default:
		return ErrUnsafeTunnelResponse
	}
	if !validTunnelID(v.Actor.ID) {
		return ErrUnsafeTunnelResponse
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9_.]*$`).MatchString(v.EventType) {
		return ErrUnsafeTunnelResponse
	}
	metadata, err := redactTunnelMetadata(v.SafeMetadata, 0)
	if err != nil {
		return err
	}
	v.SafeMetadata = metadata
	return nil
}

func (c *Client) ListTunnelEventsV1(ctx context.Context, tunnel, cursor string, limit int) (TunnelEventPage, error) {
	p, err := tunnelPath("tunnels", tunnel, "events")
	if err != nil {
		return TunnelEventPage{}, err
	}
	q, err := pageQuery(cursor, limit)
	if err != nil {
		return TunnelEventPage{}, err
	}
	var out TunnelEventPage
	if err := c.doTunnelRequest(ctx, http.MethodGet, p+q, nil, &out, nil, nil); err != nil {
		return TunnelEventPage{}, err
	}
	if len(out.Items) > limit || !validNextCursor(out.NextCursor) {
		return TunnelEventPage{}, ErrUnsafeTunnelResponse
	}
	for i := range out.Items {
		if err := validateTunnelEvent(&out.Items[i], tunnel); err != nil {
			return TunnelEventPage{}, err
		}
	}
	return out, nil
}

func validateTunnelPrivateAccessAdmission(v TunnelPrivateAccessAdmission) error {
	if v.Schema != TunnelV1Schema || v.Kind != "private_access_carrier_admission" {
		return ErrUnsafeTunnelResponse
	}
	for _, value := range []string{v.AccountID, v.DeviceID, v.ResourceID, v.CarrierSessionID, v.RouteID, v.AssignmentID, v.EdgeNodeID, v.TunnelID, v.CarrierConnectorID} {
		if !validTunnelID(value) {
			return ErrUnsafeTunnelResponse
		}
	}
	if v.InstallationGeneration == 0 || v.RouteGeneration == 0 || v.SessionGeneration == 0 || v.ProcessGeneration == 0 || v.ConfigGeneration == 0 || v.AssignmentGeneration == 0 || v.ExpiresAt.IsZero() || !validTunnelBase64URL(v.AccessorPublicKey, 43) || !validTunnelBase64URL(v.AccessorThumbprint, 43) || len(v.EdgeEndpoints) != 2 || len(v.EdgeCarrierServerCertificateChainPEM) == 0 || len(v.EdgeCarrierServerCertificateChainPEM) > 65536 || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(v.ConfigContentHash) || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(v.EdgeCarrierServerSPKISHA256) {
		return ErrUnsafeTunnelResponse
	}
	switch v.ResourceKind {
	case "preview":
		if v.ResourceID == "" || v.TunnelName != "" || v.RouteName != "" || v.OperationID != "" || v.ConnectorID != "" || v.Protocol != "http" {
			return ErrUnsafeTunnelResponse
		}
	case "tunnel":
		if !tunnelNamePatternV1.MatchString(v.TunnelName) || !tunnelRouteNamePatternV1.MatchString(v.RouteName) || !validTunnelID(v.ConnectorID) || v.OperationID != "" {
			return ErrUnsafeTunnelResponse
		}
	default:
		return ErrUnsafeTunnelResponse
	}
	if v.Protocol == "private_tcp" {
		if v.Hostname != "" || v.MatchType != "catch_all" || v.WildcardSuffix != "" {
			return ErrUnsafeTunnelResponse
		}
	} else if v.Protocol != "http" || v.Hostname == "" {
		return ErrUnsafeTunnelResponse
	}
	if len(v.EdgeProcessEpoch) < 8 || len(v.EdgeProcessEpoch) > 128 || containsTunnelControl(v.EdgeProcessEpoch) || !v.ExpiresAt.After(time.Now().UTC()) {
		return ErrUnsafeTunnelResponse
	}
	for _, endpoint := range v.EdgeEndpoints {
		u, err := url.Parse(endpoint)
		if err != nil || (u.Scheme != "tls" && u.Scheme != "quic") || u.Hostname() == "" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return ErrUnsafeTunnelResponse
		}
	}
	return nil
}

func validateTunnelPrivateAccessSnapshot(v *TunnelPrivateAccessSnapshot) error {
	if v == nil || v.Schema != TunnelV1Schema || v.Kind != "private_access_carrier_snapshot" || !v.Complete || len(v.Admissions) > 4096 {
		return ErrUnsafeTunnelResponse
	}
	for _, admission := range v.Admissions {
		if err := validateTunnelPrivateAccessAdmission(admission); err != nil {
			return err
		}
	}
	return nil
}

// DiscoverTunnelPrivateAccessRoutesV1 obtains the complete host-scoped
// prerequisite snapshot. The idempotency key is included in both the body and
// signed header because the endpoint signs the exact request document.
func (c *Client) DiscoverTunnelPrivateAccessRoutesV1(ctx context.Context, key string) (TunnelPrivateAccessSnapshot, error) {
	h, err := mutationHeaders("", key)
	if err != nil {
		return TunnelPrivateAccessSnapshot{}, err
	}
	var out TunnelPrivateAccessSnapshot
	if err := c.doTunnelRequest(ctx, http.MethodPost, "/v1/private-access/routes", struct {
		IdempotencyKey string `json:"idempotency_key"`
	}{IdempotencyKey: key}, &out, h, nil); err != nil {
		return TunnelPrivateAccessSnapshot{}, err
	}
	if err := validateTunnelPrivateAccessSnapshot(&out); err != nil {
		return TunnelPrivateAccessSnapshot{}, err
	}
	return out, nil
}

func (c *Client) ListTunnelPrivateAccessRoutesV1(ctx context.Context, key string) (TunnelPrivateAccessSnapshot, error) {
	return c.DiscoverTunnelPrivateAccessRoutesV1(ctx, key)
}
