// Package hoststate owns the durable local cache used by the Paperboat host
// runtime to resume tunnel reconciliation. The server remains authoritative.
package hoststate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	Schema        = "paperboat.host-state"
	SchemaVersion = 1
	MaxStateBytes = 8 << 20

	maxTunnels           = 1_000
	maxRoutes            = 20_000
	maxConnectors        = 10_000
	maxJournalEntries    = 2_000
	maxSnapshotBytes     = 4 << 20
	maxCredentialRefSize = 512
	maxJSONDepth         = 64
)

var (
	ErrInvalidState         = errors.New("invalid host state")
	ErrCredentialMaterial   = errors.New("reusable credential material is forbidden in host state")
	idPattern               = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	codePattern             = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)
	hostnamePattern         = regexp.MustCompile(`^[a-z0-9.-]+$`)
	stableEndpointIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type State struct {
	Tunnels          []Tunnel             `json:"tunnels,omitempty"`
	RouteGenerations []RouteGeneration    `json:"route_generations,omitempty"`
	Connectors       []Connector          `json:"connectors,omitempty"`
	UpdateJournal    []UpdateJournalEntry `json:"update_journal,omitempty"`
}

// Tunnel stores desired and last-known-good snapshots independently. A failed
// desired generation must never replace LastKnownGood.
type Tunnel struct {
	ID                string          `json:"id"`
	StableEndpointID  string          `json:"stable_endpoint_id"`
	DesiredState      string          `json:"desired_state"`
	DesiredGeneration uint64          `json:"desired_generation"`
	AppliedGeneration uint64          `json:"applied_generation"`
	DesiredSnapshot   ConfigSnapshot  `json:"desired_snapshot"`
	LastKnownGood     *ConfigSnapshot `json:"last_known_good,omitempty"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

type RouteGeneration struct {
	TunnelID   string `json:"tunnel_id"`
	RouteID    string `json:"route_id"`
	Generation uint64 `json:"generation"`
}

// Connector contains only the write-only credential locator. Secret bytes are
// held by the platform credential store and cannot be represented here.
type Connector struct {
	ID                    string              `json:"id"`
	TunnelID              string              `json:"tunnel_id"`
	HostID                string              `json:"host_id"`
	Credential            CredentialReference `json:"credential"`
	RotationGeneration    uint64              `json:"rotation_generation"`
	LastAppliedGeneration uint64              `json:"last_applied_generation"`
}

type CredentialReference struct {
	Reference  string `json:"reference"`
	Generation uint64 `json:"generation"`
}

type ConfigSnapshot struct {
	TunnelID    string          `json:"tunnel_id"`
	Generation  uint64          `json:"generation"`
	ContentHash string          `json:"content_hash"`
	Payload     json.RawMessage `json:"payload"`
}

// TunnelConfigSnapshot is the only configuration payload accepted by the
// durable host cache. It mirrors the connector-v1 wire vocabulary emitted by
// paperboat-server. References may identify a platform credential, but never
// contain reusable credential material.
type TunnelConfigSnapshot struct {
	Schema         string              `json:"schema"`
	Kind           string              `json:"kind"`
	TunnelID       string              `json:"tunnel_id"`
	Generation     uint64              `json:"generation"`
	Name           string              `json:"name"`
	DesiredState   string              `json:"desired_state"`
	AccessMode     string              `json:"access_mode"`
	StableEndpoint string              `json:"stable_endpoint"`
	ExpiresAt      *time.Time          `json:"expires_at"`
	Routes         []TunnelConfigRoute `json:"routes"`
}

type TunnelConfigRoute struct {
	ID                      string  `json:"id"`
	Name                    string  `json:"name"`
	Protocol                string  `json:"protocol"`
	MatchType               string  `json:"match_type"`
	MatchHostname           string  `json:"match_hostname,omitempty"`
	WildcardSuffix          string  `json:"wildcard_suffix,omitempty"`
	PathPrefix              *string `json:"path_prefix"`
	OriginScheme            string  `json:"origin_scheme"`
	OriginAddress           string  `json:"origin_address"`
	PreserveHost            bool    `json:"preserve_host"`
	HostOverride            *string `json:"host_override"`
	TLSVerification         string  `json:"tls_verification"`
	TLSServerName           *string `json:"tls_server_name"`
	CAReference             *string `json:"ca_reference"`
	MTLSCredentialReference *string `json:"mtls_credential_reference"`
	ConnectTimeoutMs        int32   `json:"connect_timeout_ms"`
	IdleTimeoutMs           int32   `json:"idle_timeout_ms"`
	MaxConcurrentStreams    int32   `json:"max_concurrent_streams"`
	DesiredState            string  `json:"desired_state"`
}

type UpdateJournalEntry struct {
	ID               string    `json:"id"`
	TunnelID         string    `json:"tunnel_id"`
	Phase            string    `json:"phase"`
	State            string    `json:"state"`
	TargetGeneration uint64    `json:"target_generation"`
	FailureCode      string    `json:"failure_code,omitempty"`
	StartedAt        time.Time `json:"started_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// NewConfigSnapshot canonicalizes the JSON before hashing it. It rejects
// preview leases and secret-bearing fields so durable host state cannot become
// an alternate plaintext credential store.
func NewConfigSnapshot(tunnelID string, generation uint64, payload []byte) (ConfigSnapshot, error) {
	if !validID(tunnelID) || generation == 0 || len(payload) == 0 || len(payload) > maxSnapshotBytes {
		return ConfigSnapshot{}, ErrInvalidState
	}
	canonical, err := canonicalSafeJSON(payload)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	if _, err := parseTunnelConfigSnapshot(canonical, tunnelID, generation); err != nil {
		return ConfigSnapshot{}, err
	}
	digest := sha256.Sum256(canonical)
	return ConfigSnapshot{
		TunnelID: tunnelID, Generation: generation,
		ContentHash: "sha256:" + hex.EncodeToString(digest[:]),
		Payload:     append(json.RawMessage(nil), canonical...),
	}, nil
}

// ParseTunnelConfigSnapshot strictly decodes the canonical server snapshot
// and verifies the expected tunnel and generation. Callers should hash the
// returned canonical bytes through NewConfigSnapshot rather than re-encoding
// the decoded struct.
func ParseTunnelConfigSnapshot(payload []byte, tunnelID string, generation uint64) (TunnelConfigSnapshot, error) {
	if !validID(tunnelID) || generation == 0 || len(payload) == 0 || len(payload) > maxSnapshotBytes {
		return TunnelConfigSnapshot{}, ErrInvalidState
	}
	canonical, err := canonicalSafeJSON(payload)
	if err != nil {
		return TunnelConfigSnapshot{}, err
	}
	return parseTunnelConfigSnapshot(canonical, tunnelID, generation)
}

func parseTunnelConfigSnapshot(canonical []byte, tunnelID string, generation uint64) (TunnelConfigSnapshot, error) {
	if len(canonical) == 0 {
		return TunnelConfigSnapshot{}, ErrInvalidState
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &fields); err != nil || fields == nil {
		return TunnelConfigSnapshot{}, ErrInvalidState
	}
	for _, field := range []string{"schema", "kind", "tunnel_id", "generation", "name", "desired_state", "access_mode", "stable_endpoint", "expires_at", "routes"} {
		if _, ok := fields[field]; !ok {
			return TunnelConfigSnapshot{}, fmt.Errorf("%w: snapshot field %s is required", ErrInvalidState, field)
		}
	}
	var snapshot TunnelConfigSnapshot
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return TunnelConfigSnapshot{}, fmt.Errorf("%w: snapshot shape: %v", ErrInvalidState, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return TunnelConfigSnapshot{}, ErrInvalidState
	}
	if snapshot.Schema != "paperboat.preview-tunnel/v1" || snapshot.Kind != "tunnel_config_snapshot" || snapshot.TunnelID != tunnelID || snapshot.Generation != generation {
		return TunnelConfigSnapshot{}, fmt.Errorf("%w: snapshot identity mismatch", ErrInvalidState)
	}
	if strings.TrimSpace(snapshot.Name) != snapshot.Name || len(snapshot.Name) == 0 || len(snapshot.Name) > 80 || strings.TrimSpace(snapshot.StableEndpoint) != snapshot.StableEndpoint {
		return TunnelConfigSnapshot{}, ErrInvalidState
	}
	if snapshot.DesiredState != "active" && snapshot.DesiredState != "paused" && snapshot.DesiredState != "deleted" {
		return TunnelConfigSnapshot{}, ErrInvalidState
	}
	if snapshot.AccessMode != "public" && snapshot.AccessMode != "private" {
		return TunnelConfigSnapshot{}, ErrInvalidState
	}
	if !validStableEndpoint(snapshot.StableEndpoint) || snapshot.Routes == nil {
		return TunnelConfigSnapshot{}, ErrInvalidState
	}
	if _, err := StableEndpointIDForEndpoint(snapshot.StableEndpoint); err != nil {
		return TunnelConfigSnapshot{}, err
	}
	for index, route := range snapshot.Routes {
		routeFields, ok := fields["routes"]
		if !ok || routeFields == nil {
			return TunnelConfigSnapshot{}, ErrInvalidState
		}
		var rawRoutes []json.RawMessage
		if err := json.Unmarshal(routeFields, &rawRoutes); err != nil || len(rawRoutes) != len(snapshot.Routes) {
			return TunnelConfigSnapshot{}, ErrInvalidState
		}
		var routeObject map[string]json.RawMessage
		if err := json.Unmarshal(rawRoutes[index], &routeObject); err != nil || routeObject == nil {
			return TunnelConfigSnapshot{}, ErrInvalidState
		}
		for _, field := range []string{"id", "name", "protocol", "match_type", "path_prefix", "origin_scheme", "origin_address", "preserve_host", "host_override", "tls_verification", "tls_server_name", "ca_reference", "mtls_credential_reference", "connect_timeout_ms", "idle_timeout_ms", "max_concurrent_streams", "desired_state"} {
			if _, ok := routeObject[field]; !ok {
				return TunnelConfigSnapshot{}, fmt.Errorf("%w: route field %s is required", ErrInvalidState, field)
			}
		}
		if err := validateTunnelConfigRoute(route); err != nil {
			return TunnelConfigSnapshot{}, fmt.Errorf("%w: route %d: %v", ErrInvalidState, index, err)
		}
	}
	return snapshot, nil
}

func validStableEndpoint(value string) bool {
	if len(value) < len("https://a") || len(value) > 264 {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Opaque != "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() != "" || parsed.Host != strings.ToLower(parsed.Host) || !hostnamePattern.MatchString(parsed.Host) {
		return false
	}
	return true
}

// ValidateStableEndpointID accepts only the canonical lowercase UUID used as
// the immutable managed tunnel endpoint identity. Host runtime state must not
// invent this identity from a display name, host name, or endpoint hash.
func ValidateStableEndpointID(value string) error {
	if !stableEndpointIDPattern.MatchString(value) {
		return ErrInvalidState
	}
	return nil
}

// StableEndpointIDForEndpoint extracts the immutable managed tunnel identity
// from the endpoint's first DNS label. The endpoint must use a canonical
// lowercase UUID there; callers that have an authoritative ID must compare it
// with the returned value.
func StableEndpointIDForEndpoint(value string) (string, error) {
	if !validStableEndpoint(value) {
		return "", ErrInvalidState
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", ErrInvalidState
	}
	labels := strings.Split(parsed.Hostname(), ".")
	if len(labels) < 2 {
		return "", ErrInvalidState
	}
	if err := ValidateStableEndpointID(labels[0]); err != nil {
		return "", err
	}
	return labels[0], nil
}

func validateTunnelConfigRoute(route TunnelConfigRoute) error {
	if !validID(route.ID) || strings.TrimSpace(route.Name) != route.Name || len(route.Name) == 0 || len(route.Name) > 80 || strings.TrimSpace(route.OriginAddress) != route.OriginAddress || len(route.OriginAddress) == 0 || len(route.OriginAddress) > 512 || strings.ContainsAny(route.OriginAddress, "\r\n@") {
		return ErrInvalidState
	}
	switch route.Protocol {
	case "http":
		if route.OriginScheme == "tcp" {
			return ErrInvalidState
		}
	case "tcp_private":
		if route.OriginScheme != "tcp" {
			return ErrInvalidState
		}
	default:
		return ErrInvalidState
	}
	switch route.MatchType {
	case "managed_exact", "exact":
		if route.MatchHostname == "" || route.WildcardSuffix != "" || !validMatchHostname(route.MatchHostname) {
			return ErrInvalidState
		}
	case "one_label_wildcard":
		if route.MatchHostname != "" || route.WildcardSuffix == "" || !validMatchHostname(route.WildcardSuffix) {
			return ErrInvalidState
		}
	case "catch_all":
		if route.MatchHostname != "" || route.WildcardSuffix != "" {
			return ErrInvalidState
		}
	default:
		return ErrInvalidState
	}
	switch route.OriginScheme {
	case "http", "https", "h2c", "unix", "tcp":
	default:
		return ErrInvalidState
	}
	if route.TLSVerification != "not_applicable" && route.TLSVerification != "system" && route.TLSVerification != "custom_ca" && route.TLSVerification != "insecure_development" {
		return ErrInvalidState
	}
	if route.OriginScheme != "https" && route.TLSVerification != "not_applicable" {
		return ErrInvalidState
	}
	if route.OriginScheme == "https" {
		if route.TLSVerification == "not_applicable" || route.TLSVerification == "custom_ca" && route.CAReference == nil || route.TLSVerification != "custom_ca" && route.CAReference != nil {
			return ErrInvalidState
		}
	} else if route.CAReference != nil || route.MTLSCredentialReference != nil || route.TLSServerName != nil {
		return ErrInvalidState
	}
	if route.PathPrefix != nil && (len(*route.PathPrefix) == 0 || len(*route.PathPrefix) > 512 || !strings.HasPrefix(*route.PathPrefix, "/") || strings.ContainsAny(*route.PathPrefix, "\r\n")) {
		return ErrInvalidState
	}
	if route.HostOverride != nil && (len(*route.HostOverride) == 0 || len(*route.HostOverride) > 253 || strings.TrimSpace(*route.HostOverride) != *route.HostOverride) {
		return ErrInvalidState
	}
	if route.TLSServerName != nil && (len(*route.TLSServerName) == 0 || len(*route.TLSServerName) > 253 || strings.TrimSpace(*route.TLSServerName) != *route.TLSServerName || strings.ContainsAny(*route.TLSServerName, "\r\n")) {
		return ErrInvalidState
	}
	for name, reference := range map[string]*string{"ca_reference": route.CAReference, "mtls_credential_reference": route.MTLSCredentialReference} {
		if reference != nil && !safeSnapshotCredentialReference(*reference) {
			return fmt.Errorf("%w: unsafe %s", ErrCredentialMaterial, name)
		}
	}
	if route.ConnectTimeoutMs < 100 || route.ConnectTimeoutMs > 120000 || route.IdleTimeoutMs < 1000 || route.IdleTimeoutMs > 3600000 || route.MaxConcurrentStreams < 1 || route.MaxConcurrentStreams > 100000 {
		return ErrInvalidState
	}
	if route.DesiredState != "active" && route.DesiredState != "disabled" && route.DesiredState != "deleted" {
		return ErrInvalidState
	}
	return nil
}

func validMatchHostname(value string) bool {
	return len(value) <= 253 && strings.TrimSpace(value) == value && value == strings.ToLower(value) && !strings.HasSuffix(value, ".") && !strings.Contains(value, "*") && hostnamePattern.MatchString(value)
}

func (s State) Validate() error {
	if len(s.Tunnels) > maxTunnels || len(s.RouteGenerations) > maxRoutes || len(s.Connectors) > maxConnectors || len(s.UpdateJournal) > maxJournalEntries {
		return ErrInvalidState
	}
	tunnels := make(map[string]Tunnel, len(s.Tunnels))
	for _, tunnel := range s.Tunnels {
		if !validID(tunnel.ID) || ValidateStableEndpointID(tunnel.StableEndpointID) != nil || (tunnel.DesiredState != "active" && tunnel.DesiredState != "paused") || tunnel.DesiredGeneration == 0 || tunnel.AppliedGeneration > tunnel.DesiredGeneration || tunnel.UpdatedAt.IsZero() {
			return ErrInvalidState
		}
		if _, exists := tunnels[tunnel.ID]; exists {
			return ErrInvalidState
		}
		if err := validateSnapshot(tunnel.DesiredSnapshot); err != nil || tunnel.DesiredSnapshot.TunnelID != tunnel.ID || tunnel.DesiredSnapshot.Generation != tunnel.DesiredGeneration {
			return ErrInvalidState
		}
		if err := validateStableEndpointIdentity(tunnel.StableEndpointID, tunnel.DesiredSnapshot); err != nil {
			return err
		}
		if tunnel.AppliedGeneration > 0 && tunnel.LastKnownGood == nil {
			return ErrInvalidState
		}
		if tunnel.LastKnownGood != nil {
			if err := validateSnapshot(*tunnel.LastKnownGood); err != nil || tunnel.LastKnownGood.TunnelID != tunnel.ID || tunnel.LastKnownGood.Generation != tunnel.AppliedGeneration || tunnel.LastKnownGood.Generation > tunnel.DesiredGeneration {
				return ErrInvalidState
			}
			if err := validateStableEndpointIdentity(tunnel.StableEndpointID, *tunnel.LastKnownGood); err != nil {
				return err
			}
		}
		tunnels[tunnel.ID] = tunnel
	}
	routes := make(map[string]struct{}, len(s.RouteGenerations))
	for _, route := range s.RouteGenerations {
		tunnel, ok := tunnels[route.TunnelID]
		key := route.TunnelID + "\x00" + route.RouteID
		if !ok || !validID(route.RouteID) || route.Generation == 0 || route.Generation > tunnel.DesiredGeneration {
			return ErrInvalidState
		}
		if _, exists := routes[key]; exists {
			return ErrInvalidState
		}
		routes[key] = struct{}{}
	}
	connectors := make(map[string]struct{}, len(s.Connectors))
	for _, connector := range s.Connectors {
		tunnel, ok := tunnels[connector.TunnelID]
		if !ok || !validID(connector.ID) || !validID(connector.HostID) || connector.RotationGeneration == 0 || connector.LastAppliedGeneration > tunnel.DesiredGeneration || connector.Credential.Generation != connector.RotationGeneration {
			return ErrInvalidState
		}
		if _, exists := connectors[connector.ID]; exists {
			return ErrInvalidState
		}
		if err := connector.Credential.validate(connector.ID); err != nil {
			return err
		}
		connectors[connector.ID] = struct{}{}
	}
	journal := make(map[string]struct{}, len(s.UpdateJournal))
	for _, entry := range s.UpdateJournal {
		tunnel, ok := tunnels[entry.TunnelID]
		if !ok || !validID(entry.ID) || !knownJournalPhase(entry.Phase) || !knownJournalState(entry.State) || entry.TargetGeneration == 0 || entry.TargetGeneration > tunnel.DesiredGeneration || entry.StartedAt.IsZero() || entry.UpdatedAt.Before(entry.StartedAt) || (entry.FailureCode != "" && !codePattern.MatchString(entry.FailureCode)) {
			return ErrInvalidState
		}
		if entry.State == "failed" && entry.FailureCode == "" || entry.State != "failed" && entry.FailureCode != "" {
			return ErrInvalidState
		}
		if _, exists := journal[entry.ID]; exists {
			return ErrInvalidState
		}
		journal[entry.ID] = struct{}{}
	}
	return nil
}

func validateSnapshot(snapshot ConfigSnapshot) error {
	if !validID(snapshot.TunnelID) || snapshot.Generation == 0 || len(snapshot.Payload) == 0 || len(snapshot.Payload) > maxSnapshotBytes {
		return ErrInvalidState
	}
	canonical, err := canonicalSafeJSON(snapshot.Payload)
	if err != nil || !bytes.Equal(canonical, snapshot.Payload) {
		return ErrInvalidState
	}
	digest := sha256.Sum256(canonical)
	if snapshot.ContentHash != "sha256:"+hex.EncodeToString(digest[:]) {
		return ErrInvalidState
	}
	if _, err := parseTunnelConfigSnapshot(canonical, snapshot.TunnelID, snapshot.Generation); err != nil {
		return ErrInvalidState
	}
	return nil
}

func validateStableEndpointIdentity(stableEndpointID string, snapshot ConfigSnapshot) error {
	if err := ValidateStableEndpointID(stableEndpointID); err != nil {
		return err
	}
	decoded, err := ParseTunnelConfigSnapshot(snapshot.Payload, snapshot.TunnelID, snapshot.Generation)
	if err != nil {
		return ErrInvalidState
	}
	endpointID, err := StableEndpointIDForEndpoint(decoded.StableEndpoint)
	if err != nil || endpointID != stableEndpointID {
		return ErrInvalidState
	}
	return nil
}

func (r CredentialReference) validate(connectorID string) error {
	if r.Generation == 0 || len(r.Reference) == 0 || len(r.Reference) > maxCredentialRefSize || strings.TrimSpace(r.Reference) != r.Reference {
		return ErrInvalidState
	}
	parsed, err := url.Parse(r.Reference)
	if err != nil || parsed.User != nil || parsed.Opaque != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host != "paperboat" || parsed.Path != path.Join("/connectors", connectorID) {
		return ErrInvalidState
	}
	switch parsed.Scheme {
	case "keychain", "credential-manager", "secret-service", "protected-file", "tpm":
		return nil
	default:
		return ErrInvalidState
	}
}

func canonicalSafeJSON(payload []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: snapshot JSON: %v", ErrInvalidState, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalidState
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) == 0 {
		return nil, ErrInvalidState
	}
	if err := rejectCredentialMaterial(value); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(value)
	if err != nil || len(canonical) > maxSnapshotBytes {
		return nil, ErrInvalidState
	}
	return canonical, nil
}

func decodeJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("JSON nesting exceeds %d", maxJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, ErrInvalidState
			}
			if _, duplicate := object[key]; duplicate {
				return nil, fmt.Errorf("duplicate key %q", key)
			}
			child, err := decodeJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = child
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
			return nil, ErrInvalidState
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			child, err := decodeJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, child)
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
			return nil, ErrInvalidState
		}
		return array, nil
	default:
		return nil, ErrInvalidState
	}
}

func rejectCredentialMaterial(value any) error {
	switch typed := value.(type) {
	case []any:
		for _, child := range typed {
			if err := rejectCredentialMaterial(child); err != nil {
				return err
			}
		}
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
			if normalized == "kind" && child == "preview_lease" {
				return fmt.Errorf("%w: preview leases are not durable", ErrInvalidState)
			}
			if secretReferenceKey(normalized) {
				if child == nil {
					continue
				}
				reference, ok := child.(string)
				if !ok || !safeSnapshotCredentialReference(reference) {
					return fmt.Errorf("%w: unsafe %s", ErrCredentialMaterial, key)
				}
			}
			if forbiddenCredentialKey(normalized) {
				return fmt.Errorf("%w: %s", ErrCredentialMaterial, key)
			}
			if err := rejectCredentialMaterial(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func safeSnapshotCredentialReference(reference string) bool {
	if len(reference) == 0 || len(reference) > maxCredentialRefSize || strings.TrimSpace(reference) != reference {
		return false
	}
	parsed, err := url.Parse(reference)
	if err != nil || parsed.User != nil || parsed.Opaque != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host != "paperboat" || parsed.Path == "" || parsed.Path == "/" || path.Clean(parsed.Path) != parsed.Path {
		return false
	}
	switch parsed.Scheme {
	case "keychain", "credential-manager", "secret-service", "protected-file", "tpm":
		return true
	}
	return false
}

func secretReferenceKey(key string) bool {
	if strings.Contains(key, "credential_reference") {
		return true
	}
	base, found := strings.CutSuffix(key, "_reference")
	return found && forbiddenCredentialKey(base)
}

func forbiddenCredentialKey(key string) bool {
	if strings.HasSuffix(key, "_reference") {
		return false
	}
	switch key {
	case "authorization", "proxy_authorization", "token", "access_token", "refresh_token", "bearer_token", "api_key", "password", "secret", "credential", "credential_secret", "private_key", "client_secret":
		return true
	}
	return strings.HasSuffix(key, "_token") || strings.HasSuffix(key, "_password") || strings.HasSuffix(key, "_secret") || strings.HasSuffix(key, "_private_key")
}

func normalizeState(state State) State {
	state = cloneState(state)
	slices.SortFunc(state.Tunnels, func(a, b Tunnel) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(state.RouteGenerations, func(a, b RouteGeneration) int {
		if result := strings.Compare(a.TunnelID, b.TunnelID); result != 0 {
			return result
		}
		return strings.Compare(a.RouteID, b.RouteID)
	})
	slices.SortFunc(state.Connectors, func(a, b Connector) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(state.UpdateJournal, func(a, b UpdateJournalEntry) int { return strings.Compare(a.ID, b.ID) })
	return state
}

func cloneState(state State) State {
	clone := State{
		Tunnels:          append([]Tunnel(nil), state.Tunnels...),
		RouteGenerations: append([]RouteGeneration(nil), state.RouteGenerations...),
		Connectors:       append([]Connector(nil), state.Connectors...),
		UpdateJournal:    append([]UpdateJournalEntry(nil), state.UpdateJournal...),
	}
	for index := range clone.Tunnels {
		clone.Tunnels[index].DesiredSnapshot.Payload = append(json.RawMessage(nil), clone.Tunnels[index].DesiredSnapshot.Payload...)
		if state.Tunnels[index].LastKnownGood != nil {
			lastKnownGood := *state.Tunnels[index].LastKnownGood
			lastKnownGood.Payload = append(json.RawMessage(nil), lastKnownGood.Payload...)
			clone.Tunnels[index].LastKnownGood = &lastKnownGood
		}
	}
	return clone
}

func validID(value string) bool { return idPattern.MatchString(value) }

func knownJournalPhase(value string) bool {
	switch value {
	case "received", "validated", "persisted", "applying", "ready", "draining", "complete":
		return true
	}
	return false
}

func knownJournalState(value string) bool {
	return value == "pending" || value == "applied" || value == "failed"
}
