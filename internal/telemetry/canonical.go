package telemetry

import (
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	runtimehealth "github.com/pinksaucepasta/paperboat/internal/hostruntime/health"
	runtimeobs "github.com/pinksaucepasta/paperboat/internal/hostruntime/observability"
)

// ContractSchemaV1 is the shared preview/tunnel resource schema. It is kept
// distinct from the internal edge-health schema because this adapter is the
// boundary consumed by API and dashboard clients.
const ContractSchemaV1 = "paperboat.preview-tunnel/v1"

var (
	ErrCanonicalInvalid      = errors.New("invalid canonical telemetry")
	ErrCanonicalEnvelope     = errors.New("canonical telemetry envelope is incomplete")
	ErrCanonicalMetadata     = errors.New("canonical telemetry metadata is unsafe")
	ErrCanonicalUnsupported  = errors.New("canonical telemetry value is unsupported")
	ErrCanonicalResourceKind = errors.New("canonical telemetry resource kind is invalid")
)

// HealthStatus is the status vocabulary frozen by resources.schema.json.
type HealthStatus string

const (
	StatusUnknown       HealthStatus = "unknown"
	StatusReady         HealthStatus = "ready"
	StatusDegraded      HealthStatus = "degraded"
	StatusDown          HealthStatus = "down"
	StatusNotApplicable HealthStatus = "not_applicable"
)

// HealthDimension is the nine-dimension canonical health projection.
type HealthDimension struct {
	Status HealthStatus `json:"status"`
	Code   string       `json:"code"`
}

type HealthDimensions struct {
	Service     HealthDimension `json:"service"`
	Edge        HealthDimension `json:"edge"`
	Config      HealthDimension `json:"config"`
	Route       HealthDimension `json:"route"`
	Origin      HealthDimension `json:"origin"`
	DNS         HealthDimension `json:"dns"`
	Certificate HealthDimension `json:"certificate"`
	Access      HealthDimension `json:"access"`
	Update      HealthDimension `json:"update"`
}

var canonicalDimensions = [...]string{
	"service", "edge", "config", "route", "origin", "dns", "certificate", "access", "update",
}

func (d HealthDimensions) get(name string) HealthDimension {
	switch name {
	case "service":
		return d.Service
	case "edge":
		return d.Edge
	case "config":
		return d.Config
	case "route":
		return d.Route
	case "origin":
		return d.Origin
	case "dns":
		return d.DNS
	case "certificate":
		return d.Certificate
	case "access":
		return d.Access
	case "update":
		return d.Update
	default:
		return HealthDimension{}
	}
}

func (d *HealthDimensions) set(name string, value HealthDimension) {
	switch name {
	case "service":
		d.Service = value
	case "edge":
		d.Edge = value
	case "config":
		d.Config = value
	case "route":
		d.Route = value
	case "origin":
		d.Origin = value
	case "dns":
		d.DNS = value
	case "certificate":
		d.Certificate = value
	case "access":
		d.Access = value
	case "update":
		d.Update = value
	}
}

// HealthResource is exactly the health object from the shared resources
// schema. Internal BrokenSince, dependency, and ETag details are deliberately
// not part of this wire projection.
type HealthResource struct {
	Schema        string           `json:"schema"`
	Kind          string           `json:"kind"`
	ResourceKind  string           `json:"resource_kind"`
	ResourceID    string           `json:"resource_id"`
	OverallCode   string           `json:"overall_code"`
	Dimensions    HealthDimensions `json:"dimensions"`
	Summary       string           `json:"summary"`
	Since         time.Time        `json:"since"`
	Retrying      bool             `json:"retrying"`
	NextRetryAt   time.Time        `json:"next_retry_at"`
	RepairAction  string           `json:"repair_action"`
	CorrelationID string           `json:"correlation_id"`
}

// HealthProjectionInput supplies the resource envelope that a runtime
// snapshot cannot know itself. CorrelationID is intentionally mandatory. A
// caller may override summary, repair action, overall code, retry state, and
// next retry time; otherwise only deterministic generic values are used.
type HealthProjectionInput struct {
	ResourceKind  string
	ResourceID    string
	Snapshot      runtimehealth.Snapshot
	CorrelationID string
	Summary       string
	OverallCode   string
	Retrying      bool
	NextRetryAt   time.Time
	RepairAction  string
}

// NewHealthResource projects the existing hostruntime health snapshot into
// the canonical resource shape. It does not invent resource or correlation
// identities.
func NewHealthResource(input HealthProjectionInput) (HealthResource, error) {
	if !validHealthResourceKind(input.ResourceKind) || !validCanonicalID(input.ResourceID) || !validCanonicalID(input.CorrelationID) {
		return HealthResource{}, ErrCanonicalEnvelope
	}
	checkedAt := normalizeCanonicalTime(input.Snapshot.CheckedAt)
	if checkedAt.IsZero() {
		return HealthResource{}, ErrCanonicalEnvelope
	}
	dimensions := projectRuntimeDimensions(input.Snapshot)
	overallCode := input.OverallCode
	if overallCode == "" {
		overallCode = projectOverallCode(dimensions)
	}
	if !canonicalCodePattern.MatchString(overallCode) {
		return HealthResource{}, ErrCanonicalInvalid
	}
	summary := input.Summary
	if summary == "" {
		summary = "Paperboat runtime health requires attention."
		if overallCode == "ready" {
			summary = "Paperboat runtime health is ready."
		}
	}
	repair := input.RepairAction
	if repair == "" {
		repair = "Check Paperboat runtime status."
	}
	var err error
	summary, err = canonicalRequiredText(summary, 1000)
	if err != nil {
		return HealthResource{}, err
	}
	repair, err = canonicalRequiredText(repair, 1000)
	if err != nil {
		return HealthResource{}, err
	}
	nextRetry := normalizeCanonicalTime(input.NextRetryAt)
	if nextRetry.IsZero() {
		nextRetry = checkedAt
	}
	resource := HealthResource{
		Schema:        ContractSchemaV1,
		Kind:          "health",
		ResourceKind:  input.ResourceKind,
		ResourceID:    input.ResourceID,
		OverallCode:   overallCode,
		Dimensions:    dimensions,
		Summary:       summary,
		Since:         checkedAt,
		Retrying:      input.Retrying,
		NextRetryAt:   nextRetry,
		RepairAction:  repair,
		CorrelationID: input.CorrelationID,
	}
	if err := resource.Validate(); err != nil {
		return HealthResource{}, err
	}
	return resource, nil
}

// ProjectHealth is a concise adapter for the usual runtime call path.
func ProjectHealth(snapshot runtimehealth.Snapshot, resourceKind, resourceID, correlationID string) (HealthResource, error) {
	return NewHealthResource(HealthProjectionInput{ResourceKind: resourceKind, ResourceID: resourceID, Snapshot: snapshot, CorrelationID: correlationID})
}

func NewHealthResourceFromRuntime(snapshot runtimehealth.Snapshot, resourceKind, resourceID, correlationID string) (HealthResource, error) {
	return ProjectHealth(snapshot, resourceKind, resourceID, correlationID)
}

func (r HealthResource) Validate() error {
	if r.Schema != ContractSchemaV1 || r.Kind != "health" || !validHealthResourceKind(r.ResourceKind) || !validCanonicalID(r.ResourceID) || !canonicalCodePattern.MatchString(r.OverallCode) || r.Since.IsZero() || r.NextRetryAt.IsZero() || !validCanonicalID(r.CorrelationID) {
		return ErrCanonicalInvalid
	}
	if _, err := canonicalRequiredText(r.Summary, 1000); err != nil {
		return ErrCanonicalInvalid
	}
	if _, err := canonicalRequiredText(r.RepairAction, 1000); err != nil {
		return ErrCanonicalInvalid
	}
	for _, dimension := range canonicalDimensions {
		state := r.Dimensions.get(dimension)
		if !validHealthStatus(state.Status) || !canonicalCodePattern.MatchString(state.Code) {
			return ErrCanonicalInvalid
		}
	}
	return nil
}

func (r HealthResource) JSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var err error
	if r.Summary, err = canonicalSafeText(r.Summary, 1000); err != nil {
		return nil, err
	}
	if r.RepairAction, err = canonicalSafeText(r.RepairAction, 1000); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

// CanonicalEventResource is exactly the event object from resources.schema.json.
// ID and Cursor are never generated by this package: they are supplied by the
// durable event store or transport envelope.
type CanonicalEventResource struct {
	Schema        string         `json:"schema"`
	Kind          string         `json:"kind"`
	ID            string         `json:"id"`
	Cursor        string         `json:"cursor"`
	EventType     string         `json:"event_type"`
	ResourceKind  string         `json:"resource_kind"`
	ResourceID    string         `json:"resource_id"`
	OccurredAt    time.Time      `json:"occurred_at"`
	Actor         CanonicalActor `json:"actor"`
	CorrelationID string         `json:"correlation_id"`
	SafeMetadata  map[string]any `json:"safe_metadata"`
}

type CanonicalActor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type CanonicalEventInput struct {
	ID            string
	Cursor        string
	EventType     string
	ResourceKind  string
	ResourceID    string
	OccurredAt    time.Time
	ActorType     string
	ActorID       string
	CorrelationID string
	SafeMetadata  map[string]any
}

func NewCanonicalEvent(input CanonicalEventInput) (CanonicalEventResource, error) {
	if !validCanonicalID(input.ID) || !validCanonicalCursor(input.Cursor) || !validCanonicalEventType(input.EventType) || !validEventResourceKind(input.ResourceKind) || !validCanonicalID(input.ResourceID) || normalizeCanonicalTime(input.OccurredAt).IsZero() || !validActorType(input.ActorType) || !validCanonicalID(input.ActorID) || !validCanonicalID(input.CorrelationID) {
		return CanonicalEventResource{}, ErrCanonicalEnvelope
	}
	metadata, err := sanitizeCanonicalMetadata(input.SafeMetadata)
	if err != nil {
		return CanonicalEventResource{}, err
	}
	event := CanonicalEventResource{
		Schema:        ContractSchemaV1,
		Kind:          "event",
		ID:            input.ID,
		Cursor:        input.Cursor,
		EventType:     input.EventType,
		ResourceKind:  input.ResourceKind,
		ResourceID:    input.ResourceID,
		OccurredAt:    normalizeCanonicalTime(input.OccurredAt),
		Actor:         CanonicalActor{Type: input.ActorType, ID: input.ActorID},
		CorrelationID: input.CorrelationID,
		SafeMetadata:  metadata,
	}
	if err := event.Validate(); err != nil {
		return CanonicalEventResource{}, err
	}
	return event, nil
}

// NewEventResource is an alias-friendly constructor for API adapters.
func NewEventResource(input CanonicalEventInput) (CanonicalEventResource, error) {
	return NewCanonicalEvent(input)
}

// ProjectEvent converts an already validated hostruntime event while requiring
// the caller to provide the durable event envelope. It maps only bounded safe
// scalar fields into metadata and never derives an event ID or cursor.
func ProjectEvent(input runtimeobs.Event, envelope CanonicalEventInput) (CanonicalEventResource, error) {
	metadata := cloneCanonicalMetadata(envelope.SafeMetadata)
	if metadata == nil {
		metadata = make(map[string]any)
	}
	if input.Component != "" {
		metadata["component"] = input.Component
	}
	if input.Operation != "" {
		metadata["operation"] = input.Operation
	}
	if input.Result != "" {
		metadata["result"] = input.Result
	}
	if input.ErrorCode != "" {
		metadata["error_code"] = input.ErrorCode
	}
	if input.Duration > 0 {
		metadata["duration_ms"] = input.Duration.Milliseconds()
	}
	if input.Bytes > 0 {
		metadata["bytes"] = input.Bytes
	}
	if input.Count > 0 {
		metadata["count"] = input.Count
	}
	if input.Generation > 0 {
		metadata["generation"] = input.Generation
	}
	if input.State != "" {
		metadata["state"] = input.State
	}
	if input.Role != "" {
		metadata["role"] = input.Role
	}
	envelope.SafeMetadata = metadata
	if envelope.CorrelationID == "" {
		envelope.CorrelationID = input.CorrelationID
	}
	if envelope.ResourceID == "" {
		envelope.ResourceID = input.ResourceID
	}
	return NewCanonicalEvent(envelope)
}

func (e CanonicalEventResource) Validate() error {
	if e.Schema != ContractSchemaV1 || e.Kind != "event" || !validCanonicalID(e.ID) || !validCanonicalCursor(e.Cursor) || !validCanonicalEventType(e.EventType) || !validEventResourceKind(e.ResourceKind) || !validCanonicalID(e.ResourceID) || normalizeCanonicalTime(e.OccurredAt).IsZero() || !validActorType(e.Actor.Type) || !validCanonicalID(e.Actor.ID) || !validCanonicalID(e.CorrelationID) {
		return ErrCanonicalInvalid
	}
	_, err := sanitizeCanonicalMetadata(e.SafeMetadata)
	return err
}

func (e CanonicalEventResource) JSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	metadata, err := sanitizeCanonicalMetadata(e.SafeMetadata)
	if err != nil {
		return nil, err
	}
	e.SafeMetadata = metadata
	return json.Marshal(e)
}

// EventResource is an alias for callers that use the shorter contract name.
type EventResource = CanonicalEventResource

func projectRuntimeDimensions(snapshot runtimehealth.Snapshot) HealthDimensions {
	result := HealthDimensions{}
	for _, dimension := range canonicalDimensions {
		result.set(dimension, HealthDimension{Status: StatusNotApplicable, Code: "not_applicable"})
	}
	if snapshot.Live {
		result.Service = HealthDimension{Status: StatusReady, Code: "service_ready"}
	} else {
		result.Service = HealthDimension{Status: StatusDown, Code: "service_down"}
	}
	for _, dimension := range canonicalDimensions[1:] {
		capability, found := runtimeCapability(snapshot.Capabilities, dimension)
		if !found {
			continue
		}
		result.set(dimension, projectCapability(capability))
	}
	return result
}

func runtimeCapability(capabilities map[string]runtimehealth.Capability, dimension string) (runtimehealth.Capability, bool) {
	aliases := map[string][]string{
		"edge":        {"edge", "connector", "carrier", "transport"},
		"config":      {"config", "configuration"},
		"route":       {"route", "preview"},
		"origin":      {"origin"},
		"dns":         {"dns"},
		"certificate": {"certificate", "tls"},
		"access":      {"access"},
		"update":      {"update", "updater"},
	}
	allowed := aliases[dimension]
	keys := make([]string, 0, len(capabilities))
	for key := range capabilities {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		normalized := strings.ToLower(strings.TrimSuffix(key, ".v1"))
		for _, alias := range allowed {
			if normalized == alias {
				return capabilities[key], true
			}
		}
	}
	return runtimehealth.Capability{}, false
}

func projectCapability(capability runtimehealth.Capability) HealthDimension {
	switch capability.State {
	case runtimehealth.Ready:
		return HealthDimension{Status: StatusReady, Code: "ready"}
	case runtimehealth.Degraded:
		return HealthDimension{Status: StatusDegraded, Code: "degraded"}
	case runtimehealth.Unavailable:
		if strings.EqualFold(capability.Reason, "starting") {
			return HealthDimension{Status: StatusUnknown, Code: "not_observed"}
		}
		return HealthDimension{Status: StatusDown, Code: "unavailable"}
	default:
		return HealthDimension{Status: StatusUnknown, Code: "not_observed"}
	}
}

func projectOverallCode(dimensions HealthDimensions) string {
	bestStatus := StatusReady
	bestCode := "ready"
	bestSeverity := 0
	for _, dimension := range canonicalDimensions {
		state := dimensions.get(dimension)
		severity := 0
		switch state.Status {
		case StatusUnknown:
			severity = 1
		case StatusDegraded:
			severity = 2
		case StatusDown:
			severity = 3
		}
		if severity > bestSeverity {
			bestStatus, bestCode, bestSeverity = state.Status, state.Code, severity
		}
	}
	if bestStatus == StatusReady || bestCode == "" {
		return "ready"
	}
	return bestCode
}

var (
	canonicalIDPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$`)
	canonicalCursorPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	canonicalCodePattern      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	canonicalEventTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_.]*$`)
	canonicalMetadataKey      = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	canonicalSecretKey        = regexp.MustCompile(`(?i)(token|secret|private[_-]?key|authorization|password|cookie)`)
	canonicalBearerValue      = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[^\s,;]+`)
	canonicalURLUserinfo      = regexp.MustCompile(`(?i)https?://[^\s/@:]+:[^\s/@]*@[^\s]+`)
	canonicalPrivatePEM       = regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
)

func validCanonicalID(value string) bool { return canonicalIDPattern.MatchString(value) }

func validCanonicalCursor(value string) bool {
	return canonicalCursorPattern.MatchString(value)
}

func validCanonicalEventType(value string) bool {
	return len(value) <= 128 && canonicalEventTypePattern.MatchString(value)
}

func validHealthResourceKind(value string) bool {
	switch value {
	case "preview_lease", "tunnel", "route", "domain_binding", "connector":
		return true
	default:
		return false
	}
}

func validEventResourceKind(value string) bool {
	return validHealthResourceKind(value) || value == "config_generation" || value == "operation"
}

func validActorType(value string) bool {
	switch value {
	case "user", "host", "system", "edge":
		return true
	default:
		return false
	}
}

func validHealthStatus(value HealthStatus) bool {
	switch value {
	case StatusUnknown, StatusReady, StatusDegraded, StatusDown, StatusNotApplicable:
		return true
	default:
		return false
	}
}

func normalizeCanonicalTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Round(0)
}

func canonicalSafeText(value string, maximum int) (string, error) {
	if maximum <= 0 || !utf8.ValidString(value) {
		return "", ErrCanonicalInvalid
	}
	value = redactCanonicalText(value)
	value = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > maximum {
		value = value[:maximum]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value, nil
}

func redactCanonicalText(value string) string {
	// Keep the adapter dependency-free and conservative. Structured callers
	// should pass already-safe text; these replacements protect last-resort
	// diagnostics if a provider error crosses the boundary.
	value = canonicalPrivatePEM.ReplaceAllString(value, "[REDACTED]")
	value = canonicalURLUserinfo.ReplaceAllString(value, "[REDACTED]")
	value = canonicalBearerValue.ReplaceAllString(value, "[REDACTED]")
	for _, marker := range []string{"Bearer ", "Basic ", "Authorization:", "Cookie:", "Set-Cookie:"} {
		if index := strings.Index(strings.ToLower(value), strings.ToLower(marker)); index >= 0 {
			value = value[:index] + "[REDACTED]"
		}
	}
	if strings.Contains(strings.ToLower(value), "-----begin") && strings.Contains(strings.ToLower(value), "private key") {
		return "[REDACTED]"
	}
	return value
}

func canonicalRequiredText(value string, maximum int) (string, error) {
	value, err := canonicalSafeText(value, maximum)
	if err != nil || value == "" {
		return "", ErrCanonicalInvalid
	}
	return value, nil
}

func sanitizeCanonicalMetadata(input map[string]any) (map[string]any, error) {
	if input == nil {
		return map[string]any{}, nil
	}
	return sanitizeCanonicalMap(input, 0)
}

func sanitizeCanonicalMap(input map[string]any, depth int) (map[string]any, error) {
	if depth > 8 || len(input) > 64 {
		return nil, ErrCanonicalMetadata
	}
	result := make(map[string]any, len(input))
	for key, value := range input {
		if !canonicalMetadataKey.MatchString(key) || canonicalSecretKey.MatchString(key) {
			return nil, ErrCanonicalMetadata
		}
		clean, err := sanitizeCanonicalValue(value, depth+1)
		if err != nil {
			return nil, err
		}
		result[key] = clean
	}
	return result, nil
}

func sanitizeCanonicalValue(value any, depth int) (any, error) {
	switch typed := value.(type) {
	case nil, bool:
		return typed, nil
	case string:
		return canonicalSafeText(typed, 1000)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return typed, nil
	case float32:
		if math.IsNaN(float64(typed)) || math.IsInf(float64(typed), 0) {
			return nil, ErrCanonicalMetadata
		}
		return typed, nil
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil, ErrCanonicalMetadata
		}
		return typed, nil
	case json.Number:
		if _, err := typed.Float64(); err != nil {
			return nil, ErrCanonicalMetadata
		}
		return typed, nil
	case []any:
		if depth > 8 || len(typed) > 64 {
			return nil, ErrCanonicalMetadata
		}
		result := make([]any, len(typed))
		for index, item := range typed {
			clean, err := sanitizeCanonicalValue(item, depth+1)
			if err != nil {
				return nil, err
			}
			result[index] = clean
		}
		return result, nil
	case map[string]any:
		return sanitizeCanonicalMap(typed, depth)
	default:
		return nil, ErrCanonicalUnsupported
	}
}

func cloneCanonicalMetadata(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = cloneCanonicalValue(value)
	}
	return result
}

func cloneCanonicalValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneCanonicalMetadata(typed)
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = cloneCanonicalValue(item)
		}
		return result
	default:
		return value
	}
}
