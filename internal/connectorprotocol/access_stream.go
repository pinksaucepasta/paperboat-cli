package connectorprotocol

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	PrivateAccessSchema = "paperboat.preview-tunnel/v1"
	PrivateAccessKind   = "private_access_stream"

	PrivateAccessHTTP = "private_access_http"
	PrivateAccessTCP  = "private_access_tcp"

	MaxPrivateAccessFrameBytes = 64 << 10
	maxPrivateAccessGrantBytes = 16 << 10
	privateAccessFrameHeader   = 4
)

// PrivateAccessRequest is the server-normalized request signed into Grant.
// It contains only identity and route binding metadata. Browser credentials,
// machine bearer tokens, machine proofs, origin addresses, and private keys
// are forbidden from this carrier envelope.
type PrivateAccessRequest struct {
	AccountID              string    `json:"account_id"`
	ResourceKind           string    `json:"resource_kind"`
	ResourceID             string    `json:"resource_id"`
	RouteID                string    `json:"route_id"`
	Audience               string    `json:"audience"`
	DeviceID               string    `json:"device_id"`
	SessionID              string    `json:"session_id"`
	InstallationGeneration uint64    `json:"installation_generation"`
	ExpiresAt              time.Time `json:"expires_at"`
	Nonce                  string    `json:"nonce"`
	OperationID            string    `json:"operation_id,omitempty"`
	ConnectorID            string    `json:"connector_id,omitempty"`
	CarrierSessionID       string    `json:"carrier_session_id"`
	RouteGeneration        uint64    `json:"route_generation"`
	ProcessGeneration      uint64    `json:"process_generation"`
	ConfigGeneration       uint64    `json:"config_generation"`
	SessionGeneration      uint64    `json:"session_generation"`
	AssignmentGeneration   uint64    `json:"assignment_generation"`
	EdgeNodeID             string    `json:"edge_node_id"`
	EdgeProcessEpoch       string    `json:"edge_process_epoch"`
	Protocol               string    `json:"protocol"`
	Method                 string    `json:"method,omitempty"`
	Host                   string    `json:"host,omitempty"`
	Path                   string    `json:"path,omitempty"`
	IdempotencyKey         string    `json:"idempotency_key"`
	RequestID              string    `json:"request_id"`
	CorrelationID          string    `json:"correlation_id"`
}

func (r PrivateAccessRequest) Validate(now time.Time) error {
	for _, value := range []string{r.AccountID, r.ResourceID, r.RouteID, r.Audience, r.DeviceID, r.SessionID, r.Nonce, r.CarrierSessionID, r.EdgeNodeID, r.EdgeProcessEpoch, r.IdempotencyKey, r.RequestID, r.CorrelationID} {
		if ValidateIdentifier(value) != nil {
			return ErrInvalidInput
		}
	}
	if r.ResourceKind != "preview" && r.ResourceKind != "tunnel" || r.Protocol != "http" && r.Protocol != "tcp" || r.ExpiresAt.IsZero() || !now.IsZero() && !r.ExpiresAt.After(now) || r.InstallationGeneration == 0 || r.RouteGeneration == 0 || r.ProcessGeneration == 0 || r.ConfigGeneration == 0 || r.SessionGeneration == 0 || r.AssignmentGeneration == 0 {
		return ErrInvalidInput
	}
	if r.ResourceKind == "preview" {
		if ValidateIdentifier(r.OperationID) != nil || r.ConnectorID != "" {
			return ErrInvalidInput
		}
	} else if ValidateIdentifier(r.ConnectorID) != nil {
		return ErrInvalidInput
	}
	wantAudience := "paperboat-tunnel-tcp"
	if r.Protocol == "http" {
		wantAudience = "paperboat-tunnel-http"
		if r.ResourceKind == "preview" {
			wantAudience = "paperboat-preview-http"
		}
		if r.Method == "" || len(r.Method) > 32 || strings.ContainsAny(r.Method, " \t\r\n\x00") || r.Host == "" || len(r.Host) > 512 || strings.TrimSpace(r.Host) != r.Host || strings.ContainsAny(r.Host, "\r\n\x00") || r.Path == "" || len(r.Path) > 4096 || !strings.HasPrefix(r.Path, "/") || strings.ContainsAny(r.Path, "\r\n\x00") {
			return ErrInvalidInput
		}
	} else if r.Method != "" || r.Host != "" || r.Path != "" {
		return ErrInvalidInput
	}
	if r.Audience != wantAudience {
		return ErrInvalidInput
	}
	return nil
}

type PrivateAccessOpen struct {
	Schema  string               `json:"schema"`
	Kind    string               `json:"kind"`
	Grant   string               `json:"grant"`
	Request PrivateAccessRequest `json:"request"`
}

func (o PrivateAccessOpen) Validate(now time.Time) error {
	if o.Schema != PrivateAccessSchema || o.Kind != PrivateAccessKind || len(o.Grant) == 0 || len(o.Grant) > maxPrivateAccessGrantBytes || strings.TrimSpace(o.Grant) != o.Grant || strings.ContainsAny(o.Grant, "\r\n\x00") {
		return ErrInvalidInput
	}
	return o.Request.Validate(now)
}

type PrivateAccessResult struct {
	Schema    string    `json:"schema"`
	Kind      string    `json:"kind"`
	Status    int       `json:"status"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

func (r PrivateAccessResult) Validate(now time.Time) error {
	if r.Schema != PrivateAccessSchema || r.Kind != PrivateAccessKind {
		return ErrInvalidInput
	}
	switch r.Status {
	case http.StatusOK:
		if r.ExpiresAt.IsZero() || !now.IsZero() && !r.ExpiresAt.After(now) {
			return ErrInvalidInput
		}
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable:
		if !r.ExpiresAt.IsZero() {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

func WritePrivateAccessOpen(writer io.Writer, open PrivateAccessOpen) error {
	if err := open.Validate(time.Now().UTC()); err != nil {
		return err
	}
	return writePrivateAccessFrame(writer, open)
}

func ReadPrivateAccessOpen(reader io.Reader, now time.Time) (PrivateAccessOpen, error) {
	var open PrivateAccessOpen
	if err := readPrivateAccessFrame(reader, &open); err != nil {
		return PrivateAccessOpen{}, err
	}
	if err := open.Validate(now); err != nil {
		return PrivateAccessOpen{}, err
	}
	return open, nil
}

func WritePrivateAccessResult(writer io.Writer, result PrivateAccessResult) error {
	if err := result.Validate(time.Now().UTC()); err != nil {
		return err
	}
	return writePrivateAccessFrame(writer, result)
}

func ReadPrivateAccessResult(reader io.Reader, now time.Time) (PrivateAccessResult, error) {
	var result PrivateAccessResult
	if err := readPrivateAccessFrame(reader, &result); err != nil {
		return PrivateAccessResult{}, err
	}
	if err := result.Validate(now); err != nil {
		return PrivateAccessResult{}, err
	}
	return result, nil
}

func writePrivateAccessFrame(writer io.Writer, value any) error {
	if writer == nil {
		return ErrInvalidInput
	}
	payload, err := json.Marshal(value)
	if err != nil || len(payload) == 0 || len(payload) > MaxPrivateAccessFrameBytes-privateAccessFrameHeader {
		return ErrFrameTooLarge
	}
	var header [privateAccessFrameHeader]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := writeAllStreamOpen(writer, header[:]); err != nil {
		return codeError(ErrMalformedFrame, ReasonMalformed, false, err)
	}
	if _, err := writeAllStreamOpen(writer, payload); err != nil {
		return codeError(ErrMalformedFrame, ReasonMalformed, false, err)
	}
	return nil
}

func readPrivateAccessFrame(reader io.Reader, value any) error {
	if reader == nil || value == nil {
		return ErrInvalidInput
	}
	var header [privateAccessFrameHeader]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return codeError(ErrMalformedFrame, ReasonMalformed, false, err)
	}
	length := int(binary.BigEndian.Uint32(header[:]))
	if length <= 0 || length > MaxPrivateAccessFrameBytes-privateAccessFrameHeader {
		return ErrFrameTooLarge
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return codeError(ErrMalformedFrame, ReasonMalformed, false, err)
	}
	if err := decodeStrict(payload, value); err != nil {
		return codeError(ErrMalformedFrame, ReasonMalformed, false, err)
	}
	return nil
}
