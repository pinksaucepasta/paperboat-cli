package connectorprotocol

import (
	"encoding/binary"
	"encoding/json"
	"io"
)

const (
	// MaxStreamOpenBytes bounds the complete JSON stream-open preface.  It is
	// intentionally much smaller than a configuration frame: the preface
	// carries identity and route metadata, never credentials or body bytes.
	MaxStreamOpenBytes = 16 << 10
	streamOpenHeader   = 4
)

// StreamOpen is the canonical connector-v1 data-stream admission preface.
// The carrier's authenticated control session supplies bearer credentials;
// this preface repeats only the identity and generation needed to bind an
// individual stream to one exact route and request.
type StreamOpen struct {
	Protocol          string `json:"protocol"`
	Version           string `json:"version"`
	AccountID         string `json:"account_id"`
	TunnelID          string `json:"tunnel_id"`
	ConnectorID       string `json:"connector_id"`
	SessionID         string `json:"session_id"`
	ProcessGeneration uint64 `json:"process_generation"`
	Generation        uint64 `json:"generation"`
	RouteID           string `json:"route_id"`
	RequestID         string `json:"request_id"`
	Kind              string `json:"kind"`
}

func (s StreamOpen) Validate() error {
	if s.Protocol != ProtocolName || s.Version != ProtocolVersion ||
		ValidateIdentifier(s.AccountID) != nil || ValidateIdentifier(s.TunnelID) != nil ||
		ValidateIdentifier(s.ConnectorID) != nil || ValidateIdentifier(s.SessionID) != nil ||
		ValidateIdentifier(s.RouteID) != nil || ValidateIdentifier(s.RequestID) != nil ||
		s.ProcessGeneration == 0 || s.Generation == 0 {
		return ErrInvalidInput
	}
	if len(s.Kind) == 0 || len(s.Kind) > MaxIdentifierBytes || !validStreamKind(s.Kind) {
		return ErrInvalidInput
	}
	return nil
}

func validStreamKind(kind string) bool {
	switch kind {
	case "http", "https", "h2c", "websocket", "sse", "grpc", "tcp_private", PrivateAccessHTTP, PrivateAccessTCP:
		return true
	default:
		return false
	}
}

// WriteStreamOpen writes one strict length-prefixed stream-open preface.
// The length covers JSON only and is bounded before allocation by readers.
func WriteStreamOpen(writer io.Writer, stream StreamOpen) error {
	if writer == nil || stream.Validate() != nil {
		return ErrInvalidInput
	}
	payload, err := json.Marshal(stream)
	if err != nil {
		return codeError(ErrMalformedFrame, ReasonMalformed, false, err)
	}
	if len(payload) == 0 || len(payload) > MaxStreamOpenBytes-streamOpenHeader {
		return ErrFrameTooLarge
	}
	var header [streamOpenHeader]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := writeAllStreamOpen(writer, header[:]); err != nil {
		return codeError(ErrMalformedFrame, ReasonMalformed, false, err)
	}
	if _, err := writeAllStreamOpen(writer, payload); err != nil {
		return codeError(ErrMalformedFrame, ReasonMalformed, false, err)
	}
	return nil
}

// ReadStreamOpen reads one strict stream-open preface.  Unknown fields,
// duplicate keys, trailing data, and invalid identity are rejected before a
// caller can bridge application bytes.
func ReadStreamOpen(reader io.Reader) (StreamOpen, error) {
	if reader == nil {
		return StreamOpen{}, ErrInvalidInput
	}
	var header [streamOpenHeader]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return StreamOpen{}, codeError(ErrMalformedFrame, ReasonMalformed, false, err)
	}
	length := int(binary.BigEndian.Uint32(header[:]))
	if length <= 0 {
		return StreamOpen{}, ErrMalformedFrame
	}
	if length > MaxStreamOpenBytes-streamOpenHeader {
		return StreamOpen{}, ErrFrameTooLarge
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return StreamOpen{}, codeError(ErrMalformedFrame, ReasonMalformed, false, err)
	}
	var stream StreamOpen
	if err := decodeStrict(payload, &stream); err != nil {
		return StreamOpen{}, codeError(ErrMalformedFrame, ReasonMalformed, false, err)
	}
	if err := stream.Validate(); err != nil {
		return StreamOpen{}, err
	}
	return stream, nil
}

func writeAllStreamOpen(writer io.Writer, payload []byte) (int, error) {
	total := 0
	for total < len(payload) {
		written, err := writer.Write(payload[total:])
		total += written
		if err != nil {
			return total, err
		}
		if written == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
