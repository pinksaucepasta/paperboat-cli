package connectorprotocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func testStreamOpen() StreamOpen {
	return StreamOpen{
		Protocol:          ProtocolName,
		Version:           ProtocolVersion,
		AccountID:         "acct_1",
		TunnelID:          "tunnel_1",
		ConnectorID:       "connector_1",
		SessionID:         "session_1",
		ProcessGeneration: 2,
		Generation:        3,
		RouteID:           "route_1",
		RequestID:         "request_1",
		Kind:              "http",
	}
}

func TestStreamOpenRoundTripAndStrictBounds(t *testing.T) {
	open := testStreamOpen()
	var wire bytes.Buffer
	if err := WriteStreamOpen(&wire, open); err != nil {
		t.Fatalf("write stream open: %v", err)
	}
	decoded, err := ReadStreamOpen(&wire)
	if err != nil {
		t.Fatalf("read stream open: %v", err)
	}
	if decoded != open {
		t.Fatalf("decoded = %+v, want %+v", decoded, open)
	}
	if bytes.Contains(wire.Bytes(), []byte("token")) || bytes.Contains(wire.Bytes(), []byte("bearer")) {
		t.Fatalf("stream preface contains reusable credential field: %q", wire.Bytes())
	}

	unknown := []byte(`{"protocol":"paperboat.connector","version":"1.0","account_id":"acct_1","tunnel_id":"tunnel_1","connector_id":"connector_1","session_id":"session_1","process_generation":2,"generation":3,"route_id":"route_1","request_id":"request_1","kind":"http","unexpected":true}`)
	var unknownWire bytes.Buffer
	var unknownLength [4]byte
	binary.BigEndian.PutUint32(unknownLength[:], uint32(len(unknown)))
	unknownWire.Write(unknownLength[:])
	unknownWire.Write(unknown)
	if _, err := ReadStreamOpen(&unknownWire); !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("unknown field error = %v, want malformed frame", err)
	}

	var oversized bytes.Buffer
	binary.BigEndian.PutUint32(unknownLength[:], MaxStreamOpenBytes)
	oversized.Write(unknownLength[:])
	if _, err := ReadStreamOpen(&oversized); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized error = %v, want frame too large", err)
	}
}

func TestStreamOpenRequiresExactIdentityAndRouteFields(t *testing.T) {
	open := testStreamOpen()
	cases := []struct {
		name   string
		mutate func(*StreamOpen)
	}{
		{name: "wrong protocol", mutate: func(value *StreamOpen) { value.Protocol = "paperboat.connector.other" }},
		{name: "missing session", mutate: func(value *StreamOpen) { value.SessionID = "" }},
		{name: "missing generation", mutate: func(value *StreamOpen) { value.Generation = 0 }},
		{name: "unknown kind", mutate: func(value *StreamOpen) { value.Kind = "udp_public" }},
		{name: "missing route", mutate: func(value *StreamOpen) { value.RouteID = "" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			candidate := open
			test.mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("validate error = %v, want invalid input", err)
			}
		})
	}
}
