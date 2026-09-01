package connectorprotocol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type connectorVector struct {
	Case               string          `json:"case"`
	Valid              bool            `json:"valid"`
	Type               MessageType     `json:"type"`
	RequestID          string          `json:"request_id"`
	Payload            json.RawMessage `json:"payload"`
	ExpectedGeneration uint64          `json:"expected_generation"`
	ExpectedCanonical  string          `json:"expected_canonical_payload"`
	ExpectedCode       Code            `json:"expected_code"`
	Semantic           string          `json:"semantic,omitempty"`
}

func TestSharedConnectorV1Vectors(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "contracts", "connector-v1", "fixtures", "vectors.ndjson")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), MaxFrameBytes+64<<10)
	seen := 0
	seenRotationNonces := make(map[string]struct{})
	for scanner.Scan() {
		var vector connectorVector
		if err := decodeStrict(scanner.Bytes(), &vector); err != nil {
			t.Fatalf("vector %d decode: %v", seen, err)
		}
		frame := Frame{Type: vector.Type, Version: ProtocolVersion, RequestID: vector.RequestID, Payload: vector.Payload}
		err := frame.Validate()
		if err == nil && vector.Semantic != "" {
			err = validateConnectorVectorSemantic(vector, seenRotationNonces)
		}
		if err == nil && vector.Type == MessageCredentialRotationChallenge {
			var challenge CredentialRotationChallenge
			if decodeErr := json.Unmarshal(vector.Payload, &challenge); decodeErr == nil {
				seenRotationNonces[challenge.ChallengeNonce] = struct{}{}
			}
		}
		if vector.Valid {
			if err != nil {
				t.Fatalf("%s rejected: %v", vector.Case, err)
			}
			checkSnapshotVector(t, vector)
		} else if err == nil {
			t.Fatalf("%s accepted", vector.Case)
		} else if vector.ExpectedCode != "" && CodeOf(err) != vector.ExpectedCode {
			t.Fatalf("%s error code=%q want=%q error=%v", vector.Case, CodeOf(err), vector.ExpectedCode, err)
		}
		seen++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if seen < 20 {
		t.Fatalf("vectors=%d want at least 20 normative cases", seen)
	}
}

func validateConnectorVectorSemantic(vector connectorVector, seenRotationNonces map[string]struct{}) error {
	switch vector.Semantic {
	case "stale":
		var challenge CredentialRotationChallenge
		if err := json.Unmarshal(vector.Payload, &challenge); err != nil {
			return ErrMalformedFrame
		}
		return challenge.Validate(time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC))
	case "replay":
		var challenge CredentialRotationChallenge
		if err := json.Unmarshal(vector.Payload, &challenge); err != nil {
			return ErrMalformedFrame
		}
		if _, seen := seenRotationNonces[challenge.ChallengeNonce]; seen {
			return codeError(ErrCredentialRotationRejected, ReasonCredentialRotation, false, errors.New("fixture replay detected"))
		}
		return nil
	case "wrong_session":
		var ack CredentialRotationAck
		if err := json.Unmarshal(vector.Payload, &ack); err != nil {
			return ErrMalformedFrame
		}
		if ack.SessionID != "sess_1" {
			return codeError(ErrIdentityMismatch, ReasonAuthentication, false, errors.New("fixture session is not bound"))
		}
		return nil
	case "capability_missing_rotation":
		var hello Hello
		if err := json.Unmarshal(vector.Payload, &hello); err != nil {
			return ErrMalformedFrame
		}
		if hasCapability(hello.Capabilities, CapabilityCredentialRotation) {
			return nil
		}
		return codeError(ErrCapabilityMissing, ReasonCapabilityMissing, false, errors.New("credential rotation capability is absent"))
	default:
		return ErrInvalidInput
	}
}

func checkSnapshotVector(t *testing.T, vector connectorVector) {
	t.Helper()
	if vector.Type != MessageSnapshot {
		return
	}
	var snapshot Snapshot
	if err := json.Unmarshal(vector.Payload, &snapshot); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("snapshot vector validate: %v", err)
	}
	if vector.ExpectedGeneration != snapshot.Generation || vector.ExpectedCanonical != string(snapshot.Payload) {
		t.Fatalf("snapshot vector generation=%d canonical=%q", snapshot.Generation, snapshot.Payload)
	}
	if !bytes.Equal(snapshot.Payload, []byte(vector.ExpectedCanonical)) {
		t.Fatal("shared canonical snapshot bytes changed")
	}
}

func TestSharedConnectorFixtureRejectsUnknownAndTrailingData(t *testing.T) {
	frame := Frame{Type: MessageAck, Version: ProtocolVersion, RequestID: "req_1", Payload: json.RawMessage(`{"account_id":"acct_1"} {}`)}
	if err := frame.Validate(); !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("trailing payload error=%v", err)
	}
	duplicate := Frame{Type: MessageAck, Version: ProtocolVersion, RequestID: "req_1", Payload: json.RawMessage(`{"account_id":"acct_1","account_id":"acct_2"}`)}
	if err := duplicate.Validate(); !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("duplicate payload error=%v", err)
	}
	if err := decodeStrict([]byte(`{"type":"ack","version":"1.0","request_id":"req_1","payload":{},"extra":true}`), &Frame{}); err == nil {
		t.Fatal("unknown frame field accepted")
	}
}
