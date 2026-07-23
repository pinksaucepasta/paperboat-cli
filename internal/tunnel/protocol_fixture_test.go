package tunnel

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Synced from papercode/packages/contracts/fixtures/paperboat-cli-terminal-v1.json.
//
//go:embed testdata/paperboat-cli-terminal-v1.json
var terminalProtocolFixture []byte

func TestPapercodeTerminalProtocolFixture(t *testing.T) {
	var fixture struct {
		Protocol  string `json:"protocol"`
		WebSocket struct {
			Path                 string `json:"path"`
			TicketQueryParameter string `json:"ticket_query_parameter"`
		} `json:"websocket"`
		RequestEnvelope struct {
			TagField     string `json:"tag_field"`
			TagValue     string `json:"tag_value"`
			MethodField  string `json:"method_field"`
			IDField      string `json:"id_field"`
			IDType       string `json:"id_type"`
			PayloadField string `json:"payload_field"`
			HeadersField string `json:"headers_field"`
		} `json:"request_envelope"`
		ResponseFrames struct {
			ChunkTag          string   `json:"chunk_tag"`
			ChunkValuesField  string   `json:"chunk_values_field"`
			ExitTag           string   `json:"exit_tag"`
			ExitField         string   `json:"exit_field"`
			ProtocolErrorTags []string `json:"protocol_error_tags"`
		} `json:"response_frames"`
		StreamAcknowledgement struct {
			TagField       string `json:"tag_field"`
			TagValue       string `json:"tag_value"`
			RequestIDField string `json:"request_id_field"`
			RequestIDType  string `json:"request_id_type"`
			SentByClient   bool   `json:"sent_by_client"`
		} `json:"stream_acknowledgement"`
		Reconnect struct {
			ReattachSameThreadAndTerminal bool `json:"reattach_same_thread_and_terminal"`
			RestartIfNotRunning           bool `json:"restart_if_not_running"`
			ReplayFailedWrites            bool `json:"replay_failed_writes"`
		} `json:"reconnect"`
		Methods struct {
			Attach string `json:"attach"`
			Write  string `json:"write"`
			Resize string `json:"resize"`
			Close  string `json:"close"`
		} `json:"methods"`
		Fields struct {
			ThreadID            string `json:"thread_id"`
			TerminalID          string `json:"terminal_id"`
			RestartIfNotRunning string `json:"restart_if_not_running"`
			CWD                 string `json:"cwd"`
			Env                 string `json:"env"`
			Data                string `json:"data"`
			Rows                string `json:"rows"`
			Cols                string `json:"cols"`
		} `json:"fields"`
		AttachEventTypes []string `json:"attach_event_types"`
	}
	decoder := json.NewDecoder(bytes.NewReader(terminalProtocolFixture))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatalf("decode terminal protocol fixture: %v", err)
	}
	if fixture.Protocol != papercodeTerminalProtocol {
		t.Fatalf("protocol = %q", fixture.Protocol)
	}
	if fixture.WebSocket.Path != papercodeWebSocketPath ||
		fixture.WebSocket.TicketQueryParameter != papercodeTicketQueryParameter {
		t.Fatalf("websocket contract does not match implementation: %#v", fixture.WebSocket)
	}
	requestType := reflect.TypeOf(rpcRequest{})
	requestTags := map[string]string{
		"Type":    fixture.RequestEnvelope.TagField,
		"Tag":     fixture.RequestEnvelope.MethodField,
		"ID":      fixture.RequestEnvelope.IDField,
		"Payload": fixture.RequestEnvelope.PayloadField,
		"Headers": fixture.RequestEnvelope.HeadersField,
	}
	for field, want := range requestTags {
		if got := jsonFieldName(t, requestType, field); got != want {
			t.Fatalf("rpcRequest.%s JSON field = %q, fixture = %q", field, got, want)
		}
	}
	idField, ok := requestType.FieldByName("ID")
	if !ok {
		t.Fatal("rpcRequest is missing ID field")
	}
	if fixture.RequestEnvelope.TagValue != rpcRequestTagValue || fixture.RequestEnvelope.IDType != "string" ||
		idField.Type.Kind() != reflect.String {
		t.Fatalf("request envelope does not match implementation: %#v", fixture.RequestEnvelope)
	}
	frameType := reflect.TypeOf(rpcFrame{})
	if jsonFieldName(t, frameType, "Tag") != fixture.RequestEnvelope.TagField ||
		jsonFieldName(t, frameType, "Values") != fixture.ResponseFrames.ChunkValuesField ||
		jsonFieldName(t, frameType, "Exit") != fixture.ResponseFrames.ExitField ||
		fixture.ResponseFrames.ChunkTag != rpcChunkTag || fixture.ResponseFrames.ExitTag != rpcExitTag ||
		!reflect.DeepEqual(fixture.ResponseFrames.ProtocolErrorTags, []string{rpcClientProtocolErrorTag, rpcDefectTag}) {
		t.Fatalf("response frames do not match implementation: %#v", fixture.ResponseFrames)
	}
	// The server runs Effect RPC with client acks disabled (supportsAck:
	// false), so the CLI intentionally has no acknowledgement encoder. The
	// fixture pins that contract: acks exist on the wire protocol but are
	// never sent by this client.
	if fixture.StreamAcknowledgement.SentByClient {
		t.Fatalf("fixture requires client acknowledgements, but the CLI does not send them: %#v", fixture.StreamAcknowledgement)
	}
	if fixture.StreamAcknowledgement.TagField != "_tag" || fixture.StreamAcknowledgement.TagValue != "Ack" ||
		fixture.StreamAcknowledgement.RequestIDField != "requestId" || fixture.StreamAcknowledgement.RequestIDType != "string" {
		t.Fatalf("stream acknowledgement wire shape changed: %#v", fixture.StreamAcknowledgement)
	}
	if !fixture.Reconnect.ReattachSameThreadAndTerminal || fixture.Reconnect.RestartIfNotRunning || fixture.Reconnect.ReplayFailedWrites {
		t.Fatalf("reconnect contract does not match implementation: %#v", fixture.Reconnect)
	}
	if fixture.Methods.Attach != rpcTerminalAttach || fixture.Methods.Write != rpcTerminalWrite ||
		fixture.Methods.Resize != rpcTerminalResize || fixture.Methods.Close != rpcTerminalClose {
		t.Fatalf("method constants do not match fixture: %#v", fixture.Methods)
	}
	if fixture.Fields.ThreadID != rpcFieldThreadID || fixture.Fields.TerminalID != rpcFieldTerminalID ||
		fixture.Fields.RestartIfNotRunning != rpcFieldRestartIfNotRunning ||
		fixture.Fields.CWD != rpcFieldCWD || fixture.Fields.Env != rpcFieldEnv ||
		fixture.Fields.Data != rpcFieldData || fixture.Fields.Rows != rpcFieldRows ||
		fixture.Fields.Cols != rpcFieldCols {
		t.Fatalf("field constants do not match fixture: %#v", fixture.Fields)
	}
	if !reflect.DeepEqual(fixture.AttachEventTypes, terminalAttachEventTypes) {
		t.Fatalf("attach event types do not match implementation: %#v", fixture.AttachEventTypes)
	}
}

func jsonFieldName(t *testing.T, typ reflect.Type, fieldName string) string {
	t.Helper()
	field, ok := typ.FieldByName(fieldName)
	if !ok {
		t.Fatalf("missing field %s.%s", typ.Name(), fieldName)
	}
	return strings.Split(field.Tag.Get("json"), ",")[0]
}
