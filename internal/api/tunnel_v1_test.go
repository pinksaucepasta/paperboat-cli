package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/config"
)

func tunnelTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return New(server.URL, config.Credential{AccessToken: "client-token"}, server.Client())
}

func validTunnelHealthTestValue() TunnelHealth {
	dimension := TunnelHealthDimension{Status: "healthy", Code: "ready"}
	return TunnelHealth{Schema: TunnelV1Schema, Kind: "health", ResourceKind: "tunnel", ResourceID: "tun_1", OverallCode: "ready", Summary: "Tunnel is ready.", Since: time.Unix(1, 0).UTC(), Dimensions: TunnelHealthDimensions{Service: dimension, Edge: dimension, Config: dimension, Route: dimension, Origin: dimension, DNS: dimension, Certificate: dimension, Access: dimension, Update: dimension}}
}

func TestTunnelStatusV1StrictSchemaAndTypedAuthFailure(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		client := tunnelTestClient(t, func(w http.ResponseWriter, _ *http.Request) { writeTunnelTestData(t, w, validTunnelHealthTestValue()) })
		out, err := client.TunnelStatusV1(context.Background(), "tun_1")
		if err != nil || out.OverallCode != "ready" {
			t.Fatalf("out=%#v err=%v", out, err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		client := tunnelTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			value := validTunnelHealthTestValue()
			value.ResourceID = "tun_other"
			writeTunnelTestData(t, w, value)
		})
		if _, err := client.TunnelStatusV1(context.Background(), "tun_1"); !errors.Is(err, ErrUnsafeTunnelResponse) {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("auth", func(t *testing.T) {
		client := tunnelTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"unauthenticated","message":"Authentication is required."}}`))
		})
		_, err := client.TunnelStatusV1(context.Background(), "tun_1")
		if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("error=%#v", err)
		}
	})
}

func TestTunnelLogsV1BoundsAndRedactsSecrets(t *testing.T) {
	client := tunnelTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		entry := TunnelLogEntry{Schema: TunnelV1Schema, Kind: "log_entry", ID: "log_1", TunnelID: "tun_1", Level: "info", Component: "connector", Code: "connected", Message: "Bearer should-not-escape", Metadata: map[string]any{"credential_token": "top-secret", "nested": map[string]any{"authorization": "secret", "safe": "value"}}, OccurredAt: time.Unix(2, 0).UTC(), Cursor: "cursor_1"}
		writeTunnelTestData(t, w, TunnelLogPage{Items: []TunnelLogEntry{entry}})
	})
	out, err := client.ListTunnelLogsV1(context.Background(), "tun_1", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	entry := out.Items[0]
	if entry.Message != "[REDACTED]" || entry.Metadata["credential_token"] != "[REDACTED]" {
		t.Fatalf("entry=%#v", entry)
	}
	nested := entry.Metadata["nested"].(map[string]any)
	if nested["authorization"] != "[REDACTED]" || nested["safe"] != "value" {
		t.Fatalf("nested=%#v", nested)
	}
}

func TestTunnelLogsV1RejectsOversizedAndMalformedInput(t *testing.T) {
	client := tunnelTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		entry := TunnelLogEntry{Schema: TunnelV1Schema, Kind: "wrong", ID: "log_1", TunnelID: "tun_1", Code: "x", Metadata: map[string]any{}, Cursor: "c"}
		writeTunnelTestData(t, w, TunnelLogPage{Items: []TunnelLogEntry{entry}})
	})
	if _, err := client.ListTunnelLogsV1(context.Background(), "tun_1", "", 10); !errors.Is(err, ErrUnsafeTunnelResponse) {
		t.Fatalf("error=%v", err)
	}
	if _, err := client.ListTunnelLogsV1(context.Background(), "tun_1", strings.Repeat("x", 4097), 10); err == nil {
		t.Fatal("expected cursor bound error")
	}
}

func writeTunnelTestData(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"data": value}); err != nil {
		t.Fatal(err)
	}
}

func validTunnelTestValue() Tunnel {
	return Tunnel{Schema: TunnelV1Schema, Kind: "tunnel", ID: "tun_1", AccountID: "acc_1", Generation: 3, ETag: `"tunnel:tun_1:3"`, Name: "demo", AccessMode: "private", DesiredState: "active", StableEndpointID: "123e4567-e89b-42d3-a456-426614174000", StableEndpoint: "https://123e4567-e89b-42d3-a456-426614174000.tunnels.example.test", CreatedByHostID: "host_1", CreatedByActorID: "user_1", SummaryCode: "ready", CreatedAt: time.Unix(1, 0).UTC(), UpdatedAt: time.Unix(2, 0).UTC()}
}

func TestTunnelV1RejectsNonCanonicalOrMismatchedStableEndpointIdentity(t *testing.T) {
	for name, mutate := range map[string]func(*Tunnel){
		"name-derived ID": func(value *Tunnel) { value.StableEndpointID = "demo" },
		"uppercase UUID":  func(value *Tunnel) { value.StableEndpointID = "123E4567-E89B-42D3-A456-426614174000" },
		"mismatched label": func(value *Tunnel) {
			value.StableEndpoint = "https://223e4567-e89b-42d3-a456-426614174000.tunnels.example.test"
		},
		"bare base": func(value *Tunnel) { value.StableEndpoint = "https://tunnels.example.test" },
	} {
		t.Run(name, func(t *testing.T) {
			value := validTunnelTestValue()
			mutate(&value)
			if err := validateTunnel(value); !errors.Is(err, ErrUnsafeTunnelResponse) {
				t.Fatalf("validateTunnel() error = %v", err)
			}
		})
	}
}

func validTunnelOperationTestValue(kind, id string) TunnelOperation {
	return TunnelOperation{Schema: TunnelV1Schema, Kind: "operation", ID: "operation_1", ResourceKind: kind, ResourceID: id, Phase: "connecting", State: "running", Progress: 1, CorrelationID: "correlation_1", CreatedAt: time.Unix(1, 0).UTC(), UpdatedAt: time.Unix(1, 0).UTC()}
}

func TestTunnelV1MutationBindsETagAndIdempotency(t *testing.T) {
	client := tunnelTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/v1/tunnels/tun_1" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("If-Match"); got != `"tunnel:tun_1:3"` {
			t.Fatalf("If-Match = %q", got)
		}
		if got := r.Header.Get("Idempotency-Key"); got != "idem_1" {
			t.Fatalf("Idempotency-Key = %q", got)
		}
		writeTunnelTestData(t, w, TunnelMutation{Tunnel: validTunnelTestValue(), Operation: validTunnelOperationTestValue("tunnel", "tun_1")})
	})
	name := "renamed"
	out, err := client.PatchTunnelV1(context.Background(), "tun_1", `"tunnel:tun_1:3"`, "idem_1", TunnelPatchInput{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	if out.Tunnel.ID != "tun_1" {
		t.Fatalf("unexpected tunnel: %#v", out.Tunnel)
	}
}

func TestTunnelV1GetRequiresMatchingResponseETag(t *testing.T) {
	client := tunnelTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"wrong"`)
		writeTunnelTestData(t, w, validTunnelTestValue())
	})
	_, err := client.GetTunnelV1(context.Background(), "tun_1")
	if !errors.Is(err, ErrUnsafeTunnelResponse) {
		t.Fatalf("error = %v", err)
	}
}

func TestTunnelV1RejectsUnsafeAndOversizedPages(t *testing.T) {
	client := tunnelTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		items := make([]Tunnel, 3)
		for i := range items {
			items[i] = validTunnelTestValue()
		}
		writeTunnelTestData(t, w, TunnelPage{Items: items})
	})
	if _, err := client.ListTunnelsV1(context.Background(), "", 2); !errors.Is(err, ErrUnsafeTunnelResponse) {
		t.Fatalf("error = %v", err)
	}
	if _, err := client.ListTunnelsV1(context.Background(), "", 201); err == nil {
		t.Fatal("expected limit error")
	}
	if _, err := client.GetTunnelV1(context.Background(), "../secret"); err == nil {
		t.Fatal("expected identifier error")
	}
}

func TestTunnelV1ConnectorSurfaceCannotIssueEnrollmentSecrets(t *testing.T) {
	// The public client deliberately contains only safe connector reads,
	// drain/revoke and operation-only rotation methods. This response also
	// proves strict decoding rejects a secret-bearing connector payload.
	client := tunnelTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"connector:con_1:1"`)
		_, _ = w.Write([]byte(`{"data":{"schema":"paperboat.preview-tunnel/v1","kind":"connector","id":"con_1","tunnel_id":"tun_1","generation":1,"etag":"\"connector:con_1:1\"","enrollment_token":"secret"}}`))
	})
	if _, err := client.GetTunnelConnectorV1(context.Background(), "tun_1", "con_1"); err == nil {
		t.Fatal("expected strict secret field rejection")
	}
}

func TestTunnelV1PreservesTypedPreconditionError(t *testing.T) {
	client := tunnelTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPreconditionFailed)
		_, _ = w.Write([]byte(`{"error":{"code":"etag_mismatch","message":"resource changed"}}`))
	})
	_, err := client.ChangeTunnelStateV1(context.Background(), "tun_1", "pause", `"tunnel:tun_1:2"`, "idem_1")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusPreconditionFailed || apiErr.Code != "etag_mismatch" {
		t.Fatalf("error = %#v", err)
	}
}

func TestTunnelV1RejectsInvalidInputsBeforeRequest(t *testing.T) {
	requests := 0
	client := tunnelTestClient(t, func(http.ResponseWriter, *http.Request) { requests++ })
	badOrigin := TunnelCreateInput{Name: "demo", AccessMode: "public", Origin: TunnelOriginInput{Scheme: "http", Address: "user@origin.example:80"}}
	if _, err := client.CreateTunnelV1(context.Background(), badOrigin, "idem_1"); err == nil {
		t.Fatal("expected origin validation error")
	}
	badRoute := TunnelRouteInput{Name: "tcp", Protocol: "tcp_private", HostMatch: TunnelRouteHostMatch{Type: "exact", Hostname: "private.example.test"}, Origin: TunnelRouteOrigin{Scheme: "tcp", Address: "127.0.0.1:22"}}
	if _, err := client.CreateTunnelRouteV1(context.Background(), "tun_1", "idem_2", badRoute); err == nil {
		t.Fatal("expected private TCP match validation error")
	}
	if _, err := client.CreateTunnelDomainV1(context.Background(), "tun_1", "idem_3", TunnelDomainInput{Hostname: "bad host", RouteID: "route_1", Provider: "generic"}); err == nil {
		t.Fatal("expected domain validation error")
	}
	if requests != 0 {
		t.Fatalf("requests=%d", requests)
	}
}

func TestTunnelV1AcceptsCanonicalServerResourceShapesAndRedactsFailure(t *testing.T) {
	domain := TunnelDomain{Schema: TunnelV1Schema, Kind: "domain_binding", ID: "domain_1", AccountID: "account_1", TunnelID: "tunnel_1", RouteID: "route_1", Hostname: "app.example.test", MatchType: "exact", State: "tls_error", DNS: TunnelDomainDNS{Target: "edge.example.test", ObservedRecords: []string{"edge.example.test"}}, Certificate: TunnelDomainCertificate{State: "failed", Failure: map[string]any{"authorization_token": "never-return", "code": "caa_denied"}}, Generation: 2, ETag: `"domain:domain_1:2"`}
	client := tunnelTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", domain.ETag)
		writeTunnelTestData(t, w, domain)
	})
	out, err := client.GetTunnelDomainV1(context.Background(), "tunnel_1", "domain_1")
	if err != nil {
		t.Fatal(err)
	}
	if out.Certificate.Failure["authorization_token"] != "[REDACTED]" || out.Certificate.Failure["code"] != "caa_denied" {
		t.Fatalf("failure=%v", out.Certificate.Failure)
	}
}

func TestTunnelV1RejectsUnknownAndTrailingResponseJSON(t *testing.T) {
	for _, body := range []string{
		`{"data":{"schema":"paperboat.preview-tunnel/v1","kind":"tunnel","id":"tun_1","unknown":"value"}}`,
		`{"data":{"schema":"paperboat.preview-tunnel/v1","kind":"tunnel","id":"tun_1"} {}}`,
	} {
		t.Run(body[:20], func(t *testing.T) {
			client := tunnelTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			})
			if _, err := client.ListTunnelsV1(context.Background(), "", 10); err == nil {
				t.Fatal("expected strict decode error")
			}
		})
	}
}

func TestTunnelOperationV1IsBoundAndRedactsFailureText(t *testing.T) {
	operation := validTunnelOperationTestValue("tunnel", "tun_1")
	operation.Phase = "failed"
	operation.State = "failed"
	operation.Error = &PreviewTunnelAPIError{Schema: TunnelV1Schema, Kind: "error", Code: "origin_failed", Component: "origin", Message: "Bearer must-not-escape", Outcome: "failed", RepairAction: "replace token secret", RequestID: "request_1", CorrelationID: "correlation_1"}
	client := tunnelTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/operations/operation_1" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		writeTunnelTestData(t, w, operation)
	})
	out, err := client.GetTunnelOperationV1(context.Background(), operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if out.Error == nil || out.Error.Message != "[REDACTED]" || out.Error.RepairAction != "[REDACTED]" {
		t.Fatalf("operation=%#v", out)
	}
}

func TestTunnelOperationV1RejectsOtherResourceFamilies(t *testing.T) {
	operation := validTunnelOperationTestValue("preview_lease", "preview_1")
	client := tunnelTestClient(t, func(w http.ResponseWriter, _ *http.Request) { writeTunnelTestData(t, w, operation) })
	if _, err := client.GetTunnelOperationV1(context.Background(), operation.ID); !errors.Is(err, ErrUnsafeTunnelResponse) {
		t.Fatalf("error=%v", err)
	}
}

func TestTunnelRoutePatchEncodesExplicitPathClearWithOCC(t *testing.T) {
	client := tunnelTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-Match") != `"route:route_1:1"` || r.Header.Get("Idempotency-Key") != "idem_1" {
			t.Fatalf("headers=%v", r.Header)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if value, present := body["path_prefix"]; !present || value != nil {
			t.Fatalf("body=%#v", body)
		}
		route := TunnelRoute{Schema: TunnelV1Schema, Kind: "route", ID: "route_1", TunnelID: "tun_1", Name: "api", Protocol: "http", HostMatch: TunnelRouteHostMatch{Type: "catch_all"}, Origin: TunnelRouteOrigin{Scheme: "http", Address: "127.0.0.1:8080", PreserveHost: true}, Priority: 0, ConnectTimeoutMS: 10000, IdleTimeoutMS: 300000, MaxConcurrentStreams: 128, DesiredState: "active", Generation: 2, ETag: `"route:route_1:2"`}
		writeTunnelTestData(t, w, TunnelRouteMutation{Route: route, Operation: validTunnelOperationTestValue("route", route.ID), Changed: true})
	})
	out, err := client.PatchTunnelRouteV1(context.Background(), "tun_1", "route_1", `"route:route_1:1"`, "idem_1", TunnelRoutePatch{PathPrefixSet: true})
	if err != nil || out.Route.PathPrefix != nil {
		t.Fatalf("out=%#v error=%v", out, err)
	}
}

func TestTunnelDomainInstructionsV1BindsIdentityAndRedactsNote(t *testing.T) {
	client := tunnelTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tunnels/tun_1/domains/domain_1/instructions" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		instructions := TunnelDNSInstructions{Schema: TunnelV1Schema, Kind: "dns_instructions", TunnelID: "tun_1", DomainID: "domain_1", Hostname: "app.example.test", Provider: "generic", Records: []TunnelDNSRecord{{Name: "app.example.test", Type: "CNAME", Value: "edge.example.test", TTL: 300}}, CertificateStrategy: "managed", VerificationState: "waiting_dns", Note: "Bearer must-not-escape"}
		writeTunnelTestData(t, w, instructions)
	})
	out, err := client.TunnelDomainInstructionsV1(context.Background(), "tun_1", "domain_1")
	if err != nil {
		t.Fatal(err)
	}
	if out.Note != "[REDACTED]" {
		t.Fatalf("instructions=%#v", out)
	}
}

func TestTunnelStatusV1RedactsUnsafeHumanText(t *testing.T) {
	client := tunnelTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		health := validTunnelHealthTestValue()
		health.Summary = "Bearer must-not-escape"
		health.RepairAction = "rotate token secret"
		writeTunnelTestData(t, w, health)
	})
	out, err := client.TunnelStatusV1(context.Background(), "tun_1")
	if err != nil {
		t.Fatal(err)
	}
	if out.Summary != "[REDACTED]" || out.RepairAction != "[REDACTED]" {
		t.Fatalf("health=%#v", out)
	}
}

func TestTunnelConnectorEnrollmentIssueV1WireContract(t *testing.T) {
	input := TunnelConnectorEnrollmentInput{HostID: "host_1", Capabilities: []string{"http", "tcp"}, TTLSeconds: 300}
	wantBody, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	client := tunnelTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tunnels/tun_1/connectors/enrollments" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Idempotency-Key"); got != "idem_enroll_1" {
			t.Fatalf("Idempotency-Key = %q", got)
		}
		gotBody, readErr := io.ReadAll(r.Body)
		if readErr != nil || string(gotBody) != string(wantBody) {
			t.Fatalf("body = %q, read error = %v; want %q", gotBody, readErr, wantBody)
		}
		w.Header().Set("Cache-Control", "no-store")
		enrollment := TunnelConnectorEnrollment{Schema: TunnelV1Schema, Kind: "connector_enrollment", ID: "enrollment_1", TunnelID: "tun_1", HostID: "host_1", Operation: validTunnelOperationTestValue("connector", "enrollment_1"), EnrollmentToken: "one-time-enrollment-token", ExpiresAt: time.Unix(7200, 0).UTC(), Capabilities: input.Capabilities}
		writeTunnelTestData(t, w, enrollment)
	})
	out, err := client.IssueTunnelConnectorEnrollmentV1(context.Background(), "tun_1", "idem_enroll_1", input)
	if err != nil {
		t.Fatal(err)
	}
	if out.ID != "enrollment_1" || out.EnrollmentToken != "one-time-enrollment-token" || out.Operation.ResourceID != "enrollment_1" {
		t.Fatalf("enrollment = %#v", out)
	}
}

func TestTunnelConnectorEnrollmentExchangeV1WireContract(t *testing.T) {
	input := TunnelConnectorEnrollmentExchangeInput{
		Token:                       "one-time-enrollment-token",
		HostID:                      "host_1",
		ProtocolVersion:             "1.0",
		CredentialReference:         "protected-file://paperboat/connector_1",
		CredentialThumbprint:        strings.Repeat("A", 43),
		CredentialVerifierAlgorithm: "ed25519",
		CredentialVerifierPublicKey: strings.Repeat("B", 43),
		CredentialProof:             strings.Repeat("C", 86),
	}
	wantBody, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	client := tunnelTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tunnels/tun_1/connectors/enrollments/exchange" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Idempotency-Key"); got != "idem_exchange_1" {
			t.Fatalf("Idempotency-Key = %q", got)
		}
		gotBody, readErr := io.ReadAll(r.Body)
		if readErr != nil || string(gotBody) != string(wantBody) {
			t.Fatalf("body = %q, read error = %v; want %q", gotBody, readErr, wantBody)
		}
		w.Header().Set("Cache-Control", "no-store")
		activation := TunnelConnectorActivation{Schema: TunnelV1Schema, Kind: "connector_activation", AccountID: "acc_1", TunnelID: "tun_1", ConnectorID: "connector_1", HostID: "host_1", CredentialGeneration: 2, ProcessGeneration: 3, Operation: validTunnelOperationTestValue("connector", "connector_1")}
		writeTunnelTestData(t, w, activation)
	})
	out, err := client.ExchangeTunnelConnectorEnrollmentV1(context.Background(), "tun_1", "idem_exchange_1", input)
	if err != nil {
		t.Fatal(err)
	}
	if out.ConnectorID != "connector_1" || out.CredentialGeneration != 2 || out.Operation.ResourceID != out.ConnectorID {
		t.Fatalf("activation = %#v", out)
	}
}

func TestTunnelEventsV1WireContractAndRedaction(t *testing.T) {
	client := tunnelTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/tunnels/tun_1/events" || r.URL.Query().Get("cursor") != "cursor_1" || r.URL.Query().Get("limit") != "10" {
			t.Fatalf("request = %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		event := TunnelEvent{Schema: TunnelV1Schema, Kind: "event", ID: "event_1", Cursor: "cursor_2", EventType: "connector.ready", ResourceKind: "tunnel", ResourceID: "tun_1", OccurredAt: time.Unix(3, 0).UTC(), Actor: TunnelEventActor{Type: "system", ID: "system_1"}, CorrelationID: "correlation_1", SafeMetadata: map[string]any{"token": "must-not-escape", "safe": "value"}}
		writeTunnelTestData(t, w, TunnelEventPage{Items: []TunnelEvent{event}, NextCursor: "cursor_3"})
	})
	out, err := client.ListTunnelEventsV1(context.Background(), "tun_1", "cursor_1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != 1 || out.NextCursor != "cursor_3" || out.Items[0].SafeMetadata["token"] != "[REDACTED]" || out.Items[0].SafeMetadata["safe"] != "value" {
		t.Fatalf("events = %#v", out)
	}
}

func TestTunnelPrivateAccessDiscoveryV1WireContract(t *testing.T) {
	key := "idem_private_1"
	client := tunnelTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/private-access/routes" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Idempotency-Key"); got != key {
			t.Fatalf("Idempotency-Key = %q", got)
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil || string(body) != `{"idempotency_key":"idem_private_1"}` {
			t.Fatalf("body = %q, read error = %v", body, readErr)
		}
		admission := TunnelPrivateAccessAdmission{
			Schema: TunnelV1Schema, Kind: "private_access_carrier_admission", AccountID: "acc_1", DeviceID: "device_1", InstallationGeneration: 1,
			AccessorPublicKey: strings.Repeat("A", 43), AccessorThumbprint: strings.Repeat("B", 43), ResourceKind: "tunnel", ResourceID: "tun_1", TunnelName: "demo", RouteName: "private", ConnectorID: "connector_1", CarrierSessionID: "session_1", RouteID: "route_1", RouteGeneration: 1, SessionGeneration: 1, ProcessGeneration: 1, ConfigGeneration: 1, AssignmentGeneration: 1, AssignmentID: "assignment_1", ConfigContentHash: "sha256:" + strings.Repeat("a", 64), EdgeNodeID: "edge_1", EdgeProcessEpoch: "epoch_001", EdgeCarrierServerSPKISHA256: "sha256:" + strings.Repeat("b", 64), EdgeCarrierServerCertificateChainPEM: "certificate-chain", Protocol: "http", Hostname: "app.example.test", MatchType: "exact", EdgeEndpoints: []string{"tls://edge.example.test:25001", "quic://edge.example.test:25002"}, ExpiresAt: time.Now().UTC().Add(time.Hour), TunnelID: "tun_1", CarrierConnectorID: "connector_1",
		}
		writeTunnelTestData(t, w, TunnelPrivateAccessSnapshot{Schema: TunnelV1Schema, Kind: "private_access_carrier_snapshot", Complete: true, Admissions: []TunnelPrivateAccessAdmission{admission}})
	})
	out, err := client.DiscoverTunnelPrivateAccessRoutesV1(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Complete || len(out.Admissions) != 1 || out.Admissions[0].TunnelID != "tun_1" {
		t.Fatalf("snapshot = %#v", out)
	}
}

func TestTunnelV1RefusesRedirects(t *testing.T) {
	redirected := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected++ }))
	t.Cleanup(target.Close)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL+"/v1/tunnels/tun_1")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(server.Close)
	client := New(server.URL, config.Credential{AccessToken: "client-token"}, server.Client())
	if _, err := client.GetTunnelV1(context.Background(), "tun_1"); !errors.Is(err, ErrTunnelRedirect) {
		t.Fatalf("redirect error = %v", err)
	}
	if redirected != 0 {
		t.Fatalf("redirect target received %d requests", redirected)
	}
}

func TestTunnelV1RejectsDuplicateAndTrailingJSON(t *testing.T) {
	for _, body := range []string{
		`{"data":{"items":[],"items":[]}}`,
		`{"data":{"items":[]}} {}`,
	} {
		client := tunnelTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})
		if _, err := client.ListTunnelsV1(context.Background(), "", 10); err == nil {
			t.Fatalf("body %q was accepted", body)
		}
	}
}

func TestTunnelDomainCertificateStrategyV1(t *testing.T) {
	domain := TunnelDomain{Schema: TunnelV1Schema, Kind: "domain_binding", ID: "domain_1", AccountID: "account_1", TunnelID: "tunnel_1", RouteID: "route_1", Hostname: "app.example.test", MatchType: "exact", CertificateStrategy: "managed", State: "ready", DNS: TunnelDomainDNS{Target: "edge.example.test"}, Certificate: TunnelDomainCertificate{State: "ready"}, Generation: 2, ETag: `"domain:domain_1:2"`}
	client := tunnelTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", domain.ETag)
		writeTunnelTestData(t, w, domain)
	})
	out, err := client.GetTunnelDomainV1(context.Background(), "tunnel_1", "domain_1")
	if err != nil {
		t.Fatal(err)
	}
	if out.CertificateStrategy != "managed" {
		t.Fatalf("certificate strategy = %q", out.CertificateStrategy)
	}
}
