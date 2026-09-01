package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
)

const tunnelMutationSecretCanary = "pb_secret_mutation_canary_7f0d"

func validAdversarialConnector(tunnelID string) api.TunnelConnector {
	return api.TunnelConnector{
		Schema:              api.TunnelV1Schema,
		Kind:                "connector",
		ID:                  "connector_1",
		TunnelID:            tunnelID,
		HostID:              "host_1",
		CredentialReference: "protected-file://paperboat/connector_1",
		RotationGeneration:  1,
		DesiredState:        "active",
		ProtocolVersion:     "1.0",
		DrainState:          "accepting",
		Generation:          1,
		ETag:                `"connector:connector_1:1"`,
	}
}

func executeAdversarialTunnelCommand(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	command := tunnelCobraCommandV1()
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs(args)
	err := command.Execute()
	return stdout.String(), stderr.String(), err
}

func assertNoTunnelMutationSecret(t *testing.T, values ...string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(value, tunnelMutationSecretCanary) {
			t.Fatalf("secret canary escaped: %q", value)
		}
	}
}

func TestTunnelRouteMutationIdempotencyReplayAndConflict(t *testing.T) {
	var firstBody []byte
	requests := 0
	withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tunnels/tun_1/routes" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Idempotency-Key") != "idem_test" || r.Header.Get("If-Match") != "" {
			t.Fatalf("mutation headers=%v", r.Header)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		requests++
		if firstBody == nil {
			firstBody = append([]byte(nil), body...)
		} else if !bytes.Equal(body, firstBody) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":{"code":"idempotency_conflict","message":"the idempotency key is already bound to another request"}}`)
			return
		}
		var input api.TunnelRouteInput
		if err := json.Unmarshal(body, &input); err != nil {
			t.Fatal(err)
		}
		route := validCommandRoute("route_1", input.Name)
		route.Origin = input.Origin
		_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRouteMutation{
			Route: route, Operation: validCommandOperation("route", route.ID), Changed: true, Replayed: requests > 1,
		}})
	})

	args := []string{"route", "add", "tun_1", "--name", "api", "--to", "http://127.0.0.1:8080", "--json"}
	firstOut, firstErrOut, err := executeAdversarialTunnelCommand(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	secondOut, secondErrOut, err := executeAdversarialTunnelCommand(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(firstOut, `"replayed":false`) || !strings.Contains(secondOut, `"replayed":true`) || firstErrOut != "" || secondErrOut != "" {
		t.Fatalf("first=%q second=%q stderr=%q/%q", firstOut, secondOut, firstErrOut, secondErrOut)
	}

	stdout, stderr, err := executeAdversarialTunnelCommand(t, "route", "add", "tun_1", "--name", "different", "--to", "http://127.0.0.1:8080", "--json")
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict || apiErr.Code != "idempotency_conflict" {
		t.Fatalf("error=%T %v", err, err)
	}
	if stdout != "" || stderr != "" || requests != 3 {
		t.Fatalf("stdout=%q stderr=%q requests=%d", stdout, stderr, requests)
	}
	assertNoTunnelMutationSecret(t, firstOut, secondOut, stdout, stderr, err.Error())
}

func TestTunnelMutationsRequireCurrentETagAndMapStaleWrites(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		readMethod string
		readPath   string
		mutMethod  string
		mutPath    string
		writeRead  func(http.ResponseWriter)
	}{
		{
			name: "route", args: []string{"route", "update", "tun_1", "route_1", "--name", "renamed", "--json"},
			readMethod: http.MethodGet, readPath: "/v1/tunnels/tun_1/routes", mutMethod: http.MethodPatch, mutPath: "/v1/tunnels/tun_1/routes/route_1",
			writeRead: func(w http.ResponseWriter) {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRoutePage{Items: []api.TunnelRoute{validCommandRoute("route_1", "api")}}})
			},
		},
		{
			name: "domain", args: []string{"domain", "verify", "tun_1", "domain_1", "--json"},
			readMethod: http.MethodGet, readPath: "/v1/tunnels/tun_1/domains", mutMethod: http.MethodPost, mutPath: "/v1/tunnels/tun_1/domains/domain_1/verify",
			writeRead: func(w http.ResponseWriter) {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelDomainPage{Items: []api.TunnelDomain{validCommandDomain("domain_1", "app.example.test")}}})
			},
		},
		{
			name: "connector", args: []string{"connector", "drain", "tun_1", "connector_1", "--json"},
			readMethod: http.MethodGet, readPath: "/v1/tunnels/tun_1/connectors/connector_1", mutMethod: http.MethodPost, mutPath: "/v1/tunnels/tun_1/connectors/connector_1/drain",
			writeRead: func(w http.ResponseWriter) {
				connector := validAdversarialConnector("tun_1")
				w.Header().Set("ETag", connector.ETag)
				_ = json.NewEncoder(w).Encode(map[string]any{"data": connector})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name+" stale", func(t *testing.T) {
			mutations := 0
			withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == test.readMethod && r.URL.Path == test.readPath:
					test.writeRead(w)
				case r.Method == test.mutMethod && r.URL.Path == test.mutPath:
					mutations++
					if r.Header.Get("If-Match") == "" || r.Header.Get("Idempotency-Key") != "idem_test" {
						t.Fatalf("mutation headers=%v", r.Header)
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusPreconditionFailed)
					_, _ = io.WriteString(w, `{"error":{"code":"etag_mismatch","message":"the resource changed; refresh and retry"}}`)
				default:
					t.Fatalf("request=%s %s", r.Method, r.URL.Path)
				}
			})
			stdout, stderr, err := executeAdversarialTunnelCommand(t, test.args...)
			var apiErr *api.APIError
			if !errors.As(err, &apiErr) || apiErr.Status != http.StatusPreconditionFailed || apiErr.Code != "etag_mismatch" || mutations != 1 {
				t.Fatalf("error=%T %v mutations=%d", err, err, mutations)
			}
			if stdout != "" || stderr != "" || apiErrorFallback(apiErr) != "Paperboat could not complete the request. Retry the command; if this continues, run `pb doctor`." {
				t.Fatalf("stdout=%q stderr=%q fallback=%q", stdout, stderr, apiErrorFallback(apiErr))
			}
			assertNoTunnelMutationSecret(t, stdout, stderr, err.Error(), apiErrorFallback(apiErr))
		})
	}

	t.Run("missing connector response ETag", func(t *testing.T) {
		mutations := 0
		withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/v1/tunnels/tun_1/connectors/connector_1" {
				mutations++
				t.Fatalf("unexpected mutation=%s %s", r.Method, r.URL.Path)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": validAdversarialConnector("tun_1")})
		})
		stdout, stderr, err := executeAdversarialTunnelCommand(t, "connector", "drain", "tun_1", "connector_1", "--json")
		if !errors.Is(err, api.ErrUnsafeTunnelResponse) || mutations != 0 || stdout != "" || stderr != "" {
			t.Fatalf("error=%v mutations=%d stdout=%q stderr=%q", err, mutations, stdout, stderr)
		}
	})
}

func TestTunnelMutationsRejectWrongAccountResourceProjection(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		serve func(http.ResponseWriter, *http.Request)
	}{
		{
			name: "route", args: []string{"route", "update", "tun_1", "route_other", "--name", "renamed", "--json"},
			serve: func(w http.ResponseWriter, _ *http.Request) {
				route := validCommandRoute("route_other", "other")
				route.TunnelID = "tun_other"
				_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRoutePage{Items: []api.TunnelRoute{route}}})
			},
		},
		{
			name: "domain", args: []string{"domain", "verify", "tun_1", "domain_other", "--json"},
			serve: func(w http.ResponseWriter, _ *http.Request) {
				domain := validCommandDomain("domain_other", "other.example.test")
				domain.TunnelID = "tun_other"
				_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelDomainPage{Items: []api.TunnelDomain{domain}}})
			},
		},
		{
			name: "connector", args: []string{"connector", "revoke", "tun_1", "connector_other", "--yes", "--json"},
			serve: func(w http.ResponseWriter, _ *http.Request) {
				connector := validAdversarialConnector("tun_other")
				connector.ID = "connector_other"
				connector.CredentialReference = "protected-file://paperboat/connector_other"
				connector.ETag = `"connector:connector_other:1"`
				w.Header().Set("ETag", connector.ETag)
				_ = json.NewEncoder(w).Encode(map[string]any{"data": connector})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodGet {
					t.Fatalf("cross-account mutation was attempted: %s %s", r.Method, r.URL.Path)
				}
				test.serve(w, r)
			})
			stdout, stderr, err := executeAdversarialTunnelCommand(t, test.args...)
			if !errors.Is(err, api.ErrUnsafeTunnelResponse) || requests != 1 || stdout != "" || stderr != "" {
				t.Fatalf("error=%v requests=%d stdout=%q stderr=%q", err, requests, stdout, stderr)
			}
			assertNoTunnelMutationSecret(t, stdout, stderr, err.Error())
		})
	}
}

func TestTunnelMutationSelectorsRejectCursorCyclesAndOversizePages(t *testing.T) {
	t.Run("route cursor cycle", func(t *testing.T) {
		withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/v1/tunnels/tun_1/routes" {
				t.Fatalf("request=%s %s", r.Method, r.URL.Path)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelRoutePage{NextCursor: "cycle"}})
		})
		stdout, stderr, err := executeAdversarialTunnelCommand(t, "route", "update", "tun_1", "missing", "--name", "renamed", "--json")
		if !errors.Is(err, api.ErrUnsafeTunnelResponse) || stdout != "" || stderr != "" {
			t.Fatalf("error=%v stdout=%q stderr=%q", err, stdout, stderr)
		}
	})

	t.Run("connector page exceeds requested bound", func(t *testing.T) {
		withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/v1/tunnels/tun_1/connectors" || r.URL.Query().Get("limit") != "200" {
				t.Fatalf("request=%s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
			connector := validAdversarialConnector("tun_1")
			items := make([]api.TunnelConnector, 201)
			for i := range items {
				items[i] = connector
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.TunnelConnectorPage{Items: items}})
		})
		stdout, stderr, err := executeAdversarialTunnelCommand(t, "connector", "list", "tun_1", "--limit", "200", "--json")
		if !errors.Is(err, api.ErrUnsafeTunnelResponse) || stdout != "" || stderr != "" {
			t.Fatalf("error=%v stdout=%q stderr=%q", err, stdout, stderr)
		}
	})
}

func TestTunnelMutationRejectsSecretBearingUnknownSuccessFields(t *testing.T) {
	withTunnelCommandClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tunnels/tun_1/routes" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		route := validCommandRoute("route_1", "api")
		operation := validCommandOperation("route", route.ID)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"route": route, "operation": operation, "changed": true, "replayed": false,
			"enrollment_token": tunnelMutationSecretCanary,
		}})
	})
	stdout, stderr, err := executeAdversarialTunnelCommand(t, "route", "add", "tun_1", "--name", "api", "--to", "http://127.0.0.1:8080", "--json")
	if err == nil || !strings.Contains(err.Error(), "unknown field") || stdout != "" || stderr != "" {
		t.Fatalf("error=%v stdout=%q stderr=%q", err, stdout, stderr)
	}
	assertNoTunnelMutationSecret(t, stdout, stderr, err.Error())
	if got := apiErrorFallback(&api.APIError{Status: http.StatusForbidden, Message: tunnelMutationSecretCanary}); strings.Contains(got, tunnelMutationSecretCanary) {
		t.Fatalf("forbidden mapping exposed server message: %q", got)
	}
}

func TestTunnelMutationFixtureTimestampsStayValid(t *testing.T) {
	// Guard the shared operation fixture used above against accidental future
	// clock validation changes that would turn these tests into false positives.
	operation := validCommandOperation("route", "route_1")
	if operation.CreatedAt.IsZero() || operation.UpdatedAt.Before(operation.CreatedAt) || operation.CreatedAt.After(time.Now().UTC()) {
		t.Fatalf("invalid operation fixture: %#v", operation)
	}
}
