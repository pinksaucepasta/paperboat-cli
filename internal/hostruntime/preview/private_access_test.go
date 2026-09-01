package preview

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/privatepreviewproxy"
)

type privateAccessTestAuth struct{}

func (privateAccessTestAuth) Token(context.Context) (string, error) {
	return "machine-control-token", nil
}
func (privateAccessTestAuth) Proof(context.Context, string, string, string, []byte) ([]byte, error) {
	return []byte("machine-proof"), nil
}

type privateAccessRoundTripper func(*http.Request) (*http.Response, error)

func (f privateAccessRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestPrivateAccessSourceIssuesMachineProofAndOpensBoundCarrierStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Now().UTC().Truncate(time.Second)
	identity := testPreviewCarrierIdentity(1)
	pair := newPreviewCarrierPair(t, ctx, identity)
	defer pair.close()

	transport := privateAccessRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != privateAccessGrantPath || request.Header.Get("Authorization") != "Bearer machine-control-token" || request.Header.Get("X-Paperboat-Machine-Identity") != "machine-control-token" || request.Header.Get("X-Paperboat-Machine-Proof") != base64.RawURLEncoding.EncodeToString([]byte("machine-proof")) || request.Header.Get("Cookie") != "" {
			t.Fatalf("grant headers/path = %s %#v", request.URL.Path, request.Header)
		}
		var issue privateAccessGrantIssue
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&issue); err != nil {
			t.Fatal(err)
		}
		normalized := connectorprotocol.PrivateAccessRequest{
			AccountID: "account_01", ResourceKind: issue.ResourceKind, ResourceID: issue.ResourceID, RouteID: issue.RouteID,
			Audience: issue.Audience, DeviceID: "host_01", SessionID: "installation_1", InstallationGeneration: 1,
			ExpiresAt: issue.ExpiresAt, Nonce: issue.Nonce, OperationID: issue.OperationID, CarrierSessionID: issue.CarrierSessionID,
			RouteGeneration: issue.RouteGeneration, ProcessGeneration: issue.ProcessGeneration, ConfigGeneration: issue.ConfigGeneration,
			SessionGeneration: issue.SessionGeneration, AssignmentGeneration: issue.AssignmentGeneration, EdgeNodeID: issue.EdgeNodeID,
			EdgeProcessEpoch: issue.EdgeProcessEpoch, Protocol: issue.Protocol, Method: issue.Method, Host: issue.Host, Path: issue.Path,
			IdempotencyKey: issue.IdempotencyKey, RequestID: issue.RequestID, CorrelationID: issue.CorrelationID,
		}
		body, err := json.Marshal(privateAccessGrantResponse{Schema: connectorprotocol.PrivateAccessSchema, Kind: connectorprotocol.PrivateAccessKind, Grant: "signed-grant", ExpiresAt: issue.ExpiresAt, RequestID: issue.RequestID, CorrelationID: issue.CorrelationID, Request: normalized})
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
	})
	grants, err := newPrivateAccessGrantClient("https://api.example.test", privateAccessTestAuth{}, transport)
	if err != nil {
		t.Fatal(err)
	}
	grants.now = func() time.Time { return now }
	source, err := newPrivateAccessSource(grants)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	lease, attachment := providerTestLeaseAttachment(t, now, "preview_private", "operation_private_01", "route_private_01", identity, 3)
	lease.AccessMode = "private"
	attachment.AccessMode = "private"
	attachment.Binding.LeaseGeneration = 3
	admission, err := attachment.Admission()
	if err != nil {
		t.Fatal(err)
	}
	token, err := source.register(lease, admission, pair.active, identity)
	if err != nil {
		t.Fatal(err)
	}
	if token == 0 {
		t.Fatal("registration token is zero")
	}

	edgeResult := make(chan error, 1)
	go func() {
		stream, streamOpen, acceptErr := pair.edge.AcceptStream(ctx)
		if acceptErr != nil {
			edgeResult <- acceptErr
			return
		}
		defer stream.Close()
		if streamOpen.RouteID != "route_private_01" || streamOpen.Kind != connectorprotocol.PrivateAccessHTTP {
			edgeResult <- errors.New("wrong stream binding")
			return
		}
		accessOpen, readErr := connectorprotocol.ReadPrivateAccessOpen(stream, now)
		if readErr != nil || accessOpen.Grant != "signed-grant" || accessOpen.Request.RouteID != streamOpen.RouteID || accessOpen.Request.SessionGeneration != 3 || accessOpen.Request.AssignmentGeneration != 3 {
			edgeResult <- errors.New("wrong access binding")
			return
		}
		if writeErr := connectorprotocol.WritePrivateAccessResult(stream, connectorprotocol.PrivateAccessResult{Schema: connectorprotocol.PrivateAccessSchema, Kind: connectorprotocol.PrivateAccessKind, Status: http.StatusOK, ExpiresAt: accessOpen.Request.ExpiresAt}); writeErr != nil {
			edgeResult <- writeErr
			return
		}
		payload := make([]byte, len("tls-canary"))
		if _, readErr = io.ReadFull(stream, payload); readErr != nil {
			edgeResult <- readErr
			return
		}
		_, writeErr := stream.Write(payload)
		edgeResult <- writeErr
	}()

	stream, err := source.Open(ctx, "preview.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("tls-canary")); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, len("tls-canary"))
	if _, err := io.ReadFull(stream, payload); err != nil || string(payload) != "tls-canary" {
		t.Fatalf("payload=%q err=%v", payload, err)
	}
	if err := <-edgeResult; err != nil {
		t.Fatal(err)
	}
}

func TestPrivateAccessGrantClientMapsStatusWithoutBrowserCredentials(t *testing.T) {
	for status, want := range map[int]error{
		http.StatusUnauthorized:       privatepreviewproxy.ErrAccessAuthentication,
		http.StatusForbidden:          privatepreviewproxy.ErrAccessForbidden,
		http.StatusServiceUnavailable: privatepreviewproxy.ErrAccessTemporarilyUnavailable,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client, err := newPrivateAccessGrantClient("https://api.example.test", privateAccessTestAuth{}, privateAccessRoundTripper(func(request *http.Request) (*http.Response, error) {
				if strings.Contains(strings.ToLower(request.Header.Get("Authorization")), "cookie") || request.Header.Get("Cookie") != "" {
					t.Fatal("browser credential was forwarded")
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":"redacted"}`)), Request: request}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.issue(context.Background(), privateAccessGrantIssue{IdempotencyKey: "access_test"})
			if !errors.Is(err, want) {
				t.Fatalf("status %d error=%v, want %v", status, err, want)
			}
		})
	}
}

func TestPrivateAccessSnapshotNeverPublishesPrivateTCPToPAC(t *testing.T) {
	now := time.Now().UTC()
	transport := privateAccessRoundTripper(func(request *http.Request) (*http.Response, error) {
		httpAdmission := validAccessorAdmission(t, now, "http")
		httpAdmission.Hostname = "web.example.test"
		tcpAdmission := validAccessorAdmission(t, now, "private_tcp")
		tcpAdmission.Hostname = ""
		tcpAdmission.RouteID = "route_tcp_02"
		tcpAdmission.AssignmentID = "assignment_10"
		if err := httpAdmission.validate(now); err != nil {
			t.Fatalf("http admission fixture: %v", err)
		}
		if err := tcpAdmission.validate(now); err != nil {
			t.Fatalf("tcp admission fixture: %v", err)
		}
		body, err := json.Marshal(accessorSnapshot{Schema: connectorprotocol.PrivateAccessSchema, Kind: "private_access_carrier_snapshot", Complete: true, Admissions: []accessorAdmission{httpAdmission, tcpAdmission}})
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{"Content-Type": []string{"application/json"}}, Request: request}, nil
	})
	discovery, err := newAccessorDiscoveryClient("https://api.example.test", privateAccessTestAuth{}, transport)
	if err != nil {
		t.Fatal(err)
	}
	source, err := newPrivateAccessSource(&privateAccessGrantClient{})
	if err != nil {
		t.Fatal(err)
	}
	source.discovery = discovery
	source.now = func() time.Time { return now }
	routes, err := source.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Hostname != "web.example.test" {
		t.Fatalf("PAC routes=%+v, want only HTTP", routes)
	}
}

func TestAccessorAdmissionRejectsMalformedWireFields(t *testing.T) {
	now := time.Now().UTC()
	for name, mutate := range map[string]func(*accessorAdmission){
		"uppercase hash": func(a *accessorAdmission) { a.ConfigContentHash = "sha256:" + strings.Repeat("A", 64) },
		"nonhex hash":    func(a *accessorAdmission) { a.ConfigContentHash = "sha256:" + strings.Repeat("z", 64) },
		"missing port":   func(a *accessorAdmission) { a.EdgeEndpoints[0] = "tls://edge.example.test" },
		"zero port":      func(a *accessorAdmission) { a.EdgeEndpoints[0] = "tls://edge.example.test:0" },
		"unknown match":  func(a *accessorAdmission) { a.MatchType = "recursive" },
		"http catch all": func(a *accessorAdmission) { a.MatchType = "catch_all" },
		"missing tunnel name": func(a *accessorAdmission) {
			a.TunnelName = ""
		},
		"invalid route name": func(a *accessorAdmission) {
			a.RouteName = "route name"
		},
		"non canonical idna": func(a *accessorAdmission) {
			a.Hostname = "BÜCHER.example"
		},
		"recursive wildcard": func(a *accessorAdmission) {
			a.MatchType = "one_label_wildcard"
			a.Hostname = "**.example.test"
			a.WildcardSuffix = "example.test"
		},
		"invalid suffix": func(a *accessorAdmission) {
			a.MatchType = "one_label_wildcard"
			a.Hostname = "*.example.test"
			a.WildcardSuffix = "*.example.test"
		},
		"protocol resource mismatch": func(a *accessorAdmission) {
			a.ResourceKind = "preview"
			a.OperationID = "operation_01"
			a.ConnectorID = ""
			a.TunnelName = ""
			a.RouteName = ""
			a.Protocol = "private_tcp"
			a.Hostname = ""
			a.MatchType = "catch_all"
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := validAccessorAdmission(t, now, "http")
			mutate(&a)
			if a.validate(now) == nil {
				t.Fatal("malformed admission accepted")
			}
		})
	}
}

func TestPrivateAccessSourceMergesOwnerAndDiscoveredRoutesWithoutOverwrite(t *testing.T) {
	source, err := newPrivateAccessSource(&privateAccessGrantClient{})
	if err != nil {
		t.Fatal(err)
	}
	source.ownerRoutes["owner.example.test"] = privateAccessRoute{}
	source.discoveredRoutes["other.example.test"] = privateAccessRoute{matchType: privatepreviewproxy.AccessMatchManagedExact}
	source.mu.RLock()
	merged, err := source.mergedRoutesLocked()
	source.mu.RUnlock()
	if err != nil || len(merged) != 2 {
		t.Fatalf("merged=%+v error=%v", merged, err)
	}
	source.discoveredRoutes["owner.example.test"] = privateAccessRoute{}
	source.mu.RLock()
	_, err = source.mergedRoutesLocked()
	source.mu.RUnlock()
	if !errors.Is(err, privatepreviewproxy.ErrAccessTemporarilyUnavailable) {
		t.Fatalf("authority collision error=%v", err)
	}
}

func TestAccessorDiscoveryRejectsAmbiguousURLContentTypeAndDuplicates(t *testing.T) {
	for _, raw := range []string{"https://api.example.test?target=other", "https://api.example.test#other"} {
		if _, err := newAccessorDiscoveryClient(raw, privateAccessTestAuth{}, privateAccessRoundTripper(nil)); !errors.Is(err, ErrPrivateAccessInvalid) {
			t.Fatalf("URL %q error=%v", raw, err)
		}
	}
	now := time.Now().UTC()
	admission := validAccessorAdmission(t, now, "http")
	stale := admission
	stale.AssignmentID = "assignment_stale"
	stale.RouteID = "route_stale"
	stale.RouteName = admission.RouteName
	stale.ExpiresAt = now
	jsonResponse := func(snapshot accessorSnapshot) *http.Response {
		raw, _ := json.Marshal(snapshot)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw))}
	}
	for name, response := range map[string]*http.Response{
		"content type":         {StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"schema":"paperboat.preview-tunnel/v1","kind":"private_access_carrier_snapshot","complete":true,"admissions":[]}`))},
		"duplicate":            jsonResponse(accessorSnapshot{Schema: connectorprotocol.PrivateAccessSchema, Kind: "private_access_carrier_snapshot", Complete: true, Admissions: []accessorAdmission{admission, admission}}),
		"incomplete":           jsonResponse(accessorSnapshot{Schema: connectorprotocol.PrivateAccessSchema, Kind: "private_access_carrier_snapshot", Complete: false, Admissions: []accessorAdmission{admission}}),
		"stale duplicate name": jsonResponse(accessorSnapshot{Schema: connectorprotocol.PrivateAccessSchema, Kind: "private_access_carrier_snapshot", Complete: true, Admissions: []accessorAdmission{admission, stale}}),
		"limit plus one":       jsonResponse(accessorSnapshot{Schema: connectorprotocol.PrivateAccessSchema, Kind: "private_access_carrier_snapshot", Complete: true, Admissions: make([]accessorAdmission, privateAccessMaximumAdmissions+1)}),
	} {
		t.Run(name, func(t *testing.T) {
			client, err := newAccessorDiscoveryClient("https://api.example.test", privateAccessTestAuth{}, privateAccessRoundTripper(func(request *http.Request) (*http.Response, error) { response.Request = request; return response, nil }))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.snapshot(context.Background()); !errors.Is(err, privatepreviewproxy.ErrAccessTemporarilyUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func validAccessorAdmission(t *testing.T, now time.Time, protocol string) accessorAdmission {
	t.Helper()
	a := accessorAdmission{Schema: connectorprotocol.PrivateAccessSchema, Kind: "private_access_carrier_admission", AccountID: "account_01", DeviceID: "device_02", InstallationGeneration: 7, AccessorPublicKey: "ugS1P3D8QWeKLIzyLOMZD8l_wp1lo6uY6NdicTbDz58", AccessorThumbprint: "ACVmA_IRxdrb0sXXfLqW6uB5U1oI6rRLPxHcQ0jimlg", ResourceKind: "tunnel", ResourceID: "tunnel_01", TunnelName: "payments", RouteName: "postgres", ConnectorID: "connector_01", CarrierSessionID: "session_01", RouteID: "route_tcp_01", RouteGeneration: 7, SessionGeneration: 4, ProcessGeneration: 2, ConfigGeneration: 3, AssignmentGeneration: 9, AssignmentID: "assignment_09", ConfigContentHash: "sha256:" + strings.Repeat("a", 64), EdgeNodeID: "edge_01", EdgeProcessEpoch: "epoch_001", Protocol: protocol, Hostname: "web.example.test", MatchType: "exact", EdgeEndpoints: []string{"tls://edge.example.test:25001", "quic://edge.example.test:25002"}, ExpiresAt: now.Add(time.Minute), TunnelID: "tunnel_01", CarrierConnectorID: "connector_01"}
	_, certificate := testEdgeServerCertificate(t, now, testPreviewCarrierIdentity(1), a.EdgeProcessEpoch)
	a.EdgeCarrierServerSPKISHA256, a.EdgeCarrierServerCertificateChainPEM = testEdgeServerTrust(t, certificate)
	if protocol == "private_tcp" {
		a.Hostname = ""
		a.MatchType = "catch_all"
	}
	return a
}

func TestPrivateTCPAdmissionRejectsDuplicateStaleAndClosedSource(t *testing.T) {
	now := time.Now().UTC()
	valid := accessorAdmission{ResourceKind: "tunnel", Protocol: "private_tcp", RouteID: "route_tcp_01", ExpiresAt: now.Add(time.Minute)}
	if got, err := privateTCPAdmission([]accessorAdmission{valid}, valid.RouteID, now); err != nil || got.RouteID != valid.RouteID {
		t.Fatalf("valid admission=%+v err=%v", got, err)
	}
	if _, err := privateTCPAdmission([]accessorAdmission{valid, valid}, valid.RouteID, now); !errors.Is(err, privatepreviewproxy.ErrAccessTemporarilyUnavailable) {
		t.Fatalf("duplicate error=%v", err)
	}
	stale := valid
	stale.ExpiresAt = now
	if _, err := privateTCPAdmission([]accessorAdmission{stale}, stale.RouteID, now); !errors.Is(err, privatepreviewproxy.ErrAccessForbidden) {
		t.Fatalf("stale error=%v", err)
	}
	source, err := newPrivateAccessSource(&privateAccessGrantClient{})
	if err != nil {
		t.Fatal(err)
	}
	source.discovery = &accessorDiscoveryClient{}
	source.sessions = &MachineAttachmentSessionSource{}
	source.Close()
	if _, err := source.OpenPrivateTCP(context.Background(), valid.RouteID); !errors.Is(err, privatepreviewproxy.ErrAccessTemporarilyUnavailable) {
		t.Fatalf("closed source error=%v", err)
	}
}
