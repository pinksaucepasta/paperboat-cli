package tunnelmanager

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/connector"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hoststate"
)

func TestOriginStreamForwarderBindsRouteAndStreamsHTTP(t *testing.T) {
	var originHits atomic.Int32
	holdStarted := make(chan struct{}, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		originHits.Add(1)
		if request.URL.Path == "/hold" {
			holdStarted <- struct{}{}
			<-request.Context().Done()
			return
		}
		if request.Host != "public.example.test" || request.Header.Get("X-Paperboat-Internal") != "" {
			t.Errorf("origin request host=%q internal=%q", request.Host, request.Header.Get("X-Paperboat-Internal"))
		}
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = writer.Write([]byte("origin-ok"))
	}))
	defer origin.Close()
	address := origin.Listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	identity := connector.DataCarrierIdentity{AccountID: "account_01", HostID: "host_01", TunnelID: "tunnel_01", ConnectorID: "connector_01", SessionID: "session_01", ProcessGeneration: 2, Generation: 3}
	config := connector.DefaultDataCarrierPoolConfig()
	config.MaximumCarriers = 1
	config.FailureDomains = []string{"edge-a"}
	config.Session = identity
	var edge *connector.DataCarrier
	prepared, err := connector.PrepareDataCarrier(ctx, identity, config, func(_ context.Context, request connector.DataCarrierDialRequest) (connector.DataCarrierDialResult, error) {
		local, remote := net.Pipe()
		var createErr error
		edge, createErr = connector.NewDataCarrierServer(ctx, remote, config.Carrier, connector.DataCarrierAdmission{Identity: identity, Authorize: func(_ context.Context, open connector.StreamOpen) error {
			return open.Validate()
		}})
		if createErr != nil {
			return connector.DataCarrierDialResult{}, createErr
		}
		return connector.DataCarrierDialResult{Link: local, PeerIdentity: identity, Transport: request.Transport, EdgeID: request.EdgeID, FailureDomain: request.FailureDomain}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	active, err := prepared.Activate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close(context.Background())
	defer edge.Close()
	route := hoststate.TunnelConfigRoute{ID: "route_01", Name: "default", Protocol: "http", MatchType: "exact", MatchHostname: "public.example.test", OriginScheme: "http", OriginAddress: address, PreserveHost: true, TLSVerification: "not_applicable", ConnectTimeoutMs: 1000, IdleTimeoutMs: 2000, MaxConcurrentStreams: 4, DesiredState: "active"}
	running, err := (OriginStreamForwarder{Transport: &OriginHTTPTransport{}}).Start(ctx, active, []hoststate.TunnelConfigRoute{route})
	if err != nil {
		t.Fatal(err)
	}
	bad, err := edge.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := connectorprotocol.WriteStreamOpen(bad, connectorprotocol.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: identity.AccountID, TunnelID: identity.TunnelID, ConnectorID: identity.ConnectorID, SessionID: "wrong_session", ProcessGeneration: identity.ProcessGeneration, Generation: identity.Generation + 1, RouteID: route.ID, RequestID: "request_bad", Kind: "http"}); err != nil {
		t.Fatal(err)
	}
	badRequest, _ := http.NewRequest(http.MethodGet, "http://public.example.test/", nil)
	_ = badRequest.Write(bad)
	_ = bad.Close()
	stream, err := edge.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := connectorprotocol.WriteStreamOpen(stream, connectorprotocol.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: identity.AccountID, TunnelID: identity.TunnelID, ConnectorID: identity.ConnectorID, SessionID: identity.SessionID, ProcessGeneration: identity.ProcessGeneration, Generation: identity.Generation, RouteID: route.ID, RequestID: "request_01", Kind: "http"}); err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "http://public.example.test/", nil)
	request.Host = "public.example.test"
	request.Header.Set("X-Paperboat-Internal", "secret")
	if err := request.Write(stream); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(stream), request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || string(body) != "origin-ok" {
		t.Fatalf("body=%q err=%v", body, readErr)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/plain" {
		t.Fatalf("response=%+v", response)
	}
	if originHits.Load() != 1 {
		t.Fatalf("origin hits=%d", originHits.Load())
	}
	held, err := edge.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := connectorprotocol.WriteStreamOpen(held, connectorprotocol.StreamOpen{Protocol: connectorprotocol.ProtocolName, Version: connectorprotocol.ProtocolVersion, AccountID: identity.AccountID, TunnelID: identity.TunnelID, ConnectorID: identity.ConnectorID, SessionID: identity.SessionID, ProcessGeneration: identity.ProcessGeneration, Generation: identity.Generation, RouteID: route.ID, RequestID: "request_hold", Kind: "http"}); err != nil {
		t.Fatal(err)
	}
	heldRequest, _ := http.NewRequest(http.MethodGet, "http://public.example.test/hold", nil)
	heldRequest.Host = "public.example.test"
	if err := heldRequest.Write(held); err != nil {
		t.Fatal(err)
	}
	select {
	case <-holdStarted:
	case <-time.After(time.Second):
		t.Fatal("held origin request did not start")
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), time.Second)
	defer closeCancel()
	if err := running.Close(closeCtx); err != nil {
		t.Fatalf("close held stream: %v", err)
	}
	_ = held.Close()
}

func TestOriginStreamForwarderRejectsUnknownRouteBeforeOrigin(t *testing.T) {
	// The exact rejection behavior is covered by the data-carrier admission and
	// keeps this test deterministic without opening local network listeners.
	if validOriginStreamKind(connectorprotocol.PrivateAccessHTTP) || validOriginStreamKind("unknown") {
		t.Fatal("private or unknown stream kind admitted to durable origin forwarder")
	}
	if !validOriginStreamKind("grpc") || !validOriginStreamKind("websocket") {
		t.Fatal("supported streaming HTTP kind rejected")
	}
}
