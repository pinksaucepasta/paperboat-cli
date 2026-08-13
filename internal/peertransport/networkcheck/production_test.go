package networkcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeStackUsesOwnedControlledSockets(t *testing.T) {
	result, err := ProbeStack(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.UDP || !result.IPv4 && !result.IPv6 {
		t.Fatalf("result=%#v", result)
	}
}

func TestProbeCaptivePortalRequiresExactHTTPS204WithoutRedirect(t *testing.T) {
	clear := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Accept") != "application/octet-stream" {
			t.Errorf("accept=%q", request.Header.Get("Accept"))
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer clear.Close()
	result, err := ProbeCaptivePortal(context.Background(), clear.Client(), clear.URL+"/network-check")
	if err != nil || !result.Complete || result.Suspected {
		t.Fatalf("clear result=%#v err=%v", result, err)
	}
	portal := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", clear.URL+"/network-check")
		writer.WriteHeader(http.StatusFound)
	}))
	defer portal.Close()
	result, err = ProbeCaptivePortal(context.Background(), portal.Client(), portal.URL+"/network-check")
	if err != nil || !result.Complete || !result.Suspected {
		t.Fatalf("portal result=%#v err=%v", result, err)
	}
	content := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write([]byte("login")) }))
	defer content.Close()
	result, err = ProbeCaptivePortal(context.Background(), content.Client(), content.URL)
	if err != nil || !result.Suspected {
		t.Fatalf("content result=%#v err=%v", result, err)
	}
	if _, err := ProbeCaptivePortal(context.Background(), clear.Client(), "http://example.test/check"); err == nil {
		t.Fatal("HTTP endpoint accepted")
	}
}
