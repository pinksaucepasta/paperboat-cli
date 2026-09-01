package runtime

import (
	"net/http"
	"testing"
)

type privateTCPAccessHandlerProvider struct{ handler http.Handler }

func (p privateTCPAccessHandlerProvider) PrivateTCPAccess() http.Handler { return p.handler }

func TestPreviewPrivateTCPAccessHandlerRequiresExplicitStableProvider(t *testing.T) {
	want := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if got := previewPrivateTCPAccessHandler(privateTCPAccessHandlerProvider{handler: want}); got == nil {
		t.Fatal("expected stable private TCP handler")
	}
	if got := previewPrivateTCPAccessHandler(struct{}{}); got != nil {
		t.Fatalf("unexpected handler: %#v", got)
	}
	if got := previewPrivateTCPAccessHandler(privateTCPAccessHandlerProvider{}); got != nil {
		t.Fatalf("unexpected nil provider handler: %#v", got)
	}
}
