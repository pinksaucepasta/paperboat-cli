package api

import "testing"

func TestClientScopesMatchPreviewTunnelAuthorizationContract(t *testing.T) {
	want := map[string]bool{
		"account:read": true, "clients:revoke": true, "projects:read": true, "projects:connect": true,
		"session:refresh": true, "diagnostics:upload": true, "previews:read": true, "previews:write": true,
		"tunnels:read": true, "tunnels:write": true, "operations:read": true, "operations:write": true,
	}
	if len(ClientScopes) != len(want) {
		t.Fatalf("client scopes = %d, want %d: %#v", len(ClientScopes), len(want), ClientScopes)
	}
	seen := make(map[string]bool, len(ClientScopes))
	for _, scope := range ClientScopes {
		if !want[scope] || seen[scope] {
			t.Fatalf("unexpected or duplicate client scope %q", scope)
		}
		seen[scope] = true
	}
}
