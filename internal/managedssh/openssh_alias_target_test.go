package managedssh

import "testing"

func TestOpenSSHHostPatternsOnlyPreservesAliasCasing(t *testing.T) {
	tests := []struct {
		name        string
		displayName string
		want        string
	}{
		{name: "display casing", displayName: "Victus-Windows-E2E-Fresh", want: "victus-windows-e2e-fresh.pprbt Victus-Windows-E2E-Fresh.pprbt"},
		{name: "canonical casing", displayName: "victus-windows-e2e-fresh", want: "victus-windows-e2e-fresh.pprbt"},
		{name: "unrelated display name", displayName: "Pujan's Laptop", want: "victus-windows-e2e-fresh.pprbt"},
		{name: "another valid alias", displayName: "apple", want: "victus-windows-e2e-fresh.pprbt"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := openSSHHostPatterns("victus-windows-e2e-fresh.pprbt", test.displayName, "pprbt"); got != test.want {
				t.Fatalf("openSSHHostPatterns() = %q, want %q", got, test.want)
			}
		})
	}
}
