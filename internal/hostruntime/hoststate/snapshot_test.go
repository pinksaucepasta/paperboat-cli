package hoststate

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func snapshotFixturePayload(generation uint64) []byte {
	return []byte(fmt.Sprintf(`{"schema":"paperboat.preview-tunnel/v1","kind":"tunnel_config_snapshot","tunnel_id":"tun_01","generation":%d,"name":"demo","desired_state":"active","access_mode":"public","stable_endpoint":"https://123e4567-e89b-12d3-a456-426614174000.tunnels.example.test","expires_at":null,"routes":[{"id":"rte_01","name":"default","protocol":"http","match_type":"catch_all","path_prefix":null,"origin_scheme":"http","origin_address":"127.0.0.1:3000","preserve_host":true,"host_override":null,"tls_verification":"not_applicable","tls_server_name":null,"ca_reference":null,"mtls_credential_reference":null,"connect_timeout_ms":10000,"idle_timeout_ms":90000,"max_concurrent_streams":128,"desired_state":"active"}]}`, generation))
}

func TestParseTunnelConfigSnapshotStrictCanonicalShape(t *testing.T) {
	valid := snapshotFixturePayload(7)
	parsed, err := ParseTunnelConfigSnapshot(valid, "tun_01", 7)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Kind != "tunnel_config_snapshot" || parsed.Generation != 7 || len(parsed.Routes) != 1 {
		t.Fatalf("parsed snapshot = %+v", parsed)
	}

	tests := []struct {
		name    string
		payload []byte
		want    error
	}{
		{name: "unknown top-level field", payload: []byte(strings.TrimSuffix(string(valid), "}") + `,"unexpected":true}`), want: ErrInvalidState},
		{name: "trailing data", payload: append(append([]byte(nil), valid...), []byte(` {}`)...), want: ErrInvalidState},
		{name: "missing required field", payload: []byte(strings.Replace(string(valid), `"name":"demo",`, "", 1)), want: ErrInvalidState},
		{name: "duplicate field", payload: []byte(strings.Replace(string(valid), `"name":"demo",`, `"name":"demo","name":"other",`, 1)), want: ErrInvalidState},
		{name: "unknown route field", payload: []byte(strings.Replace(string(valid), `"desired_state":"active"}]}`, `"desired_state":"active","unexpected":true}]}`, 1)), want: ErrInvalidState},
		{name: "unsafe credential reference", payload: []byte(strings.Replace(string(valid), `"mtls_credential_reference":null`, `"mtls_credential_reference":"https://user:secret@example.test/key"`, 1)), want: ErrCredentialMaterial},
		{name: "identity mismatch", payload: valid, want: ErrInvalidState},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tunnelID, generation := "tun_01", uint64(7)
			if test.name == "identity mismatch" {
				tunnelID = "tun_02"
			}
			_, err := ParseTunnelConfigSnapshot(test.payload, tunnelID, generation)
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestStableEndpointIDForEndpointRequiresCanonicalUUIDFirstLabel(t *testing.T) {
	validID := "123e4567-e89b-12d3-a456-426614174000"
	for _, test := range []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "canonical", endpoint: "https://" + validID + ".tunnels.pprbt.dev", want: validID},
		{name: "hostname", endpoint: "https://demo.tunnels.pprbt.dev"},
		{name: "missing parent label", endpoint: "https://" + validID},
		{name: "hash fallback", endpoint: "https://tep_0123456789abcdef.tunnels.pprbt.dev"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := StableEndpointIDForEndpoint(test.endpoint)
			if test.want == "" {
				if !errors.Is(err, ErrInvalidState) {
					t.Fatalf("error = %v, want ErrInvalidState", err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("id=%q err=%v, want %q", got, err, test.want)
			}
		})
	}
}

func TestParseTunnelConfigSnapshotAcceptsHTTPUnixOrigin(t *testing.T) {
	payload := strings.Replace(string(snapshotFixturePayload(8)),
		`"origin_scheme":"http","origin_address":"127.0.0.1:3000"`,
		`"origin_scheme":"unix","origin_address":"/var/run/paperboat-origin.sock"`, 1)
	parsed, err := ParseTunnelConfigSnapshot([]byte(payload), "tun_01", 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Routes) != 1 || parsed.Routes[0].Protocol != "http" || parsed.Routes[0].OriginScheme != "unix" {
		t.Fatalf("parsed Unix route = %+v", parsed.Routes)
	}
}
