package tunnel

import (
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/localapi"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

func TestLocalPeerRequestCarriesCanonicalPath(t *testing.T) {
	for _, path := range []TerminalTransport{TerminalTransportAuto, TerminalTransportDirect, TerminalTransportRelayQUIC, TerminalTransportRelayWSS, TerminalTransportRelay} {
		t.Run(string(path), func(t *testing.T) {
			tunnel := LocalPeerTunnel{Client: &localapi.Client{}, Transport: path}
			request, err := tunnel.request(resolver.ConnectInfo{ProjectID: "machine_1", MachineGeneration: 2, Terminal: &resolver.TerminalTarget{EnvironmentID: "environment_1", Auth: resolver.AuthTarget{Token: "token", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}}}, "ssh", "operation_1", nil)
			if err != nil || request.Transport != string(path) {
				t.Fatalf("transport=%q err=%v", request.Transport, err)
			}
		})
	}
}
