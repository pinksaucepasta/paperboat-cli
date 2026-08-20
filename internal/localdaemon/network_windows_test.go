//go:build windows

package localdaemon

import (
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkmonitor"
)

func TestWindowsNetworkChangeRequiresRebind(t *testing.T) {
	if windowsNetworkChangeRequiresRebind(networkmonitor.Event{}) {
		t.Fatal("observation-only network delta requested a rebind")
	}
	if !windowsNetworkChangeRequiresRebind(networkmonitor.Event{Rebind: true}) {
		t.Fatal("rebind-required network delta was ignored")
	}
}
