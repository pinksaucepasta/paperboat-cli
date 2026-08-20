//go:build windows

package localdaemon

import (
	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkmonitor"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transportmanager"
)

// windowsTransportNetworkWatcher binds the daemon's cached peer carriers to
// the native Windows address and route notifications used by Tailscale's
// netmon. netmon also debounces callback bursts and detects long sleep/wake
// jumps, so a Wi-Fi roam, VPN transition, DHCP change, or resume fences the
// same UDP-backed carriers as the Unix runtime path.
type windowsTransportNetworkWatcher struct {
	monitor *networkmonitor.Monitor
}

func newWindowsTransportNetworkWatcher(manager *transportmanager.Manager) (*windowsTransportNetworkWatcher, error) {
	if manager == nil {
		return nil, ErrInvalidInventoryConfig
	}
	monitor, err := networkmonitor.New(func(event networkmonitor.Event) {
		if windowsNetworkChangeRequiresRebind(event) {
			manager.NetworkChanged()
		}
	})
	if err != nil {
		return nil, err
	}
	if err := monitor.Start(); err != nil {
		_ = monitor.Close()
		return nil, err
	}
	return &windowsTransportNetworkWatcher{monitor: monitor}, nil
}

func windowsNetworkChangeRequiresRebind(event networkmonitor.Event) bool {
	return event.Rebind
}

func (w *windowsTransportNetworkWatcher) Close() error {
	if w == nil {
		return nil
	}
	if w.monitor == nil {
		return nil
	}
	return w.monitor.Close()
}
