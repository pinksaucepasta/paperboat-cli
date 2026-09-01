//go:build darwin && paperboat_native_network_e2e

package networkmonitor

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// TestNativeDarwinObserverReceivesExternalInterfaceChange is orchestrated by
// the macOS qualification runner. After the ready marker, the runner toggles
// an explicitly selected interface and restores it before the test exits.
// This process observes the real SystemConfiguration/netmon boundary but never
// mutates network configuration itself.
func TestNativeDarwinObserverReceivesExternalInterfaceChange(t *testing.T) {
	events := make(chan Event, 8)
	monitor, err := NewFingerprinting(bytes.Repeat([]byte{0x5a}, 32), nil, func(event Event) {
		select {
		case events <- event:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close()
	if err := monitor.Start(); err != nil {
		t.Fatal(err)
	}
	initial, err := monitor.CurrentFingerprint()
	if err != nil || initial == [32]byte{} {
		t.Fatalf("initial fingerprint=%x err=%v", initial, err)
	}
	fmt.Println("PAPERBOAT_NETWORK_MONITOR_READY")
	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()
	sawUnavailable := false
	for {
		select {
		case event := <-events:
			if event.Generation == 0 || event.Reasons == 0 {
				t.Fatalf("invalid native event: %+v", event)
			}
			if monitor.Generation() != event.Generation {
				t.Fatalf("monitor generation=%d event=%d", monitor.Generation(), event.Generation)
			}
			if !event.Viable {
				if event.FingerprintValid || event.Fingerprint != [32]byte{} {
					t.Fatalf("unavailable event exposed a fabricated fingerprint: %+v", event)
				}
				sawUnavailable = true
				fmt.Printf("PAPERBOAT_NETWORK_MONITOR_UNAVAILABLE generation=%d reasons=%d\n", event.Generation, event.Reasons)
				continue
			}
			if !sawUnavailable || !event.Rebind || !event.FingerprintValid || event.Fingerprint == [32]byte{} {
				t.Fatalf("restored event did not provide an exact viable rebind after loss: %+v", event)
			}
			fmt.Printf("PAPERBOAT_NETWORK_MONITOR_EVENT generation=%d reasons=%d rebind=%t ipv4=%t ipv6=%t viable=%t\n", event.Generation, event.Reasons, event.Rebind, event.IPv4, event.IPv6, event.Viable)
			return
		case <-deadline.C:
			t.Fatal("native macOS network monitor received no external interface change")
		}
	}
}
