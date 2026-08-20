//go:build windows && paperboat_native_network_e2e

package networkmonitor

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// TestNativeWindowsObserverReceivesExternalInterfaceChange is orchestrated by
// the Windows qualification runner. After the ready marker, the runner toggles
// a disposable or explicitly selected adapter and restores it before the test
// exits. This test never mutates network configuration itself.
func TestNativeWindowsObserverReceivesExternalInterfaceChange(t *testing.T) {
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
	for {
		select {
		case event := <-events:
			if event.Generation == 0 || event.Reasons == 0 || !event.FingerprintValid || event.Fingerprint == [32]byte{} {
				t.Fatalf("invalid native event: %+v", event)
			}
			if monitor.Generation() != event.Generation {
				t.Fatalf("monitor generation=%d event=%d", monitor.Generation(), event.Generation)
			}
			fmt.Printf("PAPERBOAT_NETWORK_MONITOR_EVENT generation=%d reasons=%d rebind=%t ipv4=%t ipv6=%t viable=%t\n", event.Generation, event.Reasons, event.Rebind, event.IPv4, event.IPv6, event.Viable)
			return
		case <-deadline.C:
			t.Fatal("native Windows network monitor received no external interface change")
		}
	}
}
