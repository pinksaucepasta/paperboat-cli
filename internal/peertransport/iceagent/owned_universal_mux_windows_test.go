//go:build windows

package iceagent

import "testing"

func TestWindowsHyperVExternalInterfaceIsEligibleForICE(t *testing.T) {
	if excludedInterface("vEthernet (External Virtual Switch)") {
		t.Fatal("Windows Hyper-V external switch was classified as a Linux veth peer")
	}
	if !excludedInterface("Tailscale") {
		t.Fatal("overlay interface was accepted")
	}
}
