//go:build linux

package config

import "testing"

func TestCredentialStoreAvailableRequiresSessionBus(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	if CredentialStoreAvailable() {
		t.Fatal("credential store reported available without a D-Bus session")
	}
}
