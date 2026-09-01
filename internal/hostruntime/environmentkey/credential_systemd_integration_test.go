//go:build linux

package environmentkey

import (
	"context"
	"os"
	"strconv"
	"testing"
)

func TestSystemdCredentialSourceIntegration(t *testing.T) {
	machineID := os.Getenv("PAPERBOAT_TEST_ENV_MACHINE_ID")
	generationText := os.Getenv("PAPERBOAT_TEST_ENV_GENERATION")
	if machineID == "" || generationText == "" {
		t.Skip("systemd credential integration environment is not configured")
	}
	generation, err := strconv.ParseUint(generationText, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	material, err := (SystemdCredentialSource{MachineID: machineID, Generation: generation}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	material.Destroy()
}
