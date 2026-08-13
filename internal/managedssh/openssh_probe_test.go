package managedssh

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestProbeOpenSSHReportsRequiredCapabilities(t *testing.T) {
	executable, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH client is not installed")
	}
	capabilities, err := ProbeOpenSSH(context.Background(), executable, 2*time.Second)
	if err != nil || !capabilities.Ready() || capabilities.Version == "" || capabilities.Executable == "" {
		t.Fatalf("capabilities=%+v error=%v", capabilities, err)
	}
}

func TestProbeOpenSSHRejectsMissingClientAndCancellation(t *testing.T) {
	if _, err := ProbeOpenSSH(context.Background(), "/not/a/real/ssh", time.Second); !errors.Is(err, ErrOpenSSHUnavailable) {
		t.Fatalf("missing client error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ProbeOpenSSH(ctx, "ssh", time.Second); err == nil {
		t.Fatal("cancelled probe succeeded")
	}
}
