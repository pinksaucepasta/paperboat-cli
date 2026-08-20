package windowsopenssh

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"
)

type deadlineRunner struct {
	deadline bool
}

func (r *deadlineRunner) Run(ctx context.Context, _ string, _ ...string) ([]byte, error) {
	deadline, ok := ctx.Deadline()
	r.deadline = ok && time.Until(deadline) > 0 && time.Until(deadline) <= 15*time.Second
	return nil, errors.New("invalid configuration")
}

func TestValidateServiceConfigUsesBoundedContext(t *testing.T) {
	sshd, config := "/opt/openssh/sshd", "/var/lib/paperboat/sshd_config"
	if runtime.GOOS == "windows" {
		sshd, config = `C:\Program Files\OpenSSH\sshd.exe`, `C:\ProgramData\Paperboat\ssh\sshd_config`
	}
	runner := &deadlineRunner{}
	if err := ValidateServiceConfig(runner, sshd, config); err == nil {
		t.Fatal("invalid configuration accepted")
	}
	if !runner.deadline {
		t.Fatal("sshd configuration validation did not receive a bounded context")
	}
}
