package managedssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var ErrOpenSSHUnavailable = errors.New("a supported OpenSSH client is unavailable")

type OpenSSHCapabilities struct {
	Executable        string
	Version           string
	Include           bool
	ProxyCommand      bool
	IdentityAgent     bool
	KnownHostsCommand bool
}

func (c OpenSSHCapabilities) Ready() bool {
	return c.Executable != "" && c.Include && c.ProxyCommand && c.IdentityAgent && c.KnownHostsCommand
}

func ProbeOpenSSH(ctx context.Context, executable string, timeout time.Duration) (OpenSSHCapabilities, error) {
	if ctx == nil || timeout <= 0 || timeout > 30*time.Second {
		return OpenSSHCapabilities{}, ErrOpenSSHUnavailable
	}
	if strings.TrimSpace(executable) == "" {
		executable = "ssh"
	}
	resolved, err := exec.LookPath(executable)
	if err != nil {
		return OpenSSHCapabilities{}, ErrOpenSSHUnavailable
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return OpenSSHCapabilities{}, err
	}
	// The inboxed Windows OpenSSH client can take several seconds to cold-start
	// under the hosted runner, even though subsequent invocations are fast. Keep
	// the caller's cancellation semantics, but give native Windows process
	// startup a bounded grace period so capability probing is not flaky.
	probeTimeout := timeout
	if runtime.GOOS == "windows" && probeTimeout < 10*time.Second {
		probeTimeout = 10 * time.Second
	}
	capabilities := OpenSSHCapabilities{Executable: resolved}
	versionCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	versionOutput, err := runOpenSSHProbe(versionCtx, resolved, "-V")
	cancel()
	if err != nil {
		return OpenSSHCapabilities{}, fmt.Errorf("%w: %v", ErrOpenSSHUnavailable, err)
	}
	capabilities.Version = strings.Join(strings.Fields(versionOutput), " ")
	if len(capabilities.Version) > 512 {
		capabilities.Version = capabilities.Version[:512]
	}
	directory, err := os.MkdirTemp("", "paperboat-openssh-probe-")
	if err != nil {
		return OpenSSHCapabilities{}, err
	}
	defer os.RemoveAll(directory)
	includeTarget := filepath.Join(directory, "included.conf")
	if err := os.WriteFile(includeTarget, nil, 0o600); err != nil {
		return OpenSSHCapabilities{}, err
	}
	probes := []struct {
		name    string
		content string
		set     func()
	}{
		{"include", "Include \"" + strings.ReplaceAll(includeTarget, "\\", "\\\\") + "\"\nHost probe.invalid\n", func() { capabilities.Include = true }},
		{"proxy", "Host probe.invalid\n    ProxyCommand none\n", func() { capabilities.ProxyCommand = true }},
		{"agent", "Host probe.invalid\n    IdentityAgent none\n", func() { capabilities.IdentityAgent = true }},
		{"known-hosts", "Host probe.invalid\n    KnownHostsCommand /usr/bin/true\n", func() { capabilities.KnownHostsCommand = true }},
	}
	knownHostsCommand := "/usr/bin/true"
	if runtime.GOOS == "windows" {
		knownHostsCommand = `cmd.exe /d /c exit 0`
	}
	probes[3].content = "Host probe.invalid\n    KnownHostsCommand " + knownHostsCommand + "\n"
	for _, probe := range probes {
		path := filepath.Join(directory, probe.name+".conf")
		if err := os.WriteFile(path, []byte(probe.content), 0o600); err != nil {
			return OpenSSHCapabilities{}, err
		}
		probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
		_, probeErr := runOpenSSHProbe(probeCtx, resolved, "-G", "-F", path, "probe.invalid")
		cancel()
		if probeErr == nil {
			probe.set()
			continue
		}
		var exitErr *exec.ExitError
		if !errors.As(probeErr, &exitErr) {
			return OpenSSHCapabilities{}, probeErr
		}
	}
	return capabilities, nil
}

func runOpenSSHProbe(ctx context.Context, executable string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, executable, arguments...)
	// Windows OpenSSH can block when stdin is inherited as the null device. An
	// empty pipe gives it an actual EOF, which is what non-interactive probes
	// need and avoids the native client's no-stdin hang.
	command.Stdin = bytes.NewReader(nil)
	output := &limitedBuffer{remaining: 64 << 10}
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	if ctx.Err() != nil {
		return output.String(), context.Cause(ctx)
	}
	return output.String(), err
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	remaining int
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	if len(value) > b.remaining {
		value = value[:b.remaining]
	}
	if len(value) > 0 {
		_, _ = b.buffer.Write(value)
		b.remaining -= len(value)
	}
	return original, nil
}

func (b *limitedBuffer) String() string { return b.buffer.String() }

var _ io.Writer = (*limitedBuffer)(nil)
