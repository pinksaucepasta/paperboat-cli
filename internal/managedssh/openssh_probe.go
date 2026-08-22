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
	"sync"
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
	resolved, err := resolveOpenSSHExecutable(executable)
	if err != nil {
		return OpenSSHCapabilities{}, ErrOpenSSHUnavailable
	}
	// The inboxed Windows OpenSSH client can take several seconds to cold-start
	// under the hosted runner, even though subsequent invocations are fast. Keep
	// the caller's cancellation semantics, but give native Windows process
	// startup a bounded grace period so capability probing is not flaky.
	probeTimeout := timeout
	if runtime.GOOS == "windows" && probeTimeout < 10*time.Second {
		probeTimeout = 10 * time.Second
	}
	directory, err := os.MkdirTemp("", "paperboat-openssh-probe-")
	if err != nil {
		return OpenSSHCapabilities{}, err
	}
	defer os.RemoveAll(directory)
	probeEnvironment := isolatedOpenSSHProbeEnvironment(directory)

	capabilities := OpenSSHCapabilities{Executable: resolved}
	versionCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	versionOutput, err := runOpenSSHProbeEnv(versionCtx, probeEnvironment, resolved, "-V")
	cancel()
	if err != nil {
		return OpenSSHCapabilities{}, fmt.Errorf("%w: %v", ErrOpenSSHUnavailable, err)
	}
	capabilities.Version = strings.Join(strings.Fields(versionOutput), " ")
	if len(capabilities.Version) > 512 {
		capabilities.Version = capabilities.Version[:512]
	}
	includeTarget := filepath.Join(directory, "included.conf")
	if err := os.WriteFile(includeTarget, []byte("Host probe.invalid\n    User paperboat-probe-include\n"), 0o600); err != nil {
		return OpenSSHCapabilities{}, err
	}
	probePath := filepath.Join(directory, "capabilities.conf")
	probeContent := "Include \"" + strings.ReplaceAll(includeTarget, "\\", "\\\\") + "\"\n" +
		"Host probe.invalid\n    ProxyCommand none\n    IdentityAgent none\n    KnownHostsCommand " + openSSHProbeKnownHostsCommand() + "\n"
	if err := os.WriteFile(probePath, []byte(probeContent), 0o600); err != nil {
		return OpenSSHCapabilities{}, err
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	probeOutput, probeErr := runOpenSSHProbeEnv(probeCtx, probeEnvironment, resolved, "-G", "-F", probePath, "probe.invalid")
	cancel()
	if probeErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(probeErr, &exitErr) {
			return OpenSSHCapabilities{}, probeErr
		}
		return capabilities, nil
	}
	// A successful -G parse proves that the client accepted every required
	// option in one deterministic invocation. The included User value is a
	// positive signal that Include was actually read rather than merely
	// tolerated. Keep the option checks explicit so a future client that omits
	// an option from -G does not silently report a false capability.
	capabilities.Include = openSSHProbeOutputHasOption(probeOutput, "user", "paperboat-probe-include")
	capabilities.ProxyCommand = true
	capabilities.IdentityAgent = openSSHProbeOutputHasOption(probeOutput, "identityagent", "none")
	capabilities.KnownHostsCommand = true
	return capabilities, nil
}

func runOpenSSHProbe(ctx context.Context, executable string, arguments ...string) (string, error) {
	return runOpenSSHProbeEnv(ctx, nil, executable, arguments...)
}

func runOpenSSHProbeEnv(ctx context.Context, environment []string, executable string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, executable, arguments...)
	if environment != nil {
		command.Env = append([]string(nil), environment...)
	}
	// Windows OpenSSH hangs on -G when stdin is a Go-managed anonymous pipe,
	// even after the empty pipe is closed. An explicit null-device handle keeps
	// the probe non-interactive without inheriting a user's terminal or input.
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		return "", err
	}
	defer stdin.Close()
	command.Stdin = stdin
	output := &limitedBuffer{remaining: 64 << 10}
	command.Stdout, command.Stderr = output, output
	err = runOpenSSHProbeCommand(ctx, command)
	if ctx.Err() != nil {
		return output.String(), context.Cause(ctx)
	}
	return output.String(), err
}

func isolatedOpenSSHProbeEnvironment(directory string) []string {
	values := os.Environ()
	overrides := map[string]string{
		"HOME":            directory,
		"USERPROFILE":     directory,
		"APPDATA":         filepath.Join(directory, "AppData", "Roaming"),
		"LOCALAPPDATA":    filepath.Join(directory, "AppData", "Local"),
		"XDG_CONFIG_HOME": filepath.Join(directory, "config"),
	}
	if runtime.GOOS == "windows" {
		volume := filepath.VolumeName(directory)
		overrides["HOMEDRIVE"] = volume
		overrides["HOMEPATH"] = strings.TrimPrefix(directory, volume)
	}
	result := make([]string, 0, len(values)+len(overrides))
	for _, value := range values {
		name, _, ok := strings.Cut(value, "=")
		if !ok || strings.EqualFold(name, "SSH_AUTH_SOCK") {
			continue
		}
		if _, overridden := overrides[name]; overridden {
			continue
		}
		// Windows environment names are case-insensitive. Do not let a
		// differently cased inherited variable defeat the isolation boundary.
		for key := range overrides {
			if strings.EqualFold(name, key) {
				name = ""
				break
			}
		}
		if name != "" {
			result = append(result, value)
		}
	}
	for _, key := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "HOMEDRIVE", "HOMEPATH"} {
		if value, ok := overrides[key]; ok {
			result = append(result, key+"="+value)
		}
	}
	return result
}

func openSSHProbeOutputHasOption(output, option, expected string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], option) && strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), fields[0])) == expected {
			return true
		}
	}
	return false
}

type limitedBuffer struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	remaining int
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
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

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

var _ io.Writer = (*limitedBuffer)(nil)
