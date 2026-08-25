//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/command"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
	"github.com/pinksaucepasta/paperboat/internal/tunnel"
)

func TestWindowsSSHRemoteCommandMatchesOpenSSHJoinSemantics(t *testing.T) {
	values := []string{"/usr/bin/sh", "-c", "'printf %s VICTUS_PB_SSH_OK'"}
	got, err := windowsSSHRemoteCommand(values)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Join(values, " "); got != want {
		t.Fatalf("command=%q want=%q", got, want)
	}
	for _, invalid := range [][]string{nil, {"bad\x00argument"}} {
		if _, err := windowsSSHRemoteCommand(invalid); err == nil {
			t.Fatalf("invalid command %q accepted", invalid)
		}
	}
}

func TestWindowsSSHCommandInputLeavesTerminalUnowned(t *testing.T) {
	previous := isWindowsSSHCommandTerminal
	isWindowsSSHCommandTerminal = func(int) bool { return true }
	t.Cleanup(func() { isWindowsSSHCommandTerminal = previous })
	file, err := os.CreateTemp(t.TempDir(), "console")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	input, err := windowsSSHCommandInput(file)
	if err != nil || input != nil {
		t.Fatalf("terminal input=%v error=%v", input, err)
	}
}

func TestWindowsSSHCommandInputDuplicateCloseCancelsReadAndPreservesOriginal(t *testing.T) {
	previous := isWindowsSSHCommandTerminal
	isWindowsSSHCommandTerminal = func(int) bool { return false }
	t.Cleanup(func() { isWindowsSSHCommandTerminal = previous })
	original, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	defer writer.Close()
	input, err := windowsSSHCommandInput(original)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	readDone := make(chan error, 1)
	go func() {
		close(started)
		_, readErr := input.Read(make([]byte, 1))
		readDone <- readErr
	}()
	<-started
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("closing owned input did not cancel its blocked read")
	}
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	value := make([]byte, 1)
	if _, err := original.Read(value); err != nil || string(value) != "x" {
		t.Fatalf("original input value=%q error=%v", value, err)
	}
}

func TestWindowsLoopbackOpenSSHArgumentsPreserveManagedIdentityAndHost(t *testing.T) {
	destination := managedssh.Destination{User: "root", Host: "hn.pprbt", Port: 2222}
	got := windowsLoopbackOpenSSHArguments(destination, 49152, `C:\Program Files\Paperboat\pb.exe`, []string{"/usr/bin/printf", "VICTUS_PB_SSH_OK"}, true)
	want := []string{
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "ProxyCommand=none",
		"-o", "Hostname=127.0.0.1",
		"-o", "HostKeyAlias=hn.pprbt",
		"-o", `KnownHostsCommand="C:\Program Files\Paperboat\pb.exe" __ssh-known-hosts --host hn.pprbt --port 2222`,
		"-p", "49152",
		"root@hn.pprbt",
		"/usr/bin/printf", "VICTUS_PB_SSH_OK",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("windowsLoopbackOpenSSHArguments()=%q want %q", got, want)
	}
}

func TestWindowsManagedSSHConnectInfoCarriesEveryExplicitTransport(t *testing.T) {
	machine := api.UserMachine{ID: "machine-hn", EnvironmentID: "environment-hn", InstallationGeneration: 7}
	descriptor := api.SSHDescriptor{Environment: &api.Environment{ID: "environment-hn"}}
	for _, value := range []string{"a", "d", "q", "w", "r"} {
		info, err := windowsManagedSSHConnectInfo(machine, descriptor, value, tunnel.TerminalTransportAuto)
		if err != nil {
			t.Fatalf("transport %q: %v", value, err)
		}
		if info.Transport != value {
			t.Fatalf("transport %q reached DialSSH as %q", value, info.Transport)
		}
	}
	if _, err := windowsManagedSSHConnectInfo(machine, descriptor, "invalid", tunnel.TerminalTransportAuto); err == nil {
		t.Fatal("invalid transport was accepted")
	}
}

func TestWindowsManagedSSHDependenciesRequiresLocalDaemonBeforeDial(t *testing.T) {
	previousBuild, previousRequire := buildWindowsManagedSSHDeps, requireWindowsManagedSSHDaemon
	t.Cleanup(func() {
		buildWindowsManagedSSHDeps, requireWindowsManagedSSHDaemon = previousBuild, previousRequire
	})
	want := errors.New("daemon unavailable")
	cfg := &config.Config{}
	buildWindowsManagedSSHDeps = func(*command.Context) (*deps, error) {
		return &deps{cfg: cfg}, nil
	}
	called := false
	requireWindowsManagedSSHDaemon = func(ctx context.Context, got *config.Config) error {
		called = true
		if ctx == nil || got != cfg {
			t.Fatalf("require daemon context=%v config=%p want=%p", ctx, got, cfg)
		}
		return want
	}
	set := flag.NewFlagSet("ssh", flag.ContinueOnError)
	ctx := command.NewContext(set)
	ctx.Context = context.Background()
	if _, err := windowsManagedSSHDependencies(ctx); !errors.Is(err, want) {
		t.Fatalf("dependencies error=%v", err)
	}
	if !called {
		t.Fatal("local daemon readiness was not required")
	}
}

func TestWindowsLoopbackOpenSSHArgumentsKeepDefaultRegisteredPortSeparateFromLoopback(t *testing.T) {
	destination := managedssh.Destination{User: "root", Host: "hn.pprbt", Port: 22}
	got := windowsLoopbackOpenSSHArguments(destination, 50443, `C:\Program Files\Paperboat\pb.exe`, []string{"must-not-appear"}, false)
	joined := strings.Join(got, "\n")
	for _, required := range []string{
		`KnownHostsCommand="C:\Program Files\Paperboat\pb.exe" __ssh-known-hosts --host hn.pprbt --port 22`,
		"HostKeyAlias=hn.pprbt",
		"ProxyCommand=none",
		"Hostname=127.0.0.1",
		"50443",
		"root@hn.pprbt",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("arguments %q do not contain %q", got, required)
		}
	}
	if strings.Contains(joined, "must-not-appear") {
		t.Fatalf("passthrough appended without --: %q", got)
	}
}
