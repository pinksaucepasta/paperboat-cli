//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/command"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/managedssh"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
	"github.com/pinksaucepasta/paperboat/internal/tunnel"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

var (
	buildWindowsManagedSSHDeps     = buildDeps
	requireWindowsManagedSSHDaemon = requireLocalDaemonService
	isWindowsSSHCommandTerminal    = term.IsTerminal
)

func executeManagedSSH(cobraCommand *cobra.Command, ctx *command.Context, machine api.UserMachine, destination managedssh.Destination, passthrough []string, includePassthrough bool, environment []string) error {
	client, liveMachine, liveTarget, err := resolveSSHCommandTargetLive(ctx, machine.ID)
	if err != nil {
		return friendlyCommandError(err)
	}
	liveDestination, err := managedssh.ResolveDestination(managedssh.DestinationInput{Alias: liveMachine.Alias, AliasSuffix: managedssh.AliasSuffix, RegisteredPort: liveTarget.Port, RequestedUser: destination.User, RegisteredUser: liveTarget.OSUser, HasRegisteredUser: true, Platform: liveMachine.Platform})
	if err != nil {
		return err
	}
	machine, destination = liveMachine, liveDestination
	d, err := windowsManagedSSHDependencies(ctx)
	if err != nil {
		return err
	}
	if d.peerApplications == nil {
		return errors.New("Paperboat peer transport is unavailable")
	}
	var (
		hostKeys      []string
		identity      config.ManagedSSHIdentity
		remoteCommand string
	)
	if includePassthrough {
		remoteCommand, err = windowsSSHRemoteCommand(passthrough)
		if err != nil {
			return invocationError(err)
		}
		active, err := client.ManagedSSHHostKeys(cobraCommand.Context(), machine.ID, uint64(machine.InstallationGeneration))
		if err != nil {
			return friendlyCommandError(err)
		}
		hostKeys = append([]string(nil), active.Keys...)
		store, err := config.ProfileStoreFor(d.cfg)
		if err != nil {
			return err
		}
		profile, err := store.Load(d.cfg.ServerURL)
		if err != nil {
			return err
		}
		identity, err = store.ManagedSSHIdentity(d.cfg.ServerURL, profile.CLIClientSessionID)
		if err != nil {
			return err
		}
	}
	operationID := newSSHOperationID()
	descriptor := pendingSSHDescriptor(machine, operationID)
	requestedTransport, _ := cobraCommand.Flags().GetString("transport")
	connectInfo, err := windowsManagedSSHConnectInfo(machine, descriptor, requestedTransport, d.transportMode)
	if err != nil {
		return invocationError(err)
	}
	connection, err := d.peerApplications.DialSSH(cobraCommand.Context(), connectInfo, operationID)
	if err != nil {
		return err
	}
	if includePassthrough {
		input, err := windowsSSHCommandInput(cobraCommand.InOrStdin())
		if err != nil {
			_ = connection.Close()
			return err
		}
		err = managedssh.RunSSHCommand(cobraCommand.Context(), connection, managedssh.SSHCommandConfig{
			Address: net.JoinHostPort(destination.Host, strconv.Itoa(int(destination.Port))),
			User:    destination.User, Command: remoteCommand, Signer: identity.Signer,
			AuthorizedHostKeys: hostKeys, Input: input,
			Output: cobraCommand.OutOrStdout(), ErrorOutput: cobraCommand.ErrOrStderr(),
		})
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			status := exitErr.ExitStatus()
			if status < 0 || status > 255 {
				status = 255
			}
			return exitCodeError{code: status}
		}
		return err
	}
	stream, ok := connection.(managedssh.LoopbackSSHStream)
	if !ok {
		_ = connection.Close()
		return tunnel.ErrInputEOFUnsupported
	}
	executable, err := os.Executable()
	if err != nil {
		_ = connection.Close()
		return err
	}
	defer connection.Close()
	return (managedssh.LoopbackOpenSSHExecutor{}).Execute(cobraCommand.Context(), "ssh", func(port uint16) []string {
		return windowsLoopbackOpenSSHArguments(destination, port, executable, passthrough, includePassthrough)
	}, environment, stream)
}

func windowsSSHRemoteCommand(values []string) (string, error) {
	if len(values) == 0 || len(values) > 4096 {
		return "", errors.New("SSH command is missing or too large")
	}
	total := len(values) - 1
	for _, value := range values {
		if strings.ContainsRune(value, 0) || len(value) > 1<<20 {
			return "", errors.New("SSH command contains an invalid argument")
		}
		total += len(value)
		if total > 1<<20 {
			return "", errors.New("SSH command is too large")
		}
	}
	return strings.Join(values, " "), nil
}

type windowsSSHOwnedInput struct {
	file *os.File
	once sync.Once
}

func windowsSSHCommandInput(input io.Reader) (io.ReadCloser, error) {
	if input == nil {
		return nil, nil
	}
	file, ok := input.(*os.File)
	if !ok {
		if closer, ok := input.(io.ReadCloser); ok {
			return closer, nil
		}
		return io.NopCloser(input), nil
	}
	if isWindowsSSHCommandTerminal(int(file.Fd())) {
		return nil, nil
	}
	process := windows.CurrentProcess()
	var duplicate windows.Handle
	if err := windows.DuplicateHandle(process, windows.Handle(file.Fd()), process, &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	owned := os.NewFile(uintptr(duplicate), "paperboat-ssh-command-stdin")
	if owned == nil {
		_ = windows.CloseHandle(duplicate)
		return nil, errors.New("duplicate SSH command input")
	}
	return &windowsSSHOwnedInput{file: owned}, nil
}

func (input *windowsSSHOwnedInput) Read(value []byte) (int, error) {
	if input == nil || input.file == nil {
		return 0, os.ErrClosed
	}
	return input.file.Read(value)
}

func (input *windowsSSHOwnedInput) Close() error {
	if input == nil || input.file == nil {
		return nil
	}
	var err error
	input.once.Do(func() {
		_ = windows.CancelIoEx(windows.Handle(input.file.Fd()), nil)
		err = input.file.Close()
	})
	return err
}

func windowsManagedSSHDependencies(ctx *command.Context) (*deps, error) {
	d, err := buildWindowsManagedSSHDeps(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireWindowsManagedSSHDaemon(ctx.Context, d.cfg); err != nil {
		return nil, fmt.Errorf("prepare local peer transport: %w", err)
	}
	return d, nil
}

func windowsManagedSSHConnectInfo(machine api.UserMachine, descriptor api.SSHDescriptor, requested string, fallback tunnel.TerminalTransport) (resolver.ConnectInfo, error) {
	mode := fallback
	if strings.TrimSpace(requested) != "" {
		var err error
		mode, err = tunnel.ParseTerminalTransport(requested)
		if err != nil {
			return resolver.ConnectInfo{}, err
		}
	}
	if mode == "" {
		mode = tunnel.TerminalTransportAuto
	}
	info := sshConnectInfo(machine, descriptor)
	info.Transport = string(mode)
	return info, nil
}

func windowsLoopbackOpenSSHArguments(destination managedssh.Destination, port uint16, executable string, passthrough []string, includePassthrough bool) []string {
	knownHostsCommand := quoteWindowsOpenSSHCommand(executable) + " __ssh-known-hosts --host " + destination.Host + " --port " + strconv.Itoa(int(destination.Port))
	arguments := openSSHSecurityArguments()
	arguments = append(arguments,
		"-o", "ProxyCommand=none",
		"-o", "Hostname=127.0.0.1",
		"-o", "HostKeyAlias="+destination.Host,
		"-o", "KnownHostsCommand="+knownHostsCommand,
		"-p", strconv.Itoa(int(port)),
		destination.User+"@"+destination.Host,
	)
	if includePassthrough {
		arguments = append(arguments, passthrough...)
	}
	return arguments
}

func quoteWindowsOpenSSHCommand(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}
