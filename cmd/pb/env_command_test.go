package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/environmentmanager"
	"github.com/spf13/cobra"
)

func TestEnvironmentVariableCommandSurfaceKeepsValuesOutOfArguments(t *testing.T) {
	root := newRootCommand()
	for _, path := range [][]string{{"env"}, {"env", "list"}, {"env", "set"}, {"env", "unset"}} {
		command, _, err := root.Find(path)
		if err != nil || command == nil {
			t.Fatalf("find %v: command=%v err=%v", path, command, err)
		}
	}
	setCommand, _, _ := root.Find([]string{"env", "set"})
	if setCommand.Flags().Lookup("value") != nil || setCommand.Flags().Lookup("value-stdin") == nil || setCommand.Flags().Lookup("machine") == nil {
		t.Fatalf("set flags expose an unsafe value input: %v", setCommand.Flags().FlagUsages())
	}
	if unsetCommand, _, _ := root.Find([]string{"env", "unset"}); unsetCommand.Flags().Lookup("yes") == nil || unsetCommand.Flags().Lookup("value") != nil {
		t.Fatalf("unset flags are incorrect: %v", unsetCommand.Flags().FlagUsages())
	}
	if listCommand, _, _ := root.Find([]string{"env", "list"}); listCommand.Flags().Lookup("json") == nil || listCommand.Flags().Lookup("machine") == nil {
		t.Fatalf("list flags are incorrect: %v", listCommand.Flags().FlagUsages())
	}
}

func TestEnvironmentVariableStdinIsRawBoundedAndAllowsEmpty(t *testing.T) {
	for _, value := range []string{"", "  canary  \n", strings.Repeat("x", api.MaximumEnvironmentVariableValueBytes)} {
		got, err := readBoundedEnvironmentVariableStdin(strings.NewReader(value))
		if err != nil || !bytes.Equal(got, []byte(value)) {
			t.Fatalf("value length=%d got length=%d err=%v", len(value), len(got), err)
		}
		clear(got)
	}
	if got, err := readBoundedEnvironmentVariableStdin(strings.NewReader(strings.Repeat("x", api.MaximumEnvironmentVariableValueBytes+1))); err == nil || got != nil || !strings.Contains(err.Error(), "32767") {
		t.Fatalf("oversized stdin got length=%d err=%v", len(got), err)
	}
	if got, err := readBoundedEnvironmentVariableStdin(strings.NewReader("prefix\x00suffix")); err == nil || got != nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("NUL stdin got=%q err=%v", got, err)
	}
	if got, err := readBoundedEnvironmentVariableStdin(bytes.NewReader([]byte{0xff})); err == nil || got != nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid UTF-8 stdin got=%q err=%v", got, err)
	}
	if got, err := readBoundedEnvironmentVariableStdin(errorReader{}); err == nil || got != nil || !strings.Contains(err.Error(), "could not read") {
		t.Fatalf("reader error got=%q err=%v", got, err)
	}
}

func TestEnvironmentVariableSetCommandEncryptsLocallyAndClearsInput(t *testing.T) {
	const canary = "command-secret-canary"
	var received, receivedBacking []byte
	mutator := fakeEnvironmentVariableMutator{set: func(_ context.Context, machineID, name string, value []byte) (environmentmanager.MutationResult, error) {
		if machineID != "" || name != "API_MODE" {
			t.Fatalf("target=%q name=%q", machineID, name)
		}
		received = append([]byte(nil), value...)
		receivedBacking = value
		return environmentmanager.MutationResult{Name: name, Version: 7, ManifestID: "sha256:opaque"}, nil
	}}
	previousBackend := environmentVariableBackendForCommand
	previousManager := environmentVariableManagerForCommand
	environmentVariableBackendForCommand = func(*cobra.Command) (*api.Client, error) {
		return api.New("https://api.example.test", config.Credential{AccessToken: "token"}, nil), nil
	}
	environmentVariableManagerForCommand = func(*cobra.Command) (environmentVariableMutator, error) {
		return mutator, nil
	}
	t.Cleanup(func() {
		environmentVariableBackendForCommand = previousBackend
		environmentVariableManagerForCommand = previousManager
	})

	var output bytes.Buffer
	command := newEnvironmentTestCommand(strings.NewReader(canary), &output)
	if err := setEnvironmentVariable(command, "", "API_MODE", true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, []byte(canary)) || !allZero(receivedBacking) || strings.Contains(output.String(), canary) || !strings.Contains(output.String(), "Set API_MODE") || !strings.Contains(output.String(), "encrypted manifest version 7") {
		t.Fatalf("received=%q cleared=%t output=%q", received, allZero(receivedBacking), output.String())
	}
	clear(received)
}

func TestEnvironmentVariableSetCommandHidesServerEcho(t *testing.T) {
	const canary = "command-error-canary"
	if got := safeEnvironmentVariableCommandError(errors.New("server echoed " + canary + "\\nwith escaped details")); got == nil || strings.Contains(got.Error(), canary) || got.Error() != "environment variable update failed" {
		t.Fatalf("unsafe command error=%v", got)
	}
}

func TestEnvironmentVariableSetConflictErrorUsesOnlyStableCode(t *testing.T) {
	const canary = "conflict-secret-canary"
	err := safeEnvironmentVariableCommandError(&api.APIError{Code: "version_conflict", Message: canary, Details: map[string]any{"message": canary}})
	if err == nil || strings.Contains(err.Error(), canary) || err.Error() != "environment variable scope changed; fetch it and retry" {
		t.Fatalf("unsafe conflict error=%v", err)
	}
}

func TestEnvironmentVariableUnsetCommandUsesEncryptedManagerAndYes(t *testing.T) {
	var unsetSeen bool
	mutator := fakeEnvironmentVariableMutator{unset: func(_ context.Context, machineID, name string) (environmentmanager.MutationResult, error) {
		if machineID != "" || name != "API_MODE" {
			t.Fatalf("target=%q name=%q", machineID, name)
		}
		unsetSeen = true
		return environmentmanager.MutationResult{Name: "API_MODE", Version: 6}, nil
	}}
	previousBackend := environmentVariableBackendForCommand
	previousManager := environmentVariableManagerForCommand
	environmentVariableBackendForCommand = func(*cobra.Command) (*api.Client, error) {
		return api.New("https://api.example.test", config.Credential{}, nil), nil
	}
	environmentVariableManagerForCommand = func(*cobra.Command) (environmentVariableMutator, error) {
		return mutator, nil
	}
	t.Cleanup(func() {
		environmentVariableBackendForCommand = previousBackend
		environmentVariableManagerForCommand = previousManager
	})

	var output bytes.Buffer
	if err := unsetEnvironmentVariable(newEnvironmentTestCommand(strings.NewReader(""), &output), "", "API_MODE", true); err != nil {
		t.Fatal(err)
	}
	if !unsetSeen || !strings.Contains(output.String(), "Unset API_MODE") || !strings.Contains(output.String(), "encrypted manifest version 6") {
		t.Fatalf("unsetSeen=%t output=%q", unsetSeen, output.String())
	}
	if err := unsetEnvironmentVariable(newEnvironmentTestCommand(strings.NewReader(""), &bytes.Buffer{}), "", "API_MODE", false); !errors.Is(err, errUsage) {
		t.Fatalf("missing --yes error=%v", err)
	}
}

func TestEnvironmentVariableJSONOutputContainsOnlyRedactedMetadata(t *testing.T) {
	const canary = "json-canary"
	snapshot := api.EnvironmentVariableCollection{Scope: api.EnvironmentVariableScopeGlobal, Version: 2, ETag: `"environment-global-2"`, Variables: []api.EnvironmentVariable{{Scope: api.EnvironmentVariableScopeGlobal, Name: "API_MODE", Configured: true, Version: 2}}}
	var output bytes.Buffer
	if err := writeEnvironmentVariableJSON(&output, snapshot); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), canary) || strings.Contains(output.String(), "value") || !strings.Contains(output.String(), "etag") {
		t.Fatalf("unsafe JSON=%q", output.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil || envelope["ok"] != true {
		t.Fatalf("envelope=%#v err=%v", envelope, err)
	}
}

func TestEnvironmentVariableHostFilteringAndCaseInsensitiveNames(t *testing.T) {
	clientOnly := api.UserMachine{ID: "client", DisplayName: "Client", SetupMode: "client", SetupRoles: []string{"interactive"}}
	hostByMode := api.UserMachine{ID: "host-mode", DisplayName: "Host mode", SetupMode: "host"}
	hostByRole := api.UserMachine{ID: "host-role", DisplayName: "Host role", SetupMode: "client", SetupRoles: []string{"interactive", "HOST"}}
	filtered := environmentVariableMachines([]api.UserMachine{clientOnly, hostByMode, hostByRole})
	if len(filtered) != 2 || filtered[0].ID != hostByMode.ID || filtered[1].ID != hostByRole.ID {
		t.Fatalf("filtered machines=%+v", filtered)
	}
	actions := machineHomeActions(clientOnly)
	for _, action := range actions {
		if action.ID == "environment-variables" {
			t.Fatal("client-only machine exposed ENV Injection action")
		}
	}
	if !environmentVariableConfigured([]api.EnvironmentVariable{{Name: "PATH", Configured: true}}, "path") {
		t.Fatal("case-insensitive environment-variable lookup failed")
	}
}

func TestEnvironmentVariableTargetRejectsClientMachineLocally(t *testing.T) {
	previous := environmentVariableResolveMachine
	environmentVariableResolveMachine = func(context.Context, *api.Client, string) (api.UserMachine, error) {
		return api.UserMachine{ID: "client", DisplayName: "Client", SetupMode: "client"}, nil
	}
	defer func() { environmentVariableResolveMachine = previous }()

	target, err := environmentVariableTargetForCommand(newEnvironmentTestCommand(strings.NewReader(""), io.Discard), nil, "client")
	if err == nil || !strings.Contains(err.Error(), "only for host-capable machines") || target.machineID != "" {
		t.Fatalf("target=%+v err=%v", target, err)
	}
}

func TestEnvironmentVariableGlobalTableDoesNotReportMachineStatus(t *testing.T) {
	var output bytes.Buffer
	snapshot := api.EnvironmentVariableCollection{Scope: api.EnvironmentVariableScopeGlobal, Version: 2, Variables: []api.EnvironmentVariable{{Scope: api.EnvironmentVariableScopeGlobal, Name: "API_MODE", Configured: true, Version: 2}}}
	if err := writeEnvironmentVariableTable(&output, snapshot, environmentVariableTarget{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "not reported") || !strings.Contains(output.String(), "STATUS  -") {
		t.Fatalf("global table=%q", output.String())
	}
}

func newEnvironmentTestCommand(input io.Reader, output io.Writer) *cobra.Command {
	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.SetIn(input)
	command.SetOut(output)
	command.SetErr(io.Discard)
	return command
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

type fakeEnvironmentVariableMutator struct {
	set   func(context.Context, string, string, []byte) (environmentmanager.MutationResult, error)
	unset func(context.Context, string, string) (environmentmanager.MutationResult, error)
}

func (fake fakeEnvironmentVariableMutator) Set(ctx context.Context, machineID, name string, value []byte) (environmentmanager.MutationResult, error) {
	if fake.set == nil {
		return environmentmanager.MutationResult{}, errors.New("unexpected set")
	}
	return fake.set(ctx, machineID, name, value)
}

func (fake fakeEnvironmentVariableMutator) Unset(ctx context.Context, machineID, name string) (environmentmanager.MutationResult, error) {
	if fake.unset == nil {
		return environmentmanager.MutationResult{}, errors.New("unexpected unset")
	}
	return fake.unset(ctx, machineID, name)
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
