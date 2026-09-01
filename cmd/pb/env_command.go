package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/environmentmanager"
	"github.com/pinksaucepasta/paperboat/internal/prompt"
	"github.com/pinksaucepasta/paperboat/internal/selector"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const environmentVariableScopeGlobal = "global"

type environmentVariableTarget struct {
	machineID   string
	machineName string
}

var environmentVariableBackendForCommand = backendForCommand
var environmentVariableResolveMachine = resolveUserMachine
var environmentVariableManagerForCommand = defaultEnvironmentVariableManagerForCommand

type environmentVariableMutator interface {
	Set(context.Context, string, string, []byte) (environmentmanager.MutationResult, error)
	Unset(context.Context, string, string) (environmentmanager.MutationResult, error)
}

func defaultEnvironmentVariableManagerForCommand(command *cobra.Command) (environmentVariableMutator, error) {
	client, store, profile, err := e2eeClient(actionContext(command, nil))
	if err != nil {
		return nil, err
	}
	if err := store.RequireEnvironmentSecureStore(); err != nil {
		return nil, err
	}
	return environmentmanager.Manager{
		Client:    client,
		Store:     store,
		Issuer:    profile.Issuer,
		AccountID: profile.Account.ID,
		SubjectID: profile.CLIClientSessionID,
	}, nil
}

func environmentVariablesCobraCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "env",
		Short: "Manage ENV Injection for connected hosts",
		Args:  commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			if !environmentVariableTerminal(command) {
				return command.Help()
			}
			return runEnvironmentVariablesTUI(command)
		},
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List configured environment-variable metadata",
		Args:  commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			machine, _ := command.Flags().GetString("machine")
			jsonOutput, _ := command.Flags().GetBool("json")
			return listEnvironmentVariables(command, machine, jsonOutput)
		},
	}
	list.Flags().String("machine", "", "machine name or ID; defaults to the global scope")
	list.Flags().Bool("json", false, "print redacted JSON metadata")

	set := &cobra.Command{
		Use:   "set <name>",
		Short: "Set one environment variable through a hidden prompt or bounded stdin",
		Args:  commandArgs(cobra.ExactArgs(1)),
		RunE: func(command *cobra.Command, args []string) error {
			machine, _ := command.Flags().GetString("machine")
			valueStdin, _ := command.Flags().GetBool("value-stdin")
			return setEnvironmentVariable(command, machine, args[0], valueStdin)
		},
	}
	set.Flags().String("machine", "", "machine name or ID; defaults to the global scope")
	set.Flags().Bool("value-stdin", false, "read the raw value from non-interactive stdin")

	unset := &cobra.Command{
		Use:   "unset <name>",
		Short: "Remove one environment variable",
		Args:  commandArgs(cobra.ExactArgs(1)),
		RunE: func(command *cobra.Command, args []string) error {
			machine, _ := command.Flags().GetString("machine")
			yes, _ := command.Flags().GetBool("yes")
			return unsetEnvironmentVariable(command, machine, args[0], yes)
		},
	}
	unset.Flags().String("machine", "", "machine name or ID; defaults to the global scope")
	unset.Flags().Bool("yes", false, "confirm removal")

	root.AddCommand(list, set, unset)
	addEnvironmentControlCommands(root)
	return root
}

func environmentVariableTerminal(command *cobra.Command) bool {
	if input, ok := command.InOrStdin().(*os.File); ok && input != nil {
		return term.IsTerminal(int(input.Fd()))
	}
	return false
}

func environmentVariableTargetForCommand(command *cobra.Command, client *api.Client, requested string) (environmentVariableTarget, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return environmentVariableTarget{}, nil
	}
	machine, err := environmentVariableResolveMachine(command.Context(), client, requested)
	if err != nil {
		return environmentVariableTarget{}, friendlyCommandError(err)
	}
	if !machineSupportsEnvironmentInjection(machine) {
		return environmentVariableTarget{}, errors.New("ENV Injection is available only for host-capable machines")
	}
	return environmentVariableTarget{machineID: machine.ID, machineName: machine.DisplayName}, nil
}

func machineSupportsEnvironmentInjection(machine api.UserMachine) bool {
	if strings.EqualFold(strings.TrimSpace(machine.SetupMode), "host") {
		return true
	}
	for _, role := range machine.SetupRoles {
		if strings.EqualFold(strings.TrimSpace(role), "host") {
			return true
		}
	}
	return false
}

func environmentVariableMachines(machines []api.UserMachine) []api.UserMachine {
	filtered := make([]api.UserMachine, 0, len(machines))
	for _, machine := range machines {
		if machineSupportsEnvironmentInjection(machine) {
			filtered = append(filtered, machine)
		}
	}
	return filtered
}

func listEnvironmentVariables(command *cobra.Command, requestedMachine string, jsonOutput bool) error {
	client, err := environmentVariableBackendForCommand(command)
	if err != nil {
		return err
	}
	target, err := environmentVariableTargetForCommand(command, client, requestedMachine)
	if err != nil {
		return err
	}
	snapshot, err := client.ListEnvironmentVariables(command.Context(), target.machineID)
	if err != nil {
		return friendlyCommandError(err)
	}
	if jsonOutput {
		return writeEnvironmentVariableJSON(command.OutOrStdout(), snapshot)
	}
	return writeEnvironmentVariableTable(command.OutOrStdout(), snapshot, target)
}

func writeEnvironmentVariableTable(output io.Writer, snapshot api.EnvironmentVariableCollection, target environmentVariableTarget) error {
	scope := environmentVariableScopeLabel(target)
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintf(writer, "SCOPE\t%s\tVERSION\t%d\tSTATUS\t%s\n", scope, snapshot.Version, environmentVariableStatusForScope(snapshot)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "NAME\tCONFIGURED\tVERSION\tSTATUS\tUPDATED"); err != nil {
		return err
	}
	for _, item := range snapshot.Variables {
		status := environmentVariableStatusForScope(snapshot)
		updated := "-"
		if !item.UpdatedAt.IsZero() {
			updated = item.UpdatedAt.Local().Format(time.RFC3339)
		}
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%d\t%s\t%s\n", item.Name, yesNo(item.Configured), item.Version, status, updated); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func writeEnvironmentVariableJSON(output io.Writer, snapshot api.EnvironmentVariableCollection) error {
	// Keep the transport ETag visible to automation while the metadata type
	// itself remains impossible to serialize with a value field.
	result := struct {
		Scope                 api.EnvironmentVariableScope `json:"scope"`
		MachineID             string                       `json:"machine_id,omitempty"`
		ScopeState            string                       `json:"scope_state,omitempty"`
		KeyState              string                       `json:"key_state"`
		Version               int64                        `json:"version"`
		KeyEpoch              int64                        `json:"key_epoch,omitempty"`
		ManifestID            string                       `json:"manifest_id,omitempty"`
		Variables             []api.EnvironmentVariable    `json:"variables"`
		ETag                  string                       `json:"etag"`
		Status                string                       `json:"status,omitempty"`
		AppliedGlobalVersion  *int64                       `json:"applied_global_version,omitempty"`
		AppliedMachineVersion *int64                       `json:"applied_machine_version,omitempty"`
		AppliedState          string                       `json:"applied_state,omitempty"`
		ErrorCode             string                       `json:"error_code,omitempty"`
		ObservedAt            *time.Time                   `json:"observed_at,omitempty"`
	}{
		Scope: snapshot.Scope, MachineID: snapshot.MachineID, ScopeState: snapshot.ScopeState, KeyState: snapshot.KeyState,
		Version: snapshot.Version, KeyEpoch: snapshot.KeyEpoch, ManifestID: snapshot.ManifestID,
		Variables: snapshot.Variables, ETag: snapshot.ETag, Status: snapshot.Status,
		AppliedGlobalVersion: snapshot.AppliedGlobalVersion, AppliedMachineVersion: snapshot.AppliedMachineVersion,
		AppliedState: snapshot.AppliedState,
		ErrorCode:    snapshot.ErrorCode, ObservedAt: snapshot.ObservedAt,
	}
	return json.NewEncoder(output).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": result})
}

func setEnvironmentVariable(command *cobra.Command, requestedMachine, name string, valueStdin bool) error {
	if err := validateEnvironmentVariableNameForCLI(name); err != nil {
		return invocationError(err)
	}
	client, err := environmentVariableBackendForCommand(command)
	if err != nil {
		return err
	}
	target, err := environmentVariableTargetForCommand(command, client, requestedMachine)
	if err != nil {
		return err
	}
	manager, err := environmentVariableManagerForCommand(command)
	if err != nil {
		return safeEnvironmentVariableCommandError(err)
	}
	value, err := readEnvironmentVariableValue(command, valueStdin)
	if err != nil {
		return err
	}
	defer clear(value)
	result, err := manager.Set(command.Context(), target.machineID, name, value)
	if err != nil {
		return safeEnvironmentVariableCommandError(err)
	}
	_, err = fmt.Fprintf(command.OutOrStdout(), "Set %s on %s (encrypted manifest version %d, pending).\n", result.Name, environmentVariableScopeLabel(target), result.Version)
	return err
}

func unsetEnvironmentVariable(command *cobra.Command, requestedMachine, name string, yes bool) error {
	if !yes {
		return invocationError(errors.New("environment variable removal requires --yes"))
	}
	if err := validateEnvironmentVariableNameForCLI(name); err != nil {
		return invocationError(err)
	}
	client, err := environmentVariableBackendForCommand(command)
	if err != nil {
		return err
	}
	target, err := environmentVariableTargetForCommand(command, client, requestedMachine)
	if err != nil {
		return err
	}
	manager, err := environmentVariableManagerForCommand(command)
	if err != nil {
		return safeEnvironmentVariableCommandError(err)
	}
	result, err := manager.Unset(command.Context(), target.machineID, name)
	if err != nil {
		return safeEnvironmentVariableCommandError(err)
	}
	_, err = fmt.Fprintf(command.OutOrStdout(), "Unset %s from %s (encrypted manifest version %d, pending).\n", result.Name, environmentVariableScopeLabel(target), result.Version)
	return err
}

func readEnvironmentVariableValue(command *cobra.Command, valueStdin bool) ([]byte, error) {
	input := command.InOrStdin()
	isTTY := environmentVariableTerminal(command)
	if valueStdin {
		if isTTY {
			return nil, errors.New("--value-stdin is only available when stdin is not a terminal")
		}
		return readBoundedEnvironmentVariableStdin(input)
	}
	if !isTTY {
		return nil, errors.New("set requires --value-stdin when stdin is not a terminal")
	}
	file, ok := input.(*os.File)
	if !ok || file == nil {
		return nil, errors.New("set requires an interactive terminal for hidden input")
	}
	return prompt.Secret(prompt.SecretOptions{
		Title:       "Set ENV Injection variable",
		Description: "Value is hidden and can be empty",
		Placeholder: "value",
		Stdin:       file,
		Output:      command.ErrOrStderr(),
		MaxBytes:    api.MaximumEnvironmentVariableValueBytes,
	})
}

func readBoundedEnvironmentVariableStdin(input io.Reader) ([]byte, error) {
	value, err := io.ReadAll(io.LimitReader(input, api.MaximumEnvironmentVariableValueBytes+1))
	if err != nil {
		clear(value)
		return nil, errors.New("could not read environment variable value")
	}
	if len(value) > api.MaximumEnvironmentVariableValueBytes {
		clear(value)
		return nil, errors.New("environment variable value exceeds 32767 bytes")
	}
	if bytes.IndexByte(value, 0) >= 0 {
		clear(value)
		return nil, errors.New("environment variable value contains NUL")
	}
	if !utf8.Valid(value) {
		clear(value)
		return nil, errors.New("environment variable value must be valid UTF-8")
	}
	return value, nil
}

func safeEnvironmentVariableCommandError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, environmentmanager.ErrKeyAuthorizationRequired):
		return errors.New("ENV key authorization required; enroll this client with an existing trusted manager")
	case errors.Is(err, environmentmanager.ErrRecoveryExportRequired):
		return errors.New("export and confirm the ENV recovery key before changing variables")
	case errors.Is(err, environmentmanager.ErrVariableNotConfigured):
		return errors.New("environment variable is not configured")
	case errors.Is(err, environmentmanager.ErrPendingMutationReconciled):
		return errors.New("a previous uncertain encrypted ENV update was reconciled; rerun this command")
	case errors.Is(err, environmentmanager.ErrPendingMutationSuperseded):
		return errors.New("a previous uncertain encrypted ENV update was superseded; fetch the scope and retry")
	case errors.Is(err, environmentmanager.ErrAuthorityFork), errors.Is(err, environmentmanager.ErrIntegrity):
		return errors.New("encrypted ENV authority or manifest verification failed; no change was sent")
	}
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		// API mutations sanitize the server response before it reaches this
		// helper. Keep conflict recovery useful, but derive the text only from
		// the stable code so arbitrary server details can never be printed.
		switch apiErr.Code {
		case "version_conflict", "precondition_failed", "authority_conflict":
			return errors.New("environment variable scope changed; fetch it and retry")
		case "key_authorization_required":
			return errors.New("ENV key authorization required; approve this client or host from a trusted manager")
		case "transition_in_progress":
			return errors.New("an ENV key rotation is in progress; finish or abort it before retrying")
		}
	}
	// A submitted value must not be retained in arbitrary transport or server
	// error text, even if it was escaped or embedded in structured details.
	return errors.New("environment variable update failed")
}

func environmentVariableScopeLabel(target environmentVariableTarget) string {
	if target.machineID == "" {
		return environmentVariableScopeGlobal
	}
	if target.machineName == "" {
		return target.machineID
	}
	return target.machineName + " (" + target.machineID + ")"
}

func environmentVariableStatus(status string) string {
	if strings.TrimSpace(status) == "" {
		return "-"
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "pending", "applied", "offline", "failed":
		return strings.ToLower(strings.TrimSpace(status))
	default:
		return "unknown"
	}
}

func environmentVariableStatusForScope(snapshot api.EnvironmentVariableCollection) string {
	return environmentVariableStatus(snapshot.Status)
}

func environmentVariableConfigured(items []api.EnvironmentVariable, name string) bool {
	_, ok := environmentVariableConfiguredName(items, name)
	return ok
}

func environmentVariableConfiguredName(items []api.EnvironmentVariable, name string) (string, bool) {
	for _, item := range items {
		if strings.EqualFold(item.Name, name) && item.Configured {
			return item.Name, true
		}
	}
	return "", false
}

func runEnvironmentVariablesTUI(command *cobra.Command) error {
	client, err := environmentVariableBackendForCommand(command)
	if err != nil {
		return err
	}
	endScreen := selector.BeginScreen(command.ErrOrStderr())
	defer endScreen()
	machines, err := client.ListUserMachines(command.Context())
	if err != nil {
		return friendlyCommandError(err)
	}
	items := []selector.Item{{ID: "global", Title: "Global", Description: "Applied to every connected host machine", Search: "account all host machines"}}
	for _, machine := range environmentVariableMachines(machines) {
		items = append(items, selector.Item{ID: machine.ID, Title: machine.DisplayName, Description: machineStatusSummary(machine), Search: machine.ID + " " + machine.DisplayName})
	}
	for {
		selection, selectErr := selector.Choose(selector.Options{
			Title:    "ENV Injection",
			Subtitle: "Choose a scope",
			Items:    items,
			Empty:    "No machine scopes are available",
			Footer:   "↑/↓ move  type to filter  enter open  esc exit",
			Stdin:    os.Stdin,
			Output:   command.ErrOrStderr(),
		})
		if selectErr != nil {
			return selectErr
		}
		target := environmentVariableTarget{}
		if selection.ID != "global" {
			for _, machine := range machines {
				if machine.ID == selection.ID {
					target = environmentVariableTarget{machineID: machine.ID, machineName: machine.DisplayName}
					break
				}
			}
		}
		if err := runEnvironmentVariableScopeTUI(command, client, target); err != nil && !errors.Is(err, selector.ErrCanceled) {
			return err
		}
	}
}

func runEnvironmentVariableScopeTUI(command *cobra.Command, client *api.Client, target environmentVariableTarget) error {
	var manager environmentVariableMutator
	managerForMutation := func() (environmentVariableMutator, error) {
		if manager != nil {
			return manager, nil
		}
		resolved, err := environmentVariableManagerForCommand(command)
		if err != nil {
			return nil, safeEnvironmentVariableCommandError(err)
		}
		manager = resolved
		return manager, nil
	}
	for {
		snapshot, err := client.ListEnvironmentVariables(command.Context(), target.machineID)
		if err != nil {
			return friendlyCommandError(err)
		}
		items := []selector.Item{{ID: "set", Title: "Set variable", Description: "Add or replace a variable with hidden input", Search: "add update"}}
		for _, variable := range snapshot.Variables {
			items = append(items, selector.Item{ID: "unset:" + variable.Name, Title: variable.Name, Description: "configured  ·  version " + fmt.Sprint(variable.Version) + "  ·  " + environmentVariableStatus(snapshot.Status), Search: variable.Name + " remove unset"})
		}
		selection, selectErr := selector.Choose(selector.Options{
			Title:    "ENV Injection",
			Subtitle: environmentVariableScopeLabel(target) + "  ·  scope version " + fmt.Sprint(snapshot.Version),
			Items:    items,
			Empty:    "No variables configured",
			Footer:   "↑/↓ move  enter select  esc back",
			Stdin:    os.Stdin,
			Output:   command.ErrOrStderr(),
		})
		if selectErr != nil {
			return selectErr
		}
		if selection.ID == "set" {
			manager, managerErr := managerForMutation()
			if managerErr != nil {
				return managerErr
			}
			name, promptErr := prompt.Text(prompt.TextOptions{
				Title:       "Variable name",
				Description: "Letters, numbers, and underscores; values stay hidden",
				Placeholder: "NAME",
				Stdin:       os.Stdin,
				Output:      command.ErrOrStderr(),
				Validate: func(value string) error {
					return validateEnvironmentVariableNameForCLI(value)
				},
			})
			if errors.Is(promptErr, prompt.ErrCanceled) {
				continue
			}
			if promptErr != nil {
				return promptErr
			}
			value, valueErr := prompt.Secret(prompt.SecretOptions{Title: "Variable value", Description: "The value is hidden; press Enter to store an empty value", Stdin: os.Stdin, Output: command.ErrOrStderr(), MaxBytes: api.MaximumEnvironmentVariableValueBytes})
			if errors.Is(valueErr, prompt.ErrCanceled) {
				continue
			}
			if valueErr != nil {
				return valueErr
			}
			result, setErr := manager.Set(command.Context(), target.machineID, name, value)
			clear(value)
			if setErr != nil {
				return safeEnvironmentVariableCommandError(setErr)
			}
			_, _ = fmt.Fprintf(command.ErrOrStderr(), "Set %s on %s (encrypted manifest version %d, pending).\n", result.Name, environmentVariableScopeLabel(target), result.Version)
			continue
		}
		name := strings.TrimPrefix(selection.ID, "unset:")
		confirmed, confirmErr := prompt.Confirm(prompt.ConfirmOptions{Title: "Unset " + name + "?", Description: "New processes on this scope will no longer receive it.", Stdin: os.Stdin, Output: command.ErrOrStderr()})
		if errors.Is(confirmErr, prompt.ErrCanceled) || confirmErr != nil {
			if confirmErr != nil && !errors.Is(confirmErr, prompt.ErrCanceled) {
				return confirmErr
			}
			continue
		}
		if !confirmed {
			continue
		}
		manager, managerErr := managerForMutation()
		if managerErr != nil {
			return managerErr
		}
		result, deleteErr := manager.Unset(command.Context(), target.machineID, name)
		if deleteErr != nil {
			return safeEnvironmentVariableCommandError(deleteErr)
		}
		_, _ = fmt.Fprintf(command.ErrOrStderr(), "Unset %s from %s (encrypted manifest version %d, pending).\n", result.Name, environmentVariableScopeLabel(target), result.Version)
	}
}

func validateEnvironmentVariableNameForCLI(name string) error {
	if name == "" || len(name) > api.MaximumEnvironmentVariableNameBytes {
		return errors.New("environment variable name must be 1-128 characters")
	}
	for index, char := range name {
		if index == 0 && (char < 'A' || char > 'Z') && (char < 'a' || char > 'z') && char != '_' {
			return errors.New("environment variable name must start with a letter or underscore")
		}
		if (char < 'A' || char > 'Z') && (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '_' {
			return errors.New("environment variable name may contain only letters, numbers, and underscores")
		}
	}
	upperName := strings.ToUpper(name)
	if strings.HasPrefix(upperName, "PAPERBOAT_") || strings.HasPrefix(upperName, "LD_") || strings.HasPrefix(upperName, "DYLD_") || upperName == "NODE_OPTIONS" || upperName == "PYTHONPATH" || upperName == "PYTHONHOME" || upperName == "GOTRACEBACK" {
		return errors.New("environment variable name is reserved")
	}
	return nil
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
