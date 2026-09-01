package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/environmente2ee"
	"github.com/pinksaucepasta/paperboat/internal/environmentmanager"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/endpointidentity"
	"github.com/spf13/cobra"
)

type environmentControlManager interface {
	BeginManagerEnrollment(context.Context, []byte, int64, bool, time.Time) (environmentmanager.EnrollmentResult, error)
	ResumeManagerEnrollment(context.Context, time.Time) (environmentmanager.EnrollmentResult, error)
	CancelManagerEnrollment() error
	ConfirmRecoveryExport([]byte) error
	BeginRecoveryPreparation([]byte) (environmentmanager.RecoveryPreparation, error)
	ResumeRecoveryPreparation() (environmentmanager.RecoveryPreparation, error)
	ConfirmRecoveryPreparationExport([]byte) error
	CancelRecoveryPreparation() error
	RecoverAndRotate(context.Context, environmentmanager.RecoveryRotationRequest) (environmentmanager.TransitionResult, error)
	ListVerifiedPendingEnrollments(context.Context, time.Time) ([]environmentmanager.VerifiedPendingEnrollment, error)
	ApproveEnrollment(context.Context, string, string, time.Time) (environmentmanager.TransitionResult, error)
	ApplyAuthorityChange(context.Context, environmentmanager.AuthorityChange) (environmentmanager.TransitionResult, error)
	AbortAuthorityTransition(context.Context, string) (environmentmanager.TransitionResult, error)
	ResumeAuthorityTransition(context.Context) (environmentmanager.TransitionResult, error)
}

// Keep reset operations in a separate capability interface so callers that
// only implement the stable enrollment surface do not accidentally gain a
// destructive operation. The concrete manager implements every method.
type environmentDestructiveResetManager interface {
	BeginDestructiveResetPreparation() (environmentmanager.DestructiveResetPreparation, error)
	ResumeDestructiveResetPreparation() (environmentmanager.DestructiveResetPreparation, error)
	ConfirmDestructiveResetExport([]byte) error
	CancelDestructiveResetPreparation() error
	StartDestructiveReset(context.Context, []byte, int64, api.EnvironmentScopeInventory, string, time.Time) (environmentmanager.TransitionResult, error)
}

type environmentControlDependencies struct {
	client            *api.Client
	manager           environmentControlManager
	accountID         string
	certificate       []byte
	subjectGeneration int64
}

func (dependencies *environmentControlDependencies) clear() {
	if dependencies == nil {
		return
	}
	clear(dependencies.certificate)
	dependencies.certificate = nil
}

var environmentControlDependenciesForCommand = defaultEnvironmentControlDependenciesForCommand

func defaultEnvironmentControlDependenciesForCommand(command *cobra.Command) (environmentControlDependencies, error) {
	client, store, profile, err := e2eeClient(actionContext(command, nil))
	if err != nil {
		return environmentControlDependencies{}, err
	}
	if err := store.RequireEnvironmentSecureStore(); err != nil {
		return environmentControlDependencies{}, err
	}
	state, err := store.LoadPeerCertificate(profile.Issuer, profile.CLIClientSessionID)
	if err != nil {
		return environmentControlDependencies{}, fmt.Errorf("load enrolled CLI identity: %w", err)
	}
	root, err := environmentAccountRootPublic(store, profile)
	if err != nil {
		clear(state.Raw)
		return environmentControlDependencies{}, err
	}
	defer clear(root)
	certificate, err := endpointidentity.Verify(state.Raw, root, endpointidentity.Expected{
		AccountID: profile.Account.ID, Role: endpointidentity.RoleCLI,
		EndpointID: profile.CLIClientSessionID,
	}, time.Now().UTC())
	if err != nil {
		clear(state.Raw)
		return environmentControlDependencies{}, errors.New("the enrolled CLI identity is invalid or expired; sign in again")
	}
	manager := environmentmanager.Manager{
		Client: client, Store: store, Issuer: profile.Issuer,
		AccountID: profile.Account.ID, SubjectID: profile.CLIClientSessionID,
	}
	return environmentControlDependencies{client: client, manager: manager, accountID: profile.Account.ID, certificate: state.Raw, subjectGeneration: int64(certificate.Claims.Generation)}, nil
}

func environmentAccountRootPublic(store config.ProfileStore, profile config.Profile) (ed25519.PublicKey, error) {
	public, err := store.LoadPeerAccountRootPublic(profile.Issuer, profile.Account.ID)
	if err == nil {
		return public, nil
	}
	if !errors.Is(err, config.ErrSecretNotFound) {
		return nil, err
	}
	seed, err := store.ExportPeerAccountRootSeed(profile.Issuer, profile.Account.ID)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("the local account root is invalid")
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	return append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...), nil
}

func addEnvironmentControlCommands(root *cobra.Command) {
	initialize := &cobra.Command{
		Use:   "init",
		Short: "Initialize end-to-end encrypted ENV authority",
		Args:  commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			output, _ := command.Flags().GetString("recovery-output")
			return initializeEnvironmentAuthority(command, output)
		},
	}
	initialize.Flags().String("recovery-output", "", "absolute path for the one-time offline ENV recovery key")

	enroll := &cobra.Command{
		Use:   "enroll",
		Short: "Request authorization for this CLI's dedicated ENV keys",
		Args:  commandArgs(cobra.NoArgs),
		RunE:  func(command *cobra.Command, _ []string) error { return beginEnvironmentManagerEnrollment(command) },
	}
	enrollment := &cobra.Command{Use: "enrollment", Short: "Manage this CLI's pending ENV key enrollment", Args: commandArgs(cobra.NoArgs)}
	cancelEnrollment := &cobra.Command{
		Use:   "cancel",
		Short: "Cancel this CLI's pending ENV key enrollment",
		Args:  commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			yes, _ := command.Flags().GetBool("yes")
			return cancelEnvironmentManagerEnrollment(command, yes)
		},
	}
	cancelEnrollment.Flags().Bool("yes", false, "confirm removal of this CLI's pending enrollment request")
	enrollment.AddCommand(cancelEnrollment)

	pending := &cobra.Command{
		Use:   "pending",
		Short: "List independently verified pending ENV key requests",
		Args:  commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			jsonOutput, _ := command.Flags().GetBool("json")
			return listPendingEnvironmentEnrollments(command, jsonOutput)
		},
	}
	pending.Flags().Bool("json", false, "print redacted JSON metadata")

	approve := &cobra.Command{
		Use:   "approve <request-id>",
		Short: "Authorize verified CLI, browser, or host ENV keys",
		Args:  commandArgs(cobra.ExactArgs(1)),
		RunE: func(command *cobra.Command, args []string) error {
			code, _ := command.Flags().GetString("code")
			return approveEnvironmentEnrollment(command, args[0], code)
		},
	}
	approve.Flags().String("code", "", "16-character safety code shown by the requester")

	revokeHost := &cobra.Command{
		Use:   "revoke-host <machine>",
		Short: "Revoke a host and rotate every ENV key it could decrypt",
		Args:  commandArgs(cobra.ExactArgs(1)),
		RunE: func(command *cobra.Command, args []string) error {
			yes, _ := command.Flags().GetBool("yes")
			return revokeEnvironmentSubject(command, environmente2ee.SubjectHost, args[0], yes)
		},
	}
	revokeHost.Flags().Bool("yes", false, "confirm revocation and required key rotation")

	revokeManager := &cobra.Command{
		Use:   "revoke-manager <manager-id>",
		Short: "Revoke a manager and rotate every ENV scope key",
		Args:  commandArgs(cobra.ExactArgs(1)),
		RunE: func(command *cobra.Command, args []string) error {
			yes, _ := command.Flags().GetBool("yes")
			kind, _ := command.Flags().GetString("kind")
			managerKind, err := parseEnvironmentManagerKind(kind)
			if err != nil {
				return err
			}
			return revokeEnvironmentSubject(command, managerKind, args[0], yes)
		},
	}
	revokeManager.Flags().String("kind", "", "manager kind: cli or browser")
	revokeManager.Flags().Bool("yes", false, "confirm revocation and full key rotation")

	rotate := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate one ENV scope key and re-encrypt its current values",
		Args:  commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			machine, _ := command.Flags().GetString("machine")
			yes, _ := command.Flags().GetBool("yes")
			return rotateEnvironmentScope(command, machine, yes)
		},
	}
	rotate.Flags().String("machine", "", "machine name or ID; defaults to the global scope")
	rotate.Flags().Bool("yes", false, "confirm scope-key rotation")

	reset := &cobra.Command{
		Use:   "reset <account_id>",
		Short: "Replace every ENV manager and recovery key and delete all values",
		Args:  commandArgs(cobra.ExactArgs(1)),
		RunE: func(command *cobra.Command, args []string) error {
			recoveryOutput, _ := command.Flags().GetString("recovery-output")
			confirmation, _ := command.Flags().GetString("confirm-reset")
			return resetEnvironmentAuthority(command, args[0], recoveryOutput, confirmation)
		},
	}
	reset.Flags().String("recovery-output", "", "absolute path for the fresh offline ENV recovery key")
	reset.Flags().String("confirm-reset", "", "exact confirmation phrase: RESET ENV <account_id>")
	resetCancel := &cobra.Command{
		Use:   "cancel <account_id>",
		Short: "Cancel an uncommitted local ENV reset preparation",
		Args:  commandArgs(cobra.ExactArgs(1)),
		RunE: func(command *cobra.Command, args []string) error {
			confirmation, _ := command.Flags().GetString("confirm-cancel")
			return cancelDestructiveReset(command, args[0], confirmation)
		},
	}
	resetCancel.Flags().String("confirm-cancel", "", "exact confirmation phrase: CANCEL ENV RESET <account_id>")
	reset.AddCommand(resetCancel)

	abort := &cobra.Command{
		Use:   "abort <transition-id>",
		Short: "Root-authorize aborting one incomplete ENV transition",
		Args:  commandArgs(cobra.ExactArgs(1)),
		RunE: func(command *cobra.Command, args []string) error {
			yes, _ := command.Flags().GetBool("yes")
			return abortEnvironmentTransition(command, args[0], yes)
		},
	}
	abort.Flags().Bool("yes", false, "confirm transition abort")

	resume := &cobra.Command{
		Use:   "resume",
		Short: "Resume the exact persisted ENV authority transition",
		Args:  commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			return resumeEnvironmentTransition(command)
		},
	}

	recovery := &cobra.Command{Use: "recovery", Short: "Manage the offline ENV recovery key", Args: commandArgs(cobra.NoArgs)}
	confirmRecovery := &cobra.Command{
		Use:   "confirm",
		Short: "Confirm that the initial ENV recovery key was stored offline",
		Args:  commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			input, _ := command.Flags().GetString("recovery-key")
			return confirmEnvironmentRecoveryFile(command, input)
		},
	}
	confirmRecovery.Flags().String("recovery-key", "", "absolute path to the owner-only ENV recovery-key file")
	recoverEnvironment := &cobra.Command{
		Use:   "recover",
		Short: "Recover ENV access and atomically rotate every scope key",
		Args:  commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			input, _ := command.Flags().GetString("recovery-key")
			output, _ := command.Flags().GetString("replacement-output")
			return recoverEnvironmentAuthority(command, input, output)
		},
	}
	recoverEnvironment.Flags().String("recovery-key", "", "absolute existing recovery-key path; omit only when resuming a prepared recovery")
	recoverEnvironment.Flags().String("replacement-output", "", "absolute path for the new one-time offline ENV recovery key")
	cancelRecovery := &cobra.Command{
		Use:   "cancel",
		Short: "Erase a pending local ENV recovery import and replacement",
		Args:  commandArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			yes, _ := command.Flags().GetBool("yes")
			return cancelEnvironmentRecovery(command, yes)
		},
	}
	cancelRecovery.Flags().Bool("yes", false, "confirm removal of the pending local recovery preparation")
	recovery.AddCommand(confirmRecovery, recoverEnvironment, cancelRecovery)

	root.AddCommand(initialize, enroll, enrollment, pending, approve, revokeHost, revokeManager, rotate, reset, abort, resume, recovery)
}

func initializeEnvironmentAuthority(command *cobra.Command, recoveryOutput string) error {
	recoveryOutput = strings.TrimSpace(recoveryOutput)
	if recoveryOutput == "" || !filepath.IsAbs(recoveryOutput) {
		return invocationError(errors.New("env init requires an absolute --recovery-output path"))
	}
	dependencies, err := environmentControlDependenciesForCommand(command)
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	defer dependencies.clear()
	now := time.Now().UTC()
	result, resumeErr := dependencies.manager.ResumeManagerEnrollment(command.Context(), now)
	if resumeErr != nil && !errors.Is(resumeErr, environmentmanager.ErrNoPendingEnrollment) {
		return safeEnvironmentControlError(resumeErr)
	}
	if errors.Is(resumeErr, environmentmanager.ErrNoPendingEnrollment) {
		if _, authorityErr := dependencies.client.GetEnvironmentAuthority(command.Context()); authorityErr == nil {
			return errors.New("ENV authority is already initialized")
		} else {
			var apiErr *api.APIError
			if !errors.As(authorityErr, &apiErr) || apiErr.Code != "authority_not_initialized" {
				return safeEnvironmentControlError(authorityErr)
			}
		}
		result, err = dependencies.manager.BeginManagerEnrollment(command.Context(), dependencies.certificate, dependencies.subjectGeneration, true, now)
		if err != nil {
			return safeEnvironmentControlError(err)
		}
	}
	defer clear(result.Recovery)
	if result.AuthorityActive {
		if !result.RecoveryExportConfirmed {
			return errors.New("ENV authority is already initialized; the pending enrollment belongs to an existing manager")
		}
		recovery, readErr := readEnvironmentRecoveryFile(recoveryOutput)
		if readErr != nil {
			return errors.New("ENV authority is active, but the confirmed offline recovery file could not be verified")
		}
		confirmErr := dependencies.manager.ConfirmRecoveryExport(recovery)
		clear(recovery)
		if confirmErr != nil {
			return safeEnvironmentControlError(confirmErr)
		}
		authority, authorityErr := dependencies.client.GetEnvironmentAuthority(command.Context())
		if authorityErr != nil {
			return safeEnvironmentControlError(authorityErr)
		}
		_, authorityErr = fmt.Fprintf(command.OutOrStdout(), "ENV authority %s is active at generation %d.\n", authority.AuthorityID, authority.Generation)
		return authorityErr
	}
	if _, authorityErr := dependencies.client.GetEnvironmentAuthority(command.Context()); authorityErr == nil {
		return errors.New("an ENV manager enrollment is pending for an existing authority; run `pb env enroll` or cancel it with `pb env enrollment cancel --yes`")
	} else {
		var apiErr *api.APIError
		if !errors.As(authorityErr, &apiErr) || apiErr.Code != "authority_not_initialized" {
			return safeEnvironmentControlError(authorityErr)
		}
	}
	if len(result.Recovery) == 0 && !result.RecoveryExportConfirmed {
		return errors.New("ENV initialization did not produce a recovery key")
	}
	if len(result.Recovery) > 0 {
		if err := ensureEnvironmentRecoveryFile(recoveryOutput, result.Recovery); err != nil {
			return err
		}
	}
	recovery, err := readEnvironmentRecoveryFile(recoveryOutput)
	if err != nil {
		return err
	}
	if err := dependencies.manager.ConfirmRecoveryExport(recovery); err != nil {
		clear(recovery)
		return safeEnvironmentControlError(err)
	}
	clear(recovery)
	_, _ = fmt.Fprintf(command.OutOrStdout(), "ENV recovery key written and verified at %s. Store it offline.\n", recoveryOutput)
	_, _ = fmt.Fprintf(command.OutOrStdout(), "ENV enrollment %s safety code %s.\n", result.RequestID, result.SafetyCode)
	transition, err := dependencies.manager.ApproveEnrollment(command.Context(), result.RequestID, result.SafetyCode, now)
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	_, err = fmt.Fprintf(command.OutOrStdout(), "ENV authority %s is active at generation %d.\n", transition.AuthorityID, transition.Generation)
	return err
}

func cancelEnvironmentManagerEnrollment(command *cobra.Command, yes bool) error {
	if !yes {
		return invocationError(errors.New("canceling an ENV manager enrollment requires --yes"))
	}
	dependencies, err := environmentControlDependenciesForCommand(command)
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	defer dependencies.clear()
	if err := dependencies.manager.CancelManagerEnrollment(); err != nil {
		return safeEnvironmentControlError(err)
	}
	_, err = fmt.Fprintln(command.OutOrStdout(), "Canceled this CLI's pending ENV key enrollment; active authority and encrypted values were not changed.")
	return err
}

func beginEnvironmentManagerEnrollment(command *cobra.Command) error {
	dependencies, err := environmentControlDependenciesForCommand(command)
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	defer dependencies.clear()
	if _, err := dependencies.client.GetEnvironmentAuthority(command.Context()); err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.Code == "authority_not_initialized" {
			return errors.New("ENV authority is not initialized; run `pb env init --recovery-output <absolute-path>`")
		}
		return safeEnvironmentControlError(err)
	}
	result, err := dependencies.manager.BeginManagerEnrollment(command.Context(), dependencies.certificate, dependencies.subjectGeneration, false, time.Now().UTC())
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	_, err = fmt.Fprintf(command.OutOrStdout(), "ENV enrollment %s is pending until %s.\nSafety code: %s\nApprove from a trusted root-bearing manager with `pb env approve %s --code %s`.\n", result.RequestID, result.ExpiresAt.Local().Format(time.RFC3339), result.SafetyCode, result.RequestID, result.SafetyCode)
	return err
}

func listPendingEnvironmentEnrollments(command *cobra.Command, jsonOutput bool) error {
	dependencies, err := environmentControlDependenciesForCommand(command)
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	defer dependencies.clear()
	items, err := dependencies.manager.ListVerifiedPendingEnrollments(command.Context(), time.Now().UTC())
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	type row struct {
		RequestID   string `json:"request_id"`
		SubjectKind string `json:"subject_kind"`
		SubjectID   string `json:"subject_id"`
		SafetyCode  string `json:"safety_code"`
		ExpiresAt   string `json:"expires_at"`
	}
	rows := make([]row, 0, len(items))
	for _, item := range items {
		rows = append(rows, row{RequestID: item.RequestID, SubjectKind: environmentSubjectKindName(item.Request.SubjectKind), SubjectID: item.Request.SubjectID, SafetyCode: item.SafetyCode, ExpiresAt: item.ExpiresAt.Format(time.RFC3339)})
	}
	if jsonOutput {
		return json.NewEncoder(command.OutOrStdout()).Encode(map[string]any{"schema_version": "1.0", "ok": true, "data": map[string]any{"items": rows}})
	}
	writer := tabwriter.NewWriter(command.OutOrStdout(), 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(writer, "REQUEST\tKIND\tSUBJECT\tSAFETY CODE\tEXPIRES")
	for _, item := range rows {
		_, _ = fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", item.RequestID, item.SubjectKind, item.SubjectID, item.SafetyCode, item.ExpiresAt)
	}
	return writer.Flush()
}

func approveEnvironmentEnrollment(command *cobra.Command, requestID, safetyCode string) error {
	requestID, safetyCode = strings.TrimSpace(requestID), strings.ToLower(strings.TrimSpace(safetyCode))
	if !environmentSubjectIDPattern.MatchString(requestID) || !environmentSafetyCodePattern.MatchString(safetyCode) {
		return invocationError(errors.New("approve requires an exact request ID and 16-character safety code"))
	}
	dependencies, err := environmentControlDependenciesForCommand(command)
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	defer dependencies.clear()
	result, err := dependencies.manager.ApproveEnrollment(command.Context(), requestID, safetyCode, time.Now().UTC())
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	_, err = fmt.Fprintf(command.OutOrStdout(), "Authorized ENV keys; authority %s is active at generation %d.\n", result.AuthorityID, result.Generation)
	return err
}

func revokeEnvironmentSubject(command *cobra.Command, kind environmente2ee.SubjectKind, requested string, yes bool) error {
	if !yes {
		return invocationError(errors.New("ENV revocation requires --yes"))
	}
	dependencies, err := environmentControlDependenciesForCommand(command)
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	defer dependencies.clear()
	subjectID := strings.TrimSpace(requested)
	if kind == environmente2ee.SubjectHost {
		target, err := environmentVariableTargetForCommand(command, dependencies.client, subjectID)
		if err != nil {
			return err
		}
		subjectID = target.machineID
	} else if !environmentSubjectIDPattern.MatchString(subjectID) {
		return invocationError(errors.New("manager ID is invalid"))
	}
	result, err := dependencies.manager.ApplyAuthorityChange(command.Context(), environmentmanager.AuthorityChange{Remove: []environmentmanager.SubjectRef{{Kind: kind, ID: subjectID}}})
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	_, err = fmt.Fprintf(command.OutOrStdout(), "Revoked %s %s; authority %s is active at generation %d and affected scope keys were rotated. Previously disclosed values cannot be taken back.\n", environmentSubjectKindName(kind), subjectID, result.AuthorityID, result.Generation)
	return err
}

func parseEnvironmentManagerKind(value string) (environmente2ee.SubjectKind, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "cli":
		return environmente2ee.SubjectManagerCLI, nil
	case "browser":
		return environmente2ee.SubjectManagerBrowser, nil
	default:
		return 0, invocationError(errors.New("revoke-manager requires --kind cli or --kind browser"))
	}
}

func rotateEnvironmentScope(command *cobra.Command, requestedMachine string, yes bool) error {
	if !yes {
		return invocationError(errors.New("ENV scope-key rotation requires --yes"))
	}
	dependencies, err := environmentControlDependenciesForCommand(command)
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	defer dependencies.clear()
	target, err := environmentVariableTargetForCommand(command, dependencies.client, requestedMachine)
	if err != nil {
		return err
	}
	scope := environmentmanager.ScopeRef{Scope: environmente2ee.ScopeGlobal}
	if target.machineID != "" {
		scope.Scope, scope.MachineID = environmente2ee.ScopeMachine, target.machineID
	}
	result, err := dependencies.manager.ApplyAuthorityChange(command.Context(), environmentmanager.AuthorityChange{RotateScopes: []environmentmanager.ScopeRef{scope}})
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	_, err = fmt.Fprintf(command.OutOrStdout(), "Rotated %s ENV key; authority %s is active at generation %d.\n", environmentVariableScopeLabel(target), result.AuthorityID, result.Generation)
	return err
}

func resetEnvironmentAuthority(command *cobra.Command, accountID, recoveryOutput, confirmation string) error {
	accountID = strings.TrimSpace(accountID)
	if !environmentSubjectIDPattern.MatchString(accountID) {
		return invocationError(errors.New("env reset requires a valid account ID"))
	}
	expected := "RESET ENV " + accountID
	if confirmation != "" && confirmation != expected {
		return invocationError(errors.New("--confirm-reset must exactly match `RESET ENV <account_id>`"))
	}
	if recoveryOutput = strings.TrimSpace(recoveryOutput); recoveryOutput != "" && !filepath.IsAbs(recoveryOutput) {
		return invocationError(errors.New("--recovery-output must be an absolute path"))
	}
	dependencies, err := environmentControlDependenciesForCommand(command)
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	defer dependencies.clear()
	if dependencies.accountID != "" && dependencies.accountID != accountID {
		return invocationError(errors.New("env reset account ID does not match the active account"))
	}
	resetManager, ok := dependencies.manager.(environmentDestructiveResetManager)
	if !ok {
		return safeEnvironmentControlError(errors.New("ENV destructive reset is unavailable"))
	}
	preparation, resumeErr := resetManager.ResumeDestructiveResetPreparation()
	if resumeErr != nil {
		if !errors.Is(resumeErr, config.ErrSecretNotFound) {
			return safeEnvironmentControlError(resumeErr)
		}
		preparation, err = resetManager.BeginDestructiveResetPreparation()
		if err != nil {
			return safeEnvironmentControlError(err)
		}
	}
	defer preparation.Clear()
	if preparation.Handle == "" || len(preparation.RecoveryRecipientPublic) == 0 {
		return safeEnvironmentControlError(errors.New("ENV destructive reset preparation is incomplete"))
	}
	if preparation.ExportConfirmed {
		if recoveryOutput != "" {
			if err := verifyDestructiveResetRecoveryFile(recoveryOutput, preparation.RecoveryRecipientPublic); err != nil {
				return err
			}
		}
	} else {
		if recoveryOutput == "" {
			return invocationError(errors.New("the first ENV reset requires --recovery-output"))
		}
		if len(preparation.Recovery) == 0 {
			return safeEnvironmentControlError(errors.New("ENV destructive reset did not produce a recovery key"))
		}
		if err := ensureEnvironmentRecoveryFile(recoveryOutput, preparation.Recovery); err != nil {
			return err
		}
		exported, readErr := readEnvironmentRecoveryFile(recoveryOutput)
		if readErr != nil {
			return readErr
		}
		confirmErr := resetManager.ConfirmDestructiveResetExport(exported)
		clear(exported)
		if confirmErr != nil {
			return safeEnvironmentControlError(confirmErr)
		}
	}
	if recoveryOutput != "" {
		if _, err := fmt.Fprintf(command.OutOrStdout(), "Fresh ENV recovery key written and verified at %s. Store it offline.\n", recoveryOutput); err != nil {
			return err
		}
	}

	// The export gate is complete before this first network read. Freeze and
	// print every destructive scope/name before accepting the typed phrase.
	inventory, err := dependencies.client.GetEnvironmentScopeInventory(command.Context())
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	if err := writeDestructiveResetInventory(command.OutOrStdout(), inventory); err != nil {
		return err
	}
	if confirmation == "" {
		if _, err := fmt.Fprintf(command.OutOrStdout(), "Type %s to permanently delete every listed ENV value and replace all manager keys: ", expected); err != nil {
			return err
		}
		line, readErr := bufio.NewReader(command.InOrStdin()).ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		confirmation = strings.TrimSpace(line)
	}
	if confirmation != expected {
		return invocationError(errors.New("destructive reset canceled: confirmation did not match"))
	}
	result, err := resetManager.StartDestructiveReset(command.Context(), dependencies.certificate, dependencies.subjectGeneration, inventory, confirmation, time.Now().UTC())
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	_, err = fmt.Fprintf(command.OutOrStdout(), "Destructive ENV reset complete; authority %s is active at generation %d. Every listed value was deleted and only this fresh CLI manager plus fresh recovery binding remain.\n", result.AuthorityID, result.Generation)
	return err
}

func cancelDestructiveReset(command *cobra.Command, accountID, confirmation string) error {
	accountID = strings.TrimSpace(accountID)
	expected := "CANCEL ENV RESET " + accountID
	if !environmentSubjectIDPattern.MatchString(accountID) || confirmation != expected {
		return invocationError(errors.New("reset cancel requires --confirm-cancel `CANCEL ENV RESET <account_id>`"))
	}
	dependencies, err := environmentControlDependenciesForCommand(command)
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	defer dependencies.clear()
	if dependencies.accountID != "" && dependencies.accountID != accountID {
		return invocationError(errors.New("reset cancel account ID does not match the active account"))
	}
	resetManager, ok := dependencies.manager.(environmentDestructiveResetManager)
	if !ok {
		return safeEnvironmentControlError(errors.New("ENV destructive reset is unavailable"))
	}
	if err := resetManager.CancelDestructiveResetPreparation(); err != nil {
		return safeEnvironmentControlError(err)
	}
	_, err = fmt.Fprintln(command.OutOrStdout(), "Canceled the local ENV destructive reset preparation; active authority and encrypted values were not changed.")
	return err
}

func writeDestructiveResetInventory(output io.Writer, inventory api.EnvironmentScopeInventory) error {
	if inventory.Schema != api.EnvironmentScopeInventorySchemaV1 || len(inventory.Scopes) == 0 {
		return errors.New("server returned an invalid ENV reset inventory")
	}
	if _, err := fmt.Fprintln(output, "WARNING: this reset permanently deletes every listed ENV value and replaces all manager and recovery bindings."); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "Frozen destructive inventory:"); err != nil {
		return err
	}
	for _, scope := range inventory.Scopes {
		label := string(scope.Scope)
		if scope.MachineID != nil {
			label += " " + *scope.MachineID
		}
		if _, err := fmt.Fprintf(output, "- %s (%s):", label, scope.ScopeState); err != nil {
			return err
		}
		if len(scope.Names) == 0 {
			if _, err := fmt.Fprintln(output, " <none>"); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(output, " %s\n", strings.Join(scope.Names, ", ")); err != nil {
			return err
		}
	}
	return nil
}

func verifyDestructiveResetRecoveryFile(path string, expectedPublic []byte) error {
	value, err := readEnvironmentRecoveryFile(path)
	if err != nil {
		return errors.New("confirmed ENV reset recovery output could not be verified")
	}
	decrypted, err := environmente2ee.DecodeRecoveryBytes(value)
	clear(value)
	if err != nil {
		clear(decrypted)
		return errors.New("confirmed ENV reset recovery output is invalid")
	}
	defer clear(decrypted)
	key, err := ecdh.X25519().NewPrivateKey(decrypted)
	if err != nil {
		return errors.New("confirmed ENV reset recovery output is invalid")
	}
	public := key.PublicKey().Bytes()
	defer clear(public)
	if len(public) != len(expectedPublic) || subtle.ConstantTimeCompare(public, expectedPublic) != 1 {
		return errors.New("confirmed ENV reset recovery output does not match the pending key")
	}
	return nil
}

func abortEnvironmentTransition(command *cobra.Command, transitionID string, yes bool) error {
	if !yes {
		return invocationError(errors.New("ENV transition abort requires --yes"))
	}
	dependencies, err := environmentControlDependenciesForCommand(command)
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	defer dependencies.clear()
	result, err := dependencies.manager.AbortAuthorityTransition(command.Context(), strings.TrimSpace(transitionID))
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	_, err = fmt.Fprintf(command.OutOrStdout(), "Aborted ENV transition %s; active authority remains %s at generation %d.\n", result.TransitionID, result.AuthorityID, result.Generation)
	return err
}

func resumeEnvironmentTransition(command *cobra.Command) error {
	dependencies, err := environmentControlDependenciesForCommand(command)
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	defer dependencies.clear()
	result, err := dependencies.manager.ResumeAuthorityTransition(command.Context())
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	_, err = fmt.Fprintf(command.OutOrStdout(), "Resumed ENV transition %s; authority %s is active at generation %d.\n", result.TransitionID, result.AuthorityID, result.Generation)
	return err
}

func confirmEnvironmentRecoveryFile(command *cobra.Command, input string) error {
	value, err := readEnvironmentRecoveryFile(input)
	if err != nil {
		return err
	}
	defer clear(value)
	dependencies, err := environmentControlDependenciesForCommand(command)
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	defer dependencies.clear()
	if err := dependencies.manager.ConfirmRecoveryExport(value); err != nil {
		return safeEnvironmentControlError(err)
	}
	_, err = fmt.Fprintln(command.OutOrStdout(), "ENV recovery key storage confirmed; its online private copy was removed.")
	return err
}

func recoverEnvironmentAuthority(command *cobra.Command, input, replacementOutput string) error {
	input, replacementOutput = strings.TrimSpace(input), strings.TrimSpace(replacementOutput)
	if !filepath.IsAbs(replacementOutput) || input != "" && (!filepath.IsAbs(input) || filepath.Clean(input) == filepath.Clean(replacementOutput)) {
		return invocationError(errors.New("ENV recovery requires an absolute --replacement-output and a distinct absolute --recovery-key when starting"))
	}
	dependencies, err := environmentControlDependenciesForCommand(command)
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	defer dependencies.clear()
	preparation, resumeErr := dependencies.manager.ResumeRecoveryPreparation()
	if resumeErr != nil {
		if !errors.Is(resumeErr, config.ErrSecretNotFound) {
			return safeEnvironmentControlError(resumeErr)
		}
		if input == "" {
			return invocationError(errors.New("--recovery-key is required when starting ENV recovery"))
		}
		imported, readErr := readEnvironmentRecoveryFile(input)
		if readErr != nil {
			return readErr
		}
		preparation, err = dependencies.manager.BeginRecoveryPreparation(imported)
		clear(imported)
		if err != nil {
			return safeEnvironmentControlError(err)
		}
	} else if input != "" {
		// Re-reading through Begin verifies that a supplied old recovery file
		// matches the secure-store import from the interrupted preparation.
		imported, readErr := readEnvironmentRecoveryFile(input)
		if readErr != nil {
			preparation.Clear()
			return readErr
		}
		verified, beginErr := dependencies.manager.BeginRecoveryPreparation(imported)
		clear(imported)
		preparation.Clear()
		if beginErr != nil {
			return safeEnvironmentControlError(beginErr)
		}
		preparation = verified
	}
	defer preparation.Clear()
	if len(preparation.Recovery) == 0 || preparation.ImportedHandle == "" || preparation.ReplacementHandle == "" {
		return errors.New("ENV recovery preparation is incomplete")
	}
	if preparation.ExportConfirmed {
		if err := verifyEnvironmentRecoveryFile(replacementOutput, preparation.Recovery); err != nil {
			return err
		}
	} else {
		if err := ensureEnvironmentRecoveryFile(replacementOutput, preparation.Recovery); err != nil {
			return err
		}
		exported, readErr := readEnvironmentRecoveryFile(replacementOutput)
		if readErr != nil {
			return readErr
		}
		confirmErr := dependencies.manager.ConfirmRecoveryPreparationExport(exported)
		clear(exported)
		if confirmErr != nil {
			return safeEnvironmentControlError(confirmErr)
		}
	}
	_, _ = fmt.Fprintf(command.OutOrStdout(), "Replacement ENV recovery key written to %s. Store it offline.\n", replacementOutput)
	result, err := dependencies.manager.RecoverAndRotate(command.Context(), environmentmanager.RecoveryRotationRequest{
		ImportedRecoveryHandle: preparation.ImportedHandle, ReplacementRecoveryHandle: preparation.ReplacementHandle,
		EndpointCertificate: dependencies.certificate, SubjectGeneration: dependencies.subjectGeneration, Now: time.Now().UTC(),
	})
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	_, err = fmt.Fprintf(command.OutOrStdout(), "Recovered ENV access; authority %s is active at generation %d and every scope key was rotated. Previously disclosed values cannot be taken back.\n", result.AuthorityID, result.Generation)
	return err
}

func cancelEnvironmentRecovery(command *cobra.Command, yes bool) error {
	if !yes {
		return invocationError(errors.New("canceling ENV recovery preparation requires --yes"))
	}
	dependencies, err := environmentControlDependenciesForCommand(command)
	if err != nil {
		return safeEnvironmentControlError(err)
	}
	defer dependencies.clear()
	if err := dependencies.manager.CancelRecoveryPreparation(); err != nil {
		return safeEnvironmentControlError(err)
	}
	_, err = fmt.Fprintln(command.OutOrStdout(), "Canceled the pending local ENV recovery preparation; offline recovery files were not changed.")
	return err
}

func ensureEnvironmentRecoveryFile(path string, value []byte) error {
	err := writeEnvironmentRecoveryFile(path, value)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	existing, readErr := readEnvironmentRecoveryFile(path)
	if readErr != nil {
		return errors.New("existing ENV recovery output could not be verified")
	}
	defer clear(existing)
	if len(existing) != len(value) || subtle.ConstantTimeCompare(existing, value) != 1 {
		return errors.New("existing ENV recovery output does not match the pending replacement key")
	}
	if err := syncEnvironmentRecoveryDirectory(filepath.Dir(strings.TrimSpace(path))); err != nil {
		return fmt.Errorf("sync existing ENV recovery-key directory: %w", err)
	}
	return nil
}

func verifyEnvironmentRecoveryFile(path string, value []byte) error {
	existing, err := readEnvironmentRecoveryFile(path)
	if err != nil {
		return errors.New("confirmed ENV replacement recovery output could not be verified; cancel the preparation before starting over")
	}
	defer clear(existing)
	if len(existing) != len(value) || subtle.ConstantTimeCompare(existing, value) != 1 {
		return errors.New("confirmed ENV replacement recovery output does not match the pending key; cancel the preparation before starting over")
	}
	if err := syncEnvironmentRecoveryDirectory(filepath.Dir(strings.TrimSpace(path))); err != nil {
		return fmt.Errorf("sync confirmed ENV recovery-key directory: %w", err)
	}
	return nil
}

func writeEnvironmentRecoveryFile(path string, value []byte) (resultErr error) {
	path = strings.TrimSpace(path)
	if !filepath.IsAbs(path) || len(value) == 0 || bytes.ContainsAny(value, "\x00\r\n") {
		return errors.New("ENV recovery output is invalid")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("ENV recovery output directory is invalid")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create ENV recovery-key file: %w", err)
	}
	created := true
	defer func() {
		if file != nil {
			resultErr = errors.Join(resultErr, file.Close())
		}
		if resultErr != nil && created {
			_ = os.Remove(path)
		}
	}()
	payload := make([]byte, 0, len(value)+1)
	payload = append(payload, value...)
	payload = append(payload, '\n')
	defer clear(payload)
	if _, err := file.Write(payload); err != nil {
		return fmt.Errorf("write ENV recovery-key file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync ENV recovery-key file: %w", err)
	}
	if err := file.Close(); err != nil {
		file = nil
		return fmt.Errorf("close ENV recovery-key file: %w", err)
	}
	file = nil
	if err := syncEnvironmentRecoveryDirectory(parent); err != nil {
		return fmt.Errorf("sync ENV recovery-key directory: %w", err)
	}
	created = false
	return nil
}

func readEnvironmentRecoveryFile(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if !filepath.IsAbs(path) {
		return nil, invocationError(errors.New("--recovery-key must be an absolute path"))
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, openedErr := file.Stat()
	linked, linkedErr := os.Lstat(path)
	if openedErr != nil || linkedErr != nil || !opened.Mode().IsRegular() || !linked.Mode().IsRegular() || linked.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, linked) || opened.Mode().Perm()&0o077 != 0 || opened.Size() <= 1 || opened.Size() > 256 {
		return nil, errors.New("ENV recovery-key file must be a small regular owner-only file")
	}
	value, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil || len(value) > 256 {
		clear(value)
		return nil, errors.New("could not read ENV recovery-key file")
	}
	value = bytes.TrimSuffix(value, []byte{'\n'})
	if len(value) == 0 || bytes.ContainsAny(value, "\x00\r\n \t") {
		clear(value)
		return nil, errors.New("ENV recovery-key file is invalid")
	}
	return value, nil
}

func safeEnvironmentControlError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, environmentmanager.ErrRootAuthorizationRequired):
		return errors.New("account-root authorization is required on this trusted CLI")
	case errors.Is(err, environmentmanager.ErrKeyAuthorizationRequired):
		return errors.New("ENV key authorization required from an existing trusted manager")
	case errors.Is(err, environmentmanager.ErrRecoveryExportRequired):
		return errors.New("confirm offline ENV recovery-key storage before changing values")
	case errors.Is(err, environmentmanager.ErrDestructiveResetConfirmationRequired):
		return errors.New("type the exact destructive reset confirmation before changing ENV state")
	case errors.Is(err, environmentmanager.ErrDestructiveResetInventoryChanged):
		return errors.New("ENV reset inventory changed; no values or keys were changed")
	case errors.Is(err, environmentmanager.ErrEnrollmentExpired):
		return errors.New("ENV key enrollment expired; create a new request")
	case errors.Is(err, environmentmanager.ErrNoPendingEnrollment):
		return errors.New("there is no pending ENV manager enrollment for this CLI")
	case errors.Is(err, environmentmanager.ErrSafetyCodeMismatch):
		return errors.New("ENV safety code does not match; do not approve this request")
	case errors.Is(err, environmentmanager.ErrNoDecryptingKey):
		return errors.New("no trusted local ENV key can decrypt every required scope; use offline recovery or reset")
	case errors.Is(err, environmentmanager.ErrTransitionIncomplete):
		return errors.New("ENV authority transition is staged but incomplete; resume it or root-authorize an abort")
	case errors.Is(err, environmentmanager.ErrPendingTransitionReconciled):
		return errors.New("a previous ENV authority transition was completed; retry the requested operation if it is still needed")
	case errors.Is(err, environmentmanager.ErrAuthorityFork), errors.Is(err, environmentmanager.ErrIntegrity):
		return errors.New("ENV authority or encrypted manifest verification failed; no change was activated")
	}
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Code {
		case "authority_conflict", "version_conflict", "precondition_failed":
			return errors.New("ENV state changed concurrently; fetch current state and retry")
		case "transition_in_progress":
			return errors.New("an ENV authority transition is already in progress; finish or abort it")
		case "key_authorization_required":
			return errors.New("ENV key authorization required from an existing trusted manager")
		}
	}
	return errors.New("ENV key-management request failed")
}

func environmentSubjectKindName(kind environmente2ee.SubjectKind) string {
	switch kind {
	case environmente2ee.SubjectManagerCLI:
		return "manager_cli"
	case environmente2ee.SubjectManagerBrowser:
		return "manager_browser"
	case environmente2ee.SubjectHost:
		return "host"
	case environmente2ee.SubjectRecovery:
		return "recovery"
	default:
		return "unknown"
	}
}

var environmentSubjectIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var environmentSafetyCodePattern = regexp.MustCompile(`^[a-z2-7]{4}(?:-[a-z2-7]{4}){3}$`)
