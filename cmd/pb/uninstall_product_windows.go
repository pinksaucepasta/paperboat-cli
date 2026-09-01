//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"github.com/pinksaucepasta/paperboat/internal/windows/elevation"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

const (
	windowsUninstallPlanSchema   = "paperboat.windows-uninstall-plan/v1"
	windowsUninstallStatusSchema = "paperboat.windows-uninstall-status/v1"
)

var (
	purgeWindowsHostRuntime    = hostinstall.Purge
	windowsUninstallExecutable = os.Executable
)

type windowsUninstallPlan struct {
	Schema     string    `json:"schema"`
	ProcessIDs []uint32  `json:"process_ids"`
	StatusPath string    `json:"status_path"`
	InboxPaths []string  `json:"inbox_paths"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type windowsUninstallStatus struct {
	Schema      string    `json:"schema"`
	State       string    `json:"state"`
	Error       string    `json:"error,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

// removePlatformProductInstallation hands cleanup to a protected helper before
// the calling executable or its user state can be removed. The helper runs the
// same unified pb executable with an internal completion argument, so it never
// depends on a separate installer or cleanup binary.
func removePlatformProductInstallation(ctx context.Context, inboxPaths []string, output io.Writer) error {
	if ctx == nil || output == nil {
		return errors.New("invalid Windows uninstall handoff")
	}
	statusPath, err := launchWindowsUninstallHelper(ctx, inboxPaths)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(output, "Windows uninstall is continuing in the elevated cleanup helper. Completion status: %s\n", statusPath)
	return nil
}

func purgePlatformRuntime(*cobra.Command) error { return nil }

func platformUninstallSuccessMessage() string {
	return "Paperboat user state was removed and Windows system cleanup was started. The Paperboat Inbox was preserved."
}

func platformProductHandoffRequired() bool { return true }

func platformRequiresConfirmedDaemonStop() bool { return true }

func unsafeCleanupPathTraversal(path string, info os.FileInfo) (bool, error) {
	if info.Mode()&os.ModeSymlink != 0 {
		return true, nil
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil {
		return false, err
	}
	return attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}

func launchWindowsUninstallHelper(ctx context.Context, inboxPaths []string) (string, error) {
	executable, err := windowsUninstallExecutable()
	if err != nil {
		return "", err
	}
	identifierBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, identifierBytes); err != nil {
		return "", err
	}
	identifier := hex.EncodeToString(identifierBytes)
	directory := filepath.Join(os.TempDir(), "Paperboat Uninstall", identifier)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	keepDirectory := false
	defer func() {
		if !keepDirectory {
			_ = os.RemoveAll(directory)
		}
	}()
	if err := protectWindowsUninstallPath(directory, true); err != nil {
		return "", err
	}
	helperPath := filepath.Join(directory, "paperboat-uninstall-helper.exe")
	if err := copyWindowsUninstallHelper(executable, helperPath); err != nil {
		return "", err
	}
	statusPath := filepath.Join(directory, "status.json")
	planPath := filepath.Join(directory, "plan.json")
	processIDs := []uint32{uint32(os.Getpid())}
	if parent := installedWindowsParentPID(); parent != 0 {
		processIDs = append(processIDs, parent)
	}
	now := time.Now().UTC()
	plan := windowsUninstallPlan{Schema: windowsUninstallPlanSchema, ProcessIDs: processIDs, StatusPath: statusPath, InboxPaths: append([]string(nil), inboxPaths...), CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if err := writeProtectedWindowsUninstallJSON(planPath, plan); err != nil {
		return "", err
	}
	if err := writeProtectedWindowsUninstallJSON(statusPath, windowsUninstallStatus{Schema: windowsUninstallStatusSchema, State: "scheduled", UpdatedAt: now}); err != nil {
		return "", err
	}
	if err := elevation.LaunchDetached(ctx, helperPath, []string{"__complete-uninstall", "--plan", planPath}); err != nil {
		failedAt := time.Now().UTC()
		_ = writeProtectedWindowsUninstallJSON(statusPath, windowsUninstallStatus{Schema: windowsUninstallStatusSchema, State: "failed", Error: err.Error(), UpdatedAt: failedAt, CompletedAt: failedAt})
		return "", err
	}
	keepDirectory = true
	if err := waitForWindowsUninstallHandoff(ctx, statusPath); err != nil {
		return "", err
	}
	return statusPath, nil
}

func platformUninstallHelperCommand() *cobra.Command {
	command := &cobra.Command{
		Use:    "__complete-uninstall",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			planPath, err := command.Flags().GetString("plan")
			if err != nil {
				return err
			}
			return runWindowsUninstallHelper(command.Context(), planPath)
		},
		SilenceUsage: true, SilenceErrors: true,
	}
	command.Flags().String("plan", "", "protected uninstall plan")
	return command
}

func runWindowsUninstallHelper(ctx context.Context, planPath string) error {
	if !elevation.IsCurrentProcessElevated() {
		return elevation.ErrNotElevated
	}
	plan, err := readWindowsUninstallPlan(planPath)
	if err != nil {
		return err
	}
	scheduleWindowsUninstallHelperDeletion()
	status := func(state string, statusErr error) error {
		value := windowsUninstallStatus{Schema: windowsUninstallStatusSchema, State: state, UpdatedAt: time.Now().UTC()}
		if statusErr != nil {
			value.Error = statusErr.Error()
		}
		if state == "completed" || state == "failed" || state == "timed_out" {
			value.CompletedAt = value.UpdatedAt
		}
		return writeProtectedWindowsUninstallJSON(plan.StatusPath, value)
	}
	if err := status("waiting_for_parent", nil); err != nil {
		return err
	}
	deadline := plan.ExpiresAt
	for _, processID := range plan.ProcessIDs {
		if err := waitForWindowsProcess(ctx, processID, deadline); err != nil {
			state := "failed"
			if errors.Is(err, context.DeadlineExceeded) {
				state = "timed_out"
			}
			_ = status(state, err)
			return err
		}
	}
	if err := status("removing", nil); err != nil {
		return err
	}
	cleanupCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	completed := make(chan error, 1)
	go func() { completed <- performWindowsSystemUninstall(cleanupCtx, plan.InboxPaths) }()
	var result error
	select {
	case result = <-completed:
	case <-cleanupCtx.Done():
		result = cleanupCtx.Err()
	}
	if result != nil {
		state := "failed"
		if errors.Is(result, context.DeadlineExceeded) {
			state = "timed_out"
		}
		_ = status(state, result)
		return result
	}
	if err := status("completed", nil); err != nil {
		return err
	}
	_ = os.Remove(planPath)
	return nil
}

func performWindowsSystemUninstall(ctx context.Context, inboxPaths []string) error {
	var result error
	result = errors.Join(result, performWindowsRegisteredCleanup(ctx))
	if layout, layoutErr := service.DefaultLayout("windows"); layoutErr != nil {
		result = errors.Join(result, layoutErr)
	} else {
		result = errors.Join(result, retryWindowsRemoval(ctx, layout.InstallRoot, inboxPaths))
	}
	result = errors.Join(result, retryWindowsRemoval(ctx, hostinstall.WindowsProgramDataRoot(), inboxPaths))
	return result
}

func performWindowsRegisteredCleanup(ctx context.Context) error {
	// The installed unified executable owns the host runtime directly. Purge
	// that runtime before removing the installation root; no split cleanup
	// action is needed.
	return purgeWindowsHostRuntime(ctx)
}

func readWindowsUninstallPlan(planPath string) (windowsUninstallPlan, error) {
	var plan windowsUninstallPlan
	helperPath, helperErr := windowsUninstallExecutable()
	if helperErr != nil || !filepath.IsAbs(planPath) || !strings.EqualFold(filepath.Base(planPath), "plan.json") || !strings.EqualFold(filepath.Dir(planPath), filepath.Dir(helperPath)) || !windowssecurity.ProtectedDACLMatches(planPath, uninstallWindowsSDDL()) {
		return plan, errors.New("invalid protected Windows uninstall plan")
	}
	encoded, err := os.ReadFile(planPath)
	if err != nil || len(encoded) > 64<<10 {
		return plan, errors.New("invalid protected Windows uninstall plan")
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&plan) != nil || !errors.Is(decoder.Decode(&extra), io.EOF) || plan.Schema != windowsUninstallPlanSchema || len(plan.ProcessIDs) < 1 || len(plan.ProcessIDs) > 2 || !filepath.IsAbs(plan.StatusPath) || !strings.EqualFold(filepath.Dir(plan.StatusPath), filepath.Dir(planPath)) || !strings.EqualFold(filepath.Base(plan.StatusPath), "status.json") || plan.CreatedAt.IsZero() || plan.ExpiresAt.IsZero() || plan.ExpiresAt.Sub(plan.CreatedAt) != 5*time.Minute || time.Now().UTC().After(plan.ExpiresAt) {
		return windowsUninstallPlan{}, errors.New("invalid protected Windows uninstall plan")
	}
	for _, processID := range plan.ProcessIDs {
		if processID == 0 || processID == uint32(os.Getpid()) {
			return windowsUninstallPlan{}, errors.New("invalid protected Windows uninstall plan")
		}
	}
	for _, path := range plan.InboxPaths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.VolumeName(path)+`\` == path {
			return windowsUninstallPlan{}, errors.New("invalid protected Windows uninstall plan")
		}
	}
	return plan, nil
}

func waitForWindowsUninstallHandoff(ctx context.Context, statusPath string) error {
	for {
		status, err := readWindowsUninstallStatus(statusPath)
		if err != nil {
			return err
		}
		switch status.State {
		case "waiting_for_parent", "completed":
			return nil
		case "failed", "timed_out":
			if strings.TrimSpace(status.Error) == "" {
				return fmt.Errorf("Windows uninstall helper reported %s", status.State)
			}
			return fmt.Errorf("Windows uninstall helper reported %s: %s", status.State, status.Error)
		case "scheduled":
		default:
			return errors.New("invalid protected Windows uninstall status")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func readWindowsUninstallStatus(statusPath string) (windowsUninstallStatus, error) {
	var status windowsUninstallStatus
	if !filepath.IsAbs(statusPath) || !strings.EqualFold(filepath.Base(statusPath), "status.json") || !windowssecurity.ProtectedDACLMatches(statusPath, uninstallWindowsSDDL()) {
		return status, errors.New("invalid protected Windows uninstall status")
	}
	encoded, err := os.ReadFile(statusPath)
	if err != nil || len(encoded) > 64<<10 {
		return status, errors.New("invalid protected Windows uninstall status")
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&status) != nil || !errors.Is(decoder.Decode(&extra), io.EOF) || status.Schema != windowsUninstallStatusSchema || status.UpdatedAt.IsZero() {
		return windowsUninstallStatus{}, errors.New("invalid protected Windows uninstall status")
	}
	return status, nil
}

func uninstallWindowsSDDL() string {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return ""
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return ""
	}
	return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")"
}

func protectWindowsUninstallPath(path string, directory bool) error {
	sddl := uninstallWindowsSDDL()
	if sddl == "" {
		return errors.New("resolve Windows uninstall owner")
	}
	if directory {
		sddl = strings.ReplaceAll(sddl, "(A;;", "(A;OICI;")
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func copyWindowsUninstallHelper(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	sourceDigest := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(output, sourceDigest), input)
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	if err := protectWindowsUninstallPath(destination, false); err != nil {
		return err
	}
	destinationFile, err := os.Open(destination)
	if err != nil {
		return err
	}
	destinationDigest := sha256.New()
	_, hashErr := io.Copy(destinationDigest, destinationFile)
	closeErr = destinationFile.Close()
	if hashErr != nil || closeErr != nil {
		return errors.Join(hashErr, closeErr)
	}
	if !bytes.Equal(sourceDigest.Sum(nil), destinationDigest.Sum(nil)) {
		return errors.New("copied Windows uninstall helper failed integrity verification")
	}
	return nil
}

func scheduleWindowsUninstallHelperDeletion() {
	executable, err := windowsUninstallExecutable()
	if err != nil {
		return
	}
	path, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return
	}
	_ = windows.MoveFileEx(path, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}

func writeProtectedWindowsUninstallJSON(path string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary := path + ".new"
	_ = os.Remove(temporary)
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	if err := protectWindowsUninstallPath(temporary, false); err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=windows-uninstall reason=same-directory-protected-status-staging
	if err := os.Rename(temporary, path); err != nil {
		from, fromErr := windows.UTF16PtrFromString(temporary)
		to, toErr := windows.UTF16PtrFromString(path)
		if fromErr != nil || toErr != nil {
			return errors.Join(err, fromErr, toErr)
		}
		if replaceErr := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); replaceErr != nil {
			return errors.Join(err, replaceErr)
		}
	}
	return protectWindowsUninstallPath(path, false)
}

func installedWindowsParentPID() uint32 {
	processID := uint32(os.Getppid())
	if processID == 0 {
		return 0
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, processID)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(handle)
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil || size == 0 {
		return 0
	}
	path := windows.UTF16ToString(buffer[:size])
	layout, err := service.DefaultLayout("windows")
	if err != nil || !pathWithinOrEqual(layout.InstallRoot, path) {
		return 0
	}
	return processID
}

func waitForWindowsProcess(ctx context.Context, processID uint32, deadline time.Time) error {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, processID)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return nil
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	for {
		if time.Now().UTC().After(deadline) {
			return context.DeadlineExceeded
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		result, err := windows.WaitForSingleObject(handle, 250)
		if err != nil {
			return err
		}
		if result == windows.WAIT_OBJECT_0 {
			return nil
		}
		if result != uint32(windows.WAIT_TIMEOUT) {
			return fmt.Errorf("wait for uninstall parent %d returned %d", processID, result)
		}
	}
}

func retryWindowsRemoval(ctx context.Context, path string, preserved []string) error {
	var last error
	for {
		last = removePathPreserving(path, preserved)
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(last, ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}
