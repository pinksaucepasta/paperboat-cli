//go:build windows && paperboat_native_e2e

package service

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/identity"
	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const s4uFixturePathEnvironment = "PAPERBOAT_WINDOWS_E2E_S4U_FIXTURE"
const s4uFixtureSHA256Environment = "PAPERBOAT_WINDOWS_E2E_S4U_FIXTURE_SHA256"
const s4uReportPathEnvironment = "PAPERBOAT_WINDOWS_E2E_S4U_REPORT_PATH"
const s4uServiceNameEnvironment = "PAPERBOAT_WINDOWS_E2E_S4U_SERVICE_NAME"
const s4uOwnerAccountEnvironment = "PAPERBOAT_WINDOWS_E2E_S4U_OWNER_ACCOUNT"

var (
	qualificationCredWrite = windows.NewLazySystemDLL("advapi32.dll").NewProc("CredWriteW")
	qualificationLogonUser = windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")
)

const (
	qualificationLogonInteractive     = uint32(2)
	qualificationLogonProviderDefault = uint32(0)
	qualificationPasswordLimit        = int64(512)
)

type qualificationWindowsCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         unsafe.Pointer
	TargetAlias        *uint16
	UserName           *uint16
}

func writeLegacyCredentialManagerFixture(t *testing.T, ref, value string) {
	t.Helper()
	target, err := windows.UTF16PtrFromString("paperboat:" + ref)
	if err != nil {
		t.Fatal(err)
	}
	username, err := windows.UTF16PtrFromString("paperboat")
	if err != nil {
		t.Fatal(err)
	}
	blob := []byte(value)
	defer clear(blob)
	credential := qualificationWindowsCredential{Type: 1, TargetName: target, CredentialBlobSize: uint32(len(blob)), Persist: 2, UserName: username}
	if len(blob) > 0 {
		credential.CredentialBlob = &blob[0]
	}
	if result, _, callErr := qualificationCredWrite.Call(uintptr(unsafe.Pointer(&credential)), 0); result == 0 {
		t.Fatalf("write legacy Credential Manager fixture: %v", callErr)
	}
}

func prepareProductionKeyringFixtures(t *testing.T, reportPath string, cleanup bool) {
	t.Helper()
	keyring := config.KeyringStore{}
	if err := keyring.Set(reportPath, "paperboat-s4u-dpapi-v1"); err != nil {
		t.Fatalf("create owner Paperboat KeyringStore fixture: %v", err)
	}
	migratedRef := reportPath + "-migrated"
	writeLegacyCredentialManagerFixture(t, migratedRef, "paperboat-s4u-migrated-v1")
	if value, err := keyring.Get(migratedRef); err != nil || value != "paperboat-s4u-migrated-v1" {
		t.Fatalf("migrate owner Credential Manager fixture into Paperboat KeyringStore: value=%q err=%v", value, err)
	}
	if cleanup {
		t.Cleanup(func() {
			_ = keyring.Delete(reportPath)
			_ = keyring.Delete(migratedRef)
		})
	}
}

const s4uPreviewControlURL = "https://api.example.test"

func prepareS4UPreviewIdentityFixture(t *testing.T, reportPath string) string {
	t.Helper()
	stateRoot := reportPath + ".preview-state"
	store, err := identity.Open(identity.Config{StateRoot: stateRoot})
	if err != nil {
		t.Fatalf("create S4U preview identity store: %v", err)
	}
	key := store.Current()
	registration := identity.Registration{
		ServerURL:              s4uPreviewControlURL,
		MachineID:              "machine_s4u_preview",
		EnvironmentID:          "environment_s4u_preview",
		PublicKeyID:            key.ID,
		PublicIdentityKey:      base64.RawURLEncoding.EncodeToString(key.Public()),
		InboxPath:              filepath.Join(stateRoot, "inbox"),
		InstallationGeneration: 1,
		SetupRoles:             []string{"host"},
		UpdatedAt:              time.Now().UTC(),
	}
	if err := store.SaveRegistration(registration); err != nil {
		t.Fatalf("save S4U preview registration: %v", err)
	}
	if err := store.SaveMachineControl(identity.MachineControl{
		MachineID:              registration.MachineID,
		EnvironmentID:          registration.EnvironmentID,
		InstallationGeneration: registration.InstallationGeneration,
		Credential:             strings.Repeat("m", 40),
		ExpiresAt:              time.Now().UTC().Add(2 * time.Hour),
		KeyID:                  key.ID,
	}); err != nil {
		t.Fatalf("save S4U preview machine-control fixture: %v", err)
	}
	return stateRoot
}

func qualificationProfilePrivilegeScope() (func() error, error) {
	runtime.LockOSThread()
	abort := func(err error, token windows.Token) (func() error, error) {
		if token != 0 {
			err = errors.Join(err, token.Close())
		}
		revertErr := windows.RevertToSelf()
		err = errors.Join(err, revertErr)
		if revertErr == nil {
			runtime.UnlockOSThread()
		}
		return nil, err
	}
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, false, &token); err != nil {
		return abort(err, 0)
	}
	names := []string{"SeBackupPrivilege", "SeRestorePrivilege"}
	stateBytes := make([]byte, unsafe.Sizeof(windows.Tokenprivileges{})+uintptr(len(names)-1)*unsafe.Sizeof(windows.LUIDAndAttributes{}))
	state := (*windows.Tokenprivileges)(unsafe.Pointer(&stateBytes[0]))
	state.PrivilegeCount = uint32(len(names))
	for index, value := range names {
		name, err := windows.UTF16PtrFromString(value)
		if err != nil {
			return abort(err, token)
		}
		if err := windows.LookupPrivilegeValue(nil, name, &state.AllPrivileges()[index].Luid); err != nil {
			return abort(err, token)
		}
		state.AllPrivileges()[index].Attributes = windows.SE_PRIVILEGE_ENABLED
	}
	previousBytes := make([]byte, len(stateBytes))
	previous := (*windows.Tokenprivileges)(unsafe.Pointer(&previousBytes[0]))
	var previousLength uint32
	result, _, callErr := syscall.SyscallN(procAdjustTokenPrivileges.Addr(), uintptr(token), 0, uintptr(unsafe.Pointer(state)), uintptr(len(previousBytes)), uintptr(unsafe.Pointer(previous)), uintptr(unsafe.Pointer(&previousLength)))
	if result == 0 || callErr == windows.ERROR_NOT_ALL_ASSIGNED {
		if callErr != syscall.Errno(0) {
			return abort(callErr, token)
		}
		return abort(windows.ERROR_GEN_FAILURE, token)
	}
	return func() error {
		var restoreErr error
		if previousLength > 0 {
			result, _, callErr := syscall.SyscallN(procAdjustTokenPrivileges.Addr(), uintptr(token), 0, uintptr(unsafe.Pointer(previous)), 0, 0, 0)
			if result == 0 {
				restoreErr = callErr
			}
		}
		revertErr := windows.RevertToSelf()
		restoreErr = errors.Join(restoreErr, token.Close(), revertErr)
		if revertErr == nil {
			runtime.UnlockOSThread()
		}
		runtime.KeepAlive(stateBytes)
		runtime.KeepAlive(previousBytes)
		return restoreErr
	}, nil
}

func closeQualificationProfile(profile *loadedOwnerProfile) error {
	if profile == nil {
		return nil
	}
	stopPrivileges, privilegeErr := qualificationProfilePrivilegeScope()
	if privilegeErr != nil {
		return errors.Join(privilegeErr, profile.Close())
	}
	closeErr := profile.Close()
	return errors.Join(closeErr, stopPrivileges())
}

func readQualificationPassword() ([]uint16, error) {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, qualificationPasswordLimit+2))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if len(raw) == 0 || int64(len(raw)) > qualificationPasswordLimit || len(raw)%2 != 0 {
		return nil, errors.New("invalid bounded UTF-16 qualification credential")
	}
	password := make([]uint16, len(raw)/2+1)
	for index := 0; index < len(raw); index += 2 {
		value := uint16(raw[index]) | uint16(raw[index+1])<<8
		if value == 0 {
			clear(password)
			return nil, errors.New("qualification credential contains an embedded NUL")
		}
		password[index/2] = value
	}
	return password, nil
}

func qualificationInteractiveToken(accountName string, password []uint16) (windows.Token, string, string, error) {
	account, domain, found := strings.Cut(accountName, `\`)
	if !found || account == "" || domain == "" {
		return 0, "", "", errors.New("qualification owner account must be DOMAIN\\user")
	}
	// strings.Cut returns the domain before the separator.
	domain, account = account, domain
	accountPointer, err := windows.UTF16PtrFromString(account)
	if err != nil {
		return 0, "", "", err
	}
	domainPointer, err := windows.UTF16PtrFromString(domain)
	if err != nil {
		return 0, "", "", err
	}
	var token windows.Token
	result, _, callErr := qualificationLogonUser.Call(uintptr(unsafe.Pointer(accountPointer)), uintptr(unsafe.Pointer(domainPointer)), uintptr(unsafe.Pointer(&password[0])), uintptr(qualificationLogonInteractive), uintptr(qualificationLogonProviderDefault), uintptr(unsafe.Pointer(&token)))
	runtime.KeepAlive(password)
	if result == 0 {
		if callErr != syscall.Errno(0) {
			return 0, "", "", callErr
		}
		return 0, "", "", windows.ERROR_LOGON_FAILURE
	}
	return token, account, domain, nil
}

func withQualificationOwner(t *testing.T, action func(windows.Token)) {
	t.Helper()
	password, err := readQualificationPassword()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(password)
	accountName := strings.TrimSpace(os.Getenv(s4uOwnerAccountEnvironment))
	token, account, domain, err := qualificationInteractiveToken(accountName, password)
	clear(password)
	if err != nil {
		t.Fatalf("create interactive qualification owner token: %v", err)
	}
	defer token.Close()
	ownerSID := requiredS4UOwnerSID(t)
	if err := validateOwnerToken(token, ownerSID); err != nil {
		t.Fatalf("interactive qualification token does not match owner %s: %v", ownerSID, err)
	}
	processUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || processUser == nil || processUser.User.Sid == nil || processUser.User.Sid.String() == ownerSID {
		t.Fatalf("qualification process identity must differ from impersonated owner %s: %v", ownerSID, err)
	}
	stopPrivileges, err := qualificationProfilePrivilegeScope()
	if err != nil {
		t.Fatalf("enable owner profile-load privileges: %v", err)
	}
	profile, loadErr := loadOwnerProfile(token, account, domain)
	privilegeErr := stopPrivileges()
	if loadErr != nil || privilegeErr != nil {
		cleanupErr := closeQualificationProfile(profile)
		t.Fatalf("load interactive qualification owner profile: %v", errors.Join(loadErr, privilegeErr, cleanupErr))
	}
	impersonationReverted := true
	defer func() {
		if !impersonationReverted {
			t.Error("owner profile could not be unloaded after impersonation reversion failed")
			return
		}
		if err := closeQualificationProfile(profile); err != nil {
			t.Errorf("unload interactive qualification owner profile: %v", err)
		}
	}()
	var impersonationToken windows.Token
	if err := windows.DuplicateTokenEx(token, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonationToken); err != nil {
		t.Fatalf("duplicate qualification impersonation token: %v", err)
	}
	defer impersonationToken.Close()
	runtime.LockOSThread()
	if err := windows.SetThreadToken(nil, impersonationToken); err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("impersonate qualification owner: %v", err)
	}
	impersonationReverted = false
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			t.Errorf("revert qualification owner impersonation: %v", err)
			return
		}
		impersonationReverted = true
		runtime.UnlockOSThread()
	}()
	action(token)
}

func assertQualificationKeyringOwner(t *testing.T, localAppData, ref, ownerSID string) {
	t.Helper()
	digest := sha256.Sum256([]byte(ref))
	path := filepath.Join(localAppData, "Paperboat", "credentials", hex.EncodeToString(digest[:])+".dpapi")
	sid, err := windows.StringToSid(ownerSID)
	if err != nil || !windowssecurity.OwnerMatchesSID(path, sid) {
		t.Fatalf("qualification keyring file is not owned by impersonated owner %s: %v", ownerSID, err)
	}
}

// TestNativePrepareS4UDPAPIQualification uses a real interactive logon token
// for the enrolled owner on a locked thread. Credential Manager rejects
// service, network, and S4U-only logons with ERROR_NO_SUCH_LOGON_SESSION. The
// harness process stays on the Session 0 runner identity so this phase has no
// inherited desktop or window-station dependency.
func TestNativePrepareS4UDPAPIQualification(t *testing.T) {
	withQualificationOwner(t, func(token windows.Token) {
		ownerSID := requiredS4UOwnerSID(t)
		var effectiveToken windows.Token
		if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &effectiveToken); err != nil {
			t.Fatalf("open effective owner token: %v", err)
		}
		effectiveUser, effectiveErr := effectiveToken.GetTokenUser()
		effectiveToken.Close()
		if effectiveErr != nil || effectiveUser == nil || effectiveUser.User.Sid == nil || effectiveUser.User.Sid.String() != ownerSID {
			t.Fatalf("fixture preparation is not impersonating enrolled owner %s: %v", ownerSID, effectiveErr)
		}
		localAppData, err := token.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
		if err != nil || !filepath.IsAbs(localAppData) {
			t.Fatalf("resolve enrolled owner LocalAppData: %v", err)
		}
		previousLocalAppData, hadLocalAppData := os.LookupEnv("LOCALAPPDATA")
		if err := os.Setenv("LOCALAPPDATA", filepath.Clean(localAppData)); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if hadLocalAppData {
				_ = os.Setenv("LOCALAPPDATA", previousLocalAppData)
			} else {
				_ = os.Unsetenv("LOCALAPPDATA")
			}
		}()
		reportPath := requiredS4UReportPath(t)
		workingDirectory, err := os.Getwd()
		if err != nil || !strings.EqualFold(filepath.Clean(workingDirectory), filepath.Dir(reportPath)) {
			t.Fatalf("owner preparation working directory = %q, want %q: %v", workingDirectory, filepath.Dir(reportPath), err)
		}
		probePath := reportPath + ".owner-access"
		if err := os.WriteFile(probePath, []byte("owner-access-v1"), 0o600); err != nil {
			t.Fatalf("write owner qualification access probe: %v", err)
		}
		if err := os.Remove(probePath); err != nil {
			t.Fatalf("remove owner qualification access probe: %v", err)
		}
		prepareProductionKeyringFixtures(t, reportPath, false)
		prepareS4UPreviewIdentityFixture(t, reportPath)
		assertQualificationKeyringOwner(t, localAppData, reportPath, ownerSID)
		assertQualificationKeyringOwner(t, localAppData, reportPath+"-migrated", ownerSID)
	})
}

// TestNativeOwnerCannotMutateS4UFixture runs as the enrolled owner after the
// privileged harness publishes the future LocalSystem executable. The owner
// may read and execute it, but cannot write, replace, rename, delete, or create
// a sibling in its trusted directory.
func TestNativeOwnerCannotMutateS4UFixture(t *testing.T) {
	withQualificationOwner(t, func(windows.Token) {
		fixture := requiredS4UFixture(t)
		if handle, err := os.OpenFile(fixture, os.O_WRONLY|os.O_TRUNC, 0); err == nil {
			handle.Close()
			t.Fatal("enrolled owner could truncate the future LocalSystem fixture")
		}
		replacement := fixture + ".owner-replacement"
		if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err == nil {
			t.Fatal("enrolled owner could create a sibling in the trusted fixture directory")
		}
		if err := os.Rename(fixture, replacement); err == nil {
			t.Fatal("enrolled owner could rename the future LocalSystem fixture")
		}
		if err := os.Remove(fixture); err == nil {
			t.Fatal("enrolled owner could delete the future LocalSystem fixture")
		}
		_ = requiredS4UFixture(t)
	})
}

// TestNativeLoggedOutS4UDPAPIQualification is the release gate for the exact
// cross-logon credential contract Paperboat relies on. An earlier real owner
// logon prepares machine-scope v2 DPAPI values behind the owner's strict ACL.
// This phase proves no interactive owner token is selectable and requires the
// actual LocalSystem -> enrolled-owner S4U child to decrypt them. It deliberately
// has no Git, Codex, EFS, or network dependency.
func TestNativeLoggedOutS4UDPAPIQualification(t *testing.T) {
	fixture := requiredS4UFixture(t)
	ownerSID := requiredS4UOwnerSID(t)
	if hasSelectableOwnerWTSToken(t, ownerSID) {
		t.Fatalf("owner %s has a selectable WTS token; logged-out DPAPI qualification did not run", ownerSID)
	}

	name := requiredS4UServiceName(t)
	reportPath := requiredS4UReportPath(t)
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatalf("connect SCM: %v", err)
	}
	defer manager.Disconnect()
	serviceHandle, err := manager.CreateService(name, fixture, mgr.Config{
		DisplayName:      name,
		Description:      "Paperboat native logged-out S4U DPAPI qualification fixture",
		StartType:        mgr.StartManual,
		ServiceStartName: "LocalSystem",
	}, "--paperboat-s4u-dpapi-service", "--service-name", name, "--owner-sid", ownerSID, "--report", reportPath)
	if err != nil {
		t.Fatalf("create S4U DPAPI qualification service: %v", err)
	}
	defer func() { _ = stopAndDeleteS4UService(serviceHandle) }()
	if err := serviceHandle.Start(); err != nil {
		t.Fatalf("start S4U DPAPI qualification service: %v", err)
	}
	if err := waitS4UServiceState(serviceHandle, svc.Running, 30*time.Second); err != nil {
		body, _ := os.ReadFile(reportPath + ".launch-error")
		t.Fatalf("%v: %s", err, strings.TrimSpace(string(body)))
	}
	record := waitS4UReport(t, reportPath, 30*time.Second)
	assertS4UDPAPIReport(t, record, ownerSID)

	if _, err := serviceHandle.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		t.Fatalf("stop S4U DPAPI qualification service: %v", err)
	}
	if err := waitS4UServiceState(serviceHandle, svc.Stopped, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	for _, pid := range []uint32{record.ChildPID, record.DescendantPID} {
		if err := waitS4UProcessExit(pid, 15*time.Second); err != nil {
			t.Fatalf("S4U Job Object cleanup for pid %d: %v", pid, err)
		}
	}
}

// TestNativeLoggedOutS4UFileSecretQualification is the focused regression for
// runtime-owned transfer keys. Unlike the owner-prepared KeyringStore gate, it
// requires the logged-out S4U child itself to create and reopen a fresh
// FileSecretStore value, matching the file-transfer receiver path.
func TestNativeLoggedOutS4UFileSecretQualification(t *testing.T) {
	fixture := requiredS4UFixture(t)
	ownerSID := requiredS4UOwnerSID(t)
	if hasSelectableOwnerWTSToken(t, ownerSID) {
		t.Fatalf("owner %s has a selectable WTS token; logged-out FileSecretStore qualification did not run", ownerSID)
	}

	name := fmt.Sprintf("PaperboatS4UFileSecret%d", os.Getpid())
	reportPath := filepath.Join(t.TempDir(), "s4u-file-secret-report.json")
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatalf("connect SCM: %v", err)
	}
	defer manager.Disconnect()
	serviceHandle, err := manager.CreateService(name, fixture, mgr.Config{
		DisplayName:      name,
		Description:      "Paperboat native logged-out S4U FileSecretStore qualification fixture",
		StartType:        mgr.StartManual,
		ServiceStartName: "LocalSystem",
	}, "--paperboat-s4u-dpapi-service", "--service-name", name, "--owner-sid", ownerSID, "--report", reportPath)
	if err != nil {
		t.Fatalf("create S4U FileSecretStore qualification service: %v", err)
	}
	defer func() { _ = stopAndDeleteS4UService(serviceHandle) }()
	if err := serviceHandle.Start(); err != nil {
		t.Fatalf("start S4U FileSecretStore qualification service: %v", err)
	}
	if err := waitS4UServiceState(serviceHandle, svc.Running, 30*time.Second); err != nil {
		body, _ := os.ReadFile(reportPath + ".launch-error")
		t.Fatalf("%v: %s", err, strings.TrimSpace(string(body)))
	}
	record := waitS4UReport(t, reportPath, 30*time.Second)
	if record.OwnerSID != ownerSID || record.SessionID != 0 || !record.JobCleanupExpected {
		t.Fatalf("invalid logged-out S4U FileSecretStore report: %+v", record)
	}
	if record.Limitations.FileSecretStore.Status != "pass" || strings.TrimSpace(record.Limitations.FileSecretStore.Reason) == "" {
		t.Fatalf("logged-out S4U must write and read a fresh FileSecretStore credential: %+v", record.Limitations.FileSecretStore)
	}

	if _, err := serviceHandle.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		t.Fatalf("stop S4U FileSecretStore qualification service: %v", err)
	}
	if err := waitS4UServiceState(serviceHandle, svc.Stopped, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	for _, pid := range []uint32{record.ChildPID, record.DescendantPID} {
		if err := waitS4UProcessExit(pid, 15*time.Second); err != nil {
			t.Fatalf("S4U Job Object cleanup for pid %d: %v", pid, err)
		}
	}
}

func assertS4UDPAPIReport(t *testing.T, record s4uQualificationReport, ownerSID string) {
	t.Helper()
	if record.Schema != "paperboat.windows-s4u-qualification/v1" || record.OwnerSID != ownerSID || record.ChildPID == 0 || record.DescendantPID == 0 || record.ChildPID == record.DescendantPID || record.SessionID != 0 {
		t.Fatalf("invalid logged-out S4U DPAPI report: %+v", record)
	}
	if !record.Profile.Exists || !filepath.IsAbs(record.Profile.Home) || !strings.EqualFold(record.Profile.Home, record.Profile.UserProfile) || record.Environment.OwnerWorkload != "1" {
		t.Fatalf("S4U owner profile was not loaded correctly: %+v", record)
	}
	if !record.JobCleanupExpected {
		t.Fatal("S4U DPAPI fixture did not declare kill-on-close Job Object ownership")
	}
	if record.Limitations.DPAPI.Status != "pass" || strings.TrimSpace(record.Limitations.DPAPI.Reason) == "" {
		t.Fatalf("logged-out S4U must decrypt the owner DPAPI credential: %+v", record.Limitations.DPAPI)
	}
	if record.Limitations.DPAPIMigration.Status != "pass" || strings.TrimSpace(record.Limitations.DPAPIMigration.Reason) == "" {
		t.Fatalf("logged-out S4U must read the owner-migrated Credential Manager credential through KeyringStore: %+v", record.Limitations.DPAPIMigration)
	}
	if record.Limitations.FileSecretStore.Status != "pass" || strings.TrimSpace(record.Limitations.FileSecretStore.Reason) == "" {
		t.Fatalf("logged-out S4U must write and read a fresh FileSecretStore credential: %+v", record.Limitations.FileSecretStore)
	}
	for _, result := range []struct {
		name   string
		status string
		reason string
	}{
		{name: "identity_open", status: record.Limitations.PreviewIdentityOpen.Status, reason: record.Limitations.PreviewIdentityOpen.Reason},
		{name: "registration", status: record.Limitations.PreviewRegistration.Status, reason: record.Limitations.PreviewRegistration.Reason},
		{name: "machine_control_source", status: record.Limitations.PreviewMachineControlSource.Status, reason: record.Limitations.PreviewMachineControlSource.Reason},
		{name: "machine_control_token", status: record.Limitations.PreviewMachineControlToken.Status, reason: record.Limitations.PreviewMachineControlToken.Reason},
	} {
		if result.status != "pass" || strings.TrimSpace(result.reason) == "" {
			t.Fatalf("logged-out S4U preview stage %s did not pass: status=%q reason=%q", result.name, result.status, result.reason)
		}
	}
}

type s4uQualificationReport struct {
	Schema        string `json:"schema"`
	OwnerSID      string `json:"owner_sid"`
	ChildPID      uint32 `json:"child_pid"`
	DescendantPID uint32 `json:"descendant_pid"`
	SessionID     uint32 `json:"session_id"`
	Profile       struct {
		Home         string `json:"home"`
		Exists       bool   `json:"exists"`
		UserProfile  string `json:"userprofile"`
		AppData      string `json:"appdata"`
		LocalAppData string `json:"localappdata"`
	} `json:"profile"`
	Environment struct {
		OwnerWorkload string `json:"owner_workload"`
	} `json:"environment"`
	JobCleanupExpected bool `json:"job_cleanup_expected"`
	Limitations        struct {
		SMB struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"smb"`
		DPAPI struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"dpapi"`
		DPAPIMigration struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"dpapi_credential_manager_migration"`
		FileSecretStore struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"file_secret_store"`
		EFS struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"efs"`
		Git struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"git"`
		Network struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"network"`
		Codex struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"codex"`
		PreviewIdentityOpen struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"preview_identity_open"`
		PreviewRegistration struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"preview_registration"`
		PreviewMachineControlSource struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"preview_machine_control_source"`
		PreviewMachineControlToken struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"preview_machine_control_token"`
	} `json:"limitations"`
}

// TestNativeLoggedOutS4UQualification must be run from an elevated native
// Windows test process with a deliberately logged-out enrolled owner. It
// refuses to certify a WTS-backed launch, then exercises the actual SCM ->
// RunWindowsService -> CreateProcessAsUser(S4U) path and its kill-on-close Job.
//
// Build the fixture first:
//
//	go build -o s4u-fixture.exe ./internal/hostruntime/service/testdata/s4u-fixture
//	$env:PAPERBOAT_WINDOWS_E2E_S4U_FIXTURE = (Resolve-Path .\s4u-fixture.exe)
//	go test -tags paperboat_native_e2e ./internal/hostruntime/service -run TestNativeLoggedOutS4UQualification
func TestNativeLoggedOutS4UQualification(t *testing.T) {
	fixture := requiredS4UFixture(t)
	ownerSID := requiredS4UOwnerSID(t)
	if hasSelectableOwnerWTSToken(t, ownerSID) {
		t.Fatalf("owner %s has a selectable WTS token; log the owner out before S4U qualification", ownerSID)
	}

	name := fmt.Sprintf("PaperboatS4UQualification%d", os.Getpid())
	reportPath := filepath.Join(t.TempDir(), "s4u-report.json")
	prepareProductionKeyringFixtures(t, reportPath, true)
	if err := os.WriteFile(reportPath+".efs", []byte("paperboat-s4u-efs-v1"), 0o600); err != nil {
		t.Fatalf("write owner EFS fixture: %v", err)
	}
	repository := reportPath + ".git"
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", repository}, {"-C", repository, "config", "user.name", "Paperboat"}, {"-C", repository, "config", "user.email", "paperboat@example.invalid"}} {
		if output, err := exec.Command(`C:\Program Files\Git\cmd\git.exe`, args...).CombinedOutput(); err != nil {
			t.Fatalf("prepare Git fixture: %v: %s", err, output)
		}
	}
	if err := os.WriteFile(filepath.Join(repository, "fixture.txt"), []byte("paperboat\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"-C", repository, "add", "fixture.txt"}, {"-C", repository, "commit", "-m", "qualification"}} {
		if output, err := exec.Command(`C:\Program Files\Git\cmd\git.exe`, args...).CombinedOutput(); err != nil {
			t.Fatalf("commit Git fixture: %v: %s", err, output)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start network fixture: %v", err)
	}
	defer listener.Close()
	if err := os.WriteFile(reportPath+".network", []byte(listener.Addr().String()), 0o600); err != nil {
		t.Fatal(err)
	}
	codexPath := os.Getenv("PAPERBOAT_WINDOWS_E2E_CODEX_PATH")
	if !filepath.IsAbs(codexPath) || !strings.EqualFold(filepath.Ext(codexPath), ".exe") {
		t.Fatal("PAPERBOAT_WINDOWS_E2E_CODEX_PATH must name an absolute native Codex .exe")
	}
	if err := os.WriteFile(reportPath+".codex-path", []byte(codexPath), 0o600); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			acceptErr = connection.Close()
		}
		accepted <- acceptErr
	}()
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatalf("connect SCM: %v", err)
	}
	defer manager.Disconnect()
	serviceHandle, err := manager.CreateService(name, fixture, mgr.Config{
		DisplayName:      name,
		Description:      "Paperboat native logged-out S4U qualification fixture",
		StartType:        mgr.StartManual,
		ServiceStartName: "LocalSystem",
	}, "--paperboat-s4u-service", "--service-name", name, "--owner-sid", ownerSID, "--report", reportPath)
	if err != nil {
		t.Fatalf("create S4U qualification service: %v", err)
	}
	defer func() {
		_ = stopAndDeleteS4UService(serviceHandle)
	}()
	if err := serviceHandle.Start(); err != nil {
		t.Fatalf("start S4U qualification service: %v", err)
	}
	if err := waitS4UServiceState(serviceHandle, svc.Running, 30*time.Second); err != nil {
		body, _ := os.ReadFile(reportPath + ".launch-error")
		t.Fatalf("%v: %s", err, strings.TrimSpace(string(body)))
	}
	record := waitS4UReport(t, reportPath, 30*time.Second)
	assertS4UReport(t, record, ownerSID)
	if err := <-accepted; err != nil {
		t.Fatalf("accept logged-out S4U network probe: %v", err)
	}

	if _, err := serviceHandle.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		t.Fatalf("stop S4U qualification service: %v", err)
	}
	if err := waitS4UServiceState(serviceHandle, svc.Stopped, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	for _, pid := range []uint32{record.ChildPID, record.DescendantPID} {
		if err := waitS4UProcessExit(pid, 15*time.Second); err != nil {
			t.Fatalf("S4U Job Object cleanup for pid %d: %v", pid, err)
		}
	}
}

func requiredS4UFixture(t *testing.T) string {
	t.Helper()
	path := os.Getenv(s4uFixturePathEnvironment)
	if path == "" {
		t.Fatalf("%s is required", s4uFixturePathEnvironment)
	}
	absolute, err := filepath.Abs(path)
	if err != nil || !strings.EqualFold(filepath.Ext(absolute), ".exe") {
		t.Fatalf("S4U fixture must be an absolute .exe: %q", path)
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("S4U fixture is not a regular file: %q: %v", absolute, err)
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(absolute))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		t.Fatalf("S4U fixture is a reparse point: %q: %v", absolute, err)
	}
	body, err := os.ReadFile(absolute)
	if err != nil {
		t.Fatalf("read S4U fixture: %v", err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(body))
	expectedDigest := strings.ToLower(strings.TrimSpace(os.Getenv(s4uFixtureSHA256Environment)))
	if len(expectedDigest) != sha256.Size*2 || digest != expectedDigest {
		t.Fatalf("S4U fixture SHA256 = %q, want %q", digest, expectedDigest)
	}
	return absolute
}

func requiredS4UOwnerSID(t *testing.T) string {
	t.Helper()
	value := os.Getenv("PAPERBOAT_WINDOWS_E2E_S4U_OWNER_SID")
	sid, err := windows.StringToSid(value)
	if value == "" || err != nil || sid == nil || sid.String() != value {
		t.Fatalf("PAPERBOAT_WINDOWS_E2E_S4U_OWNER_SID must be an enrolled Windows SID")
	}
	return value
}

func requiredS4UReportPath(t *testing.T) string {
	t.Helper()
	path := os.Getenv(s4uReportPathEnvironment)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		t.Fatalf("%s must be an absolute clean path", s4uReportPathEnvironment)
	}
	return path
}

func requiredS4UServiceName(t *testing.T) string {
	t.Helper()
	name := os.Getenv(s4uServiceNameEnvironment)
	if len(name) < len("PaperboatS4UDPAPI-")+8 || len(name) > 80 || !strings.HasPrefix(name, "PaperboatS4UDPAPI-") {
		t.Fatalf("%s must be a bounded Paperboat qualification service name", s4uServiceNameEnvironment)
	}
	for _, r := range name {
		if r != '-' && (r < '0' || r > '9') && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			t.Fatalf("%s contains an invalid character", s4uServiceNameEnvironment)
		}
	}
	return name
}

func hasSelectableOwnerWTSToken(t *testing.T, ownerSID string) bool {
	t.Helper()
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		t.Fatalf("enumerate WTS sessions: %v", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	if sessions == nil {
		return false
	}
	for _, candidate := range unsafe.Slice(sessions, int(count)) {
		if sessionPriority(candidate.State) > 2 {
			continue
		}
		var token windows.Token
		if err := windows.WTSQueryUserToken(candidate.SessionID, &token); err != nil {
			continue
		}
		user, userErr := token.GetTokenUser()
		_ = token.Close()
		if userErr == nil && user != nil && user.User.Sid != nil && user.User.Sid.String() == ownerSID {
			return true
		}
	}
	return false
}

func waitS4UReport(t *testing.T, path string, timeout time.Duration) s4uQualificationReport {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		body, err := os.ReadFile(path)
		if err == nil {
			var record s4uQualificationReport
			if err := json.Unmarshal(body, &record); err != nil {
				t.Fatalf("decode S4U report: %v", err)
			}
			return record
		}
		if !errors.Is(err, os.ErrNotExist) || time.Now().After(deadline) {
			t.Fatalf("wait for S4U child report: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func assertS4UReport(t *testing.T, record s4uQualificationReport, ownerSID string) {
	t.Helper()
	if record.Schema != "paperboat.windows-s4u-qualification/v1" || record.OwnerSID != ownerSID || record.ChildPID == 0 || record.DescendantPID == 0 || record.ChildPID == record.DescendantPID || record.SessionID != 0 {
		t.Fatalf("invalid logged-out S4U report: %+v", record)
	}
	if !record.Profile.Exists || !filepath.IsAbs(record.Profile.Home) || filepath.Clean(record.Profile.Home) != record.Profile.Home || !strings.EqualFold(record.Profile.Home, record.Profile.UserProfile) || !filepath.IsAbs(record.Profile.AppData) || !filepath.IsAbs(record.Profile.LocalAppData) || record.Environment.OwnerWorkload != "1" {
		t.Fatalf("S4U profile/environment was not loaded correctly: %+v", record)
	}
	if !record.JobCleanupExpected {
		t.Fatal("S4U fixture did not declare kill-on-close Job Object ownership")
	}
	if record.Limitations.SMB.Status != "not_qualified" || strings.TrimSpace(record.Limitations.SMB.Reason) == "" {
		t.Fatalf("SMB limitation is not reported honestly: %+v", record.Limitations.SMB)
	}
	if record.Limitations.DPAPI.Status != "pass" || strings.TrimSpace(record.Limitations.DPAPI.Reason) == "" {
		t.Fatalf("logged-out S4U must decrypt the owner DPAPI credential: %+v", record.Limitations.DPAPI)
	}
	if record.Limitations.DPAPIMigration.Status != "pass" || strings.TrimSpace(record.Limitations.DPAPIMigration.Reason) == "" {
		t.Fatalf("logged-out S4U must read the owner-migrated Credential Manager credential through KeyringStore: %+v", record.Limitations.DPAPIMigration)
	}
	if record.Limitations.FileSecretStore.Status != "pass" || strings.TrimSpace(record.Limitations.FileSecretStore.Reason) == "" {
		t.Fatalf("logged-out S4U must write and read a fresh FileSecretStore credential: %+v", record.Limitations.FileSecretStore)
	}
	for name, result := range map[string]struct{ Status, Reason string }{"EFS": {record.Limitations.EFS.Status, record.Limitations.EFS.Reason}, "Git": {record.Limitations.Git.Status, record.Limitations.Git.Reason}, "network": {record.Limitations.Network.Status, record.Limitations.Network.Reason}, "Codex": {record.Limitations.Codex.Status, record.Limitations.Codex.Reason}} {
		if result.Status != "pass" {
			t.Errorf("logged-out S4U %s result: %s: %s", name, result.Status, result.Reason)
		} else {
			t.Logf("logged-out S4U %s result: %s: %s", name, result.Status, result.Reason)
		}
	}
	t.Logf("logged-out S4U DPAPI result: %s: %s", record.Limitations.DPAPI.Status, record.Limitations.DPAPI.Reason)
}

func waitS4UServiceState(serviceHandle *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		status, err := serviceHandle.Query()
		if err != nil {
			return err
		}
		if status.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("S4U qualification service state=%d, want=%d", status.State, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func waitS4UProcessExit(pid uint32, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil
		}
		if err != nil {
			return err
		}
		result, waitErr := windows.WaitForSingleObject(process, 0)
		_ = windows.Close(process)
		if waitErr != nil {
			return waitErr
		}
		if result == windows.WAIT_OBJECT_0 {
			return nil
		}
		if result != uint32(windows.WAIT_TIMEOUT) {
			return fmt.Errorf("wait for pid %d returned %d", pid, result)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("pid %d remained alive after timeout", pid)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func stopAndDeleteS4UService(serviceHandle *mgr.Service) error {
	if serviceHandle == nil {
		return nil
	}
	if _, err := serviceHandle.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	if err := serviceHandle.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return err
	}
	return serviceHandle.Close()
}
