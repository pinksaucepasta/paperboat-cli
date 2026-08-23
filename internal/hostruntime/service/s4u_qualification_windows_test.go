//go:build windows && paperboat_native_e2e

package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/config"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const s4uFixturePathEnvironment = "PAPERBOAT_WINDOWS_E2E_S4U_FIXTURE"

var qualificationCredWrite = windows.NewLazySystemDLL("advapi32.dll").NewProc("CredWriteW")

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

func prepareProductionKeyringFixtures(t *testing.T, reportPath string) {
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
	t.Cleanup(func() {
		_ = keyring.Delete(reportPath)
		_ = keyring.Delete(migratedRef)
	})
}

// TestNativeLoggedOutS4UDPAPIQualification is the release gate for the exact
// cross-logon credential contract Paperboat relies on. The test process writes
// a user-scoped DPAPI value, proves that no interactive owner token is
// selectable, and requires the actual LocalSystem -> enrolled-owner S4U child
// to decrypt it. It deliberately has no Git, Codex, EFS, or network dependency.
func TestNativeLoggedOutS4UDPAPIQualification(t *testing.T) {
	fixture := requiredS4UFixture(t)
	ownerSID := requiredS4UOwnerSID(t)
	if hasSelectableOwnerWTSToken(t, ownerSID) {
		t.Fatalf("owner %s has a selectable WTS token; logged-out DPAPI qualification did not run", ownerSID)
	}

	name := fmt.Sprintf("PaperboatS4UDPAPIQualification%d", os.Getpid())
	reportPath := filepath.Join(t.TempDir(), "s4u-dpapi-report.json")
	prepareProductionKeyringFixtures(t, reportPath)
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
	prepareProductionKeyringFixtures(t, reportPath)
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
	info, err := os.Stat(absolute)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("S4U fixture is not a regular file: %q: %v", absolute, err)
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
