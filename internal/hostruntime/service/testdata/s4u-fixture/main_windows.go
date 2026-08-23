//go:build windows

// paperboat-s4u-fixture is a native-only SCM qualification helper. It is not
// shipped with Paperboat. The parent process is LocalSystem, while its child
// is launched by service.RunWindowsService through the enrolled owner's S4U
// token. Keeping this in a separate executable prevents a test-only entry
// point from becoming part of a production binary.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/config"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	"golang.org/x/sys/windows"
)

const (
	serviceMode      = "--paperboat-s4u-service"
	dpapiServiceMode = "--paperboat-s4u-dpapi-service"
	childMode        = "--paperboat-s4u-child"
	dpapiChildMode   = "--paperboat-s4u-dpapi-child"
	descendantMode   = "--paperboat-s4u-descendant"
	nameFlag         = "--service-name"
	ownerSIDFlag     = "--owner-sid"
	reportFlag       = "--report"
)

type report struct {
	Schema             string      `json:"schema"`
	OwnerSID           string      `json:"owner_sid"`
	ChildPID           uint32      `json:"child_pid"`
	DescendantPID      uint32      `json:"descendant_pid"`
	SessionID          uint32      `json:"session_id"`
	Profile            profile     `json:"profile"`
	Environment        environment `json:"environment"`
	JobCleanupExpected bool        `json:"job_cleanup_expected"`
	Limitations        limitations `json:"limitations"`
}

type profile struct {
	Home         string `json:"home"`
	Exists       bool   `json:"exists"`
	UserProfile  string `json:"userprofile"`
	AppData      string `json:"appdata"`
	LocalAppData string `json:"localappdata"`
}

type environment struct {
	OwnerWorkload string `json:"owner_workload"`
}

// limitations deliberately report only what this S4U fixture establishes.
// A loaded profile is not evidence that the user's DPAPI master keys can be
// unlocked, and a local S4U logon is not evidence of credentialed SMB access.
type limitations struct {
	SMB            limitation `json:"smb"`
	DPAPI          limitation `json:"dpapi"`
	DPAPIMigration limitation `json:"dpapi_credential_manager_migration"`
	EFS            limitation `json:"efs"`
	Git            limitation `json:"git"`
	Network        limitation `json:"network"`
	Codex          limitation `json:"codex"`
}

type limitation struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

func main() {
	mode, name, ownerSID, reportPath, err := parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	switch mode {
	case serviceMode, dpapiServiceMode:
		executable, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		child := childMode
		if mode == dpapiServiceMode {
			child = dpapiChildMode
		}
		err = service.RunWindowsService(service.ServiceEntryConfig{
			Name:        name,
			Executable:  executable,
			Arguments:   []string{child, ownerSIDFlag, ownerSID, reportFlag, reportPath},
			EnrolledSID: ownerSID,
			Environment: map[string]string{"PAPERBOAT_S4U_QUALIFICATION": "1"},
			LaunchFailure: func(launchErr error) {
				_ = os.WriteFile(reportPath+".launch-error", []byte(launchErr.Error()), 0o600)
			},
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case childMode, dpapiChildMode:
		if err := writeChildReport(ownerSID, reportPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		holdForJobCleanup()
	case descendantMode:
		holdForJobCleanup()
	default:
		fmt.Fprintln(os.Stderr, "missing Paperboat S4U qualification mode")
		os.Exit(2)
	}
}

func holdForJobCleanup() {
	select {}
}

func parse(args []string) (mode, name, ownerSID, reportPath string, err error) {
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case serviceMode, dpapiServiceMode, childMode, dpapiChildMode, descendantMode:
			if mode != "" {
				return "", "", "", "", errors.New("multiple Paperboat S4U qualification modes")
			}
			mode = args[index]
		case nameFlag, ownerSIDFlag, reportFlag:
			if index+1 >= len(args) {
				return "", "", "", "", fmt.Errorf("%s requires a value", args[index])
			}
			value := args[index+1]
			index++
			switch args[index-1] {
			case nameFlag:
				name = value
			case ownerSIDFlag:
				ownerSID = value
			case reportFlag:
				reportPath = value
			}
		default:
			return "", "", "", "", fmt.Errorf("unknown Paperboat S4U qualification argument %q", args[index])
		}
	}
	if mode == "" || ownerSID == "" || strings.ContainsAny(ownerSID, "\x00\r\n") {
		return "", "", "", "", errors.New("a valid Paperboat S4U owner SID is required")
	}
	sid, sidErr := windows.StringToSid(ownerSID)
	if sidErr != nil || sid == nil || sid.String() != ownerSID {
		return "", "", "", "", errors.New("a valid Paperboat S4U owner SID is required")
	}
	if mode == serviceMode && (name == "" || strings.ContainsAny(name, "\\/\x00\r\n")) {
		return "", "", "", "", errors.New("a valid SCM service name is required")
	}
	if mode != descendantMode && (!filepath.IsAbs(reportPath) || filepath.Clean(reportPath) != reportPath || strings.ContainsAny(reportPath, "\x00\r\n")) {
		return "", "", "", "", errors.New("an absolute report path is required")
	}
	return mode, name, ownerSID, reportPath, nil
}

func writeChildReport(ownerSID, reportPath string) error {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || user.User.Sid.String() != ownerSID {
		return errors.New("S4U child is not running as the enrolled owner SID")
	}
	home, err := token.KnownFolderPath(windows.FOLDERID_Profile, windows.KF_FLAG_DEFAULT)
	if err != nil || !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return fmt.Errorf("resolve enrolled owner profile: %w", err)
	}
	info, err := os.Stat(home)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("loaded owner profile is unavailable: %w", err)
	}
	for _, key := range []string{"USERPROFILE", "APPDATA", "LOCALAPPDATA"} {
		value := os.Getenv(key)
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("owner environment %s is missing or invalid", key)
		}
	}
	if !strings.EqualFold(filepath.Clean(os.Getenv("USERPROFILE")), home) {
		return errors.New("owner USERPROFILE does not match the loaded profile")
	}
	if os.Getenv("PAPERBOAT_S4U_QUALIFICATION") != "1" {
		return errors.New("Paperboat S4U child environment marker is missing")
	}
	var sessionID uint32
	if err := windows.ProcessIdToSessionId(uint32(os.Getpid()), &sessionID); err != nil {
		return err
	}
	// Local S4U uses a service session, not an interactive WTS session. The
	// native test separately confirms that no selectable owner WTS token exists.
	if sessionID != 0 {
		return fmt.Errorf("S4U child session=%d, want service session 0", sessionID)
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	descendant := exec.Command(executable, descendantMode, ownerSIDFlag, ownerSID)
	if err := descendant.Start(); err != nil {
		return fmt.Errorf("start S4U descendant: %w", err)
	}
	dpapi := limitation{Status: "fail", Reason: "logged-out S4U could not read the owner-created Paperboat KeyringStore credential"}
	if cleartext, readErr := (config.KeyringStore{}).Get(reportPath); readErr != nil {
		dpapi.Reason += ": " + readErr.Error()
	} else if cleartext != "paperboat-s4u-dpapi-v1" {
		dpapi.Reason += ": credential value did not match"
	} else {
		dpapi = limitation{Status: "pass", Reason: "logged-out S4U read the owner-created Paperboat KeyringStore credential from the production owner LocalAppData DPAPI store"}
	}
	dpapiMigration := limitation{Status: "fail", Reason: "logged-out S4U could not read the owner-migrated Credential Manager credential from Paperboat KeyringStore"}
	if cleartext, readErr := (config.KeyringStore{}).Get(reportPath + "-migrated"); readErr != nil {
		dpapiMigration.Reason += ": " + readErr.Error()
	} else if cleartext != "paperboat-s4u-migrated-v1" {
		dpapiMigration.Reason += ": credential value did not match"
	} else {
		dpapiMigration = limitation{Status: "pass", Reason: "logged-out S4U read the Credential Manager credential after owner migration to the production LocalAppData DPAPI store"}
	}
	efs := limitation{Status: "fail", Reason: "logged-out S4U could not read the owner-encrypted EFS fixture"}
	if output, encryptErr := exec.Command("cipher.exe", "/E", "/A", reportPath+".efs").CombinedOutput(); encryptErr != nil {
		efs.Reason += ": encrypt: " + encryptErr.Error() + ": " + strings.TrimSpace(string(output))
	} else if cleartext, readErr := os.ReadFile(reportPath + ".efs"); readErr != nil {
		efs.Reason += ": " + readErr.Error()
	} else if string(cleartext) != "paperboat-s4u-efs-v1" {
		efs.Reason += ": value did not match"
	} else {
		efs = limitation{Status: "pass", Reason: "logged-out S4U read the owner-encrypted EFS fixture"}
	}
	git := limitation{Status: "fail", Reason: "logged-out S4U could not execute native Git against the owner repository"}
	gitCommand := exec.Command(`C:\Program Files\Git\cmd\git.exe`, "-C", reportPath+".git", "rev-parse", "--verify", "HEAD")
	if output, gitErr := gitCommand.Output(); gitErr != nil {
		git.Reason += ": " + gitErr.Error()
	} else if len(strings.TrimSpace(string(output))) != 40 {
		git.Reason += ": malformed commit identifier"
	} else {
		git = limitation{Status: "pass", Reason: "logged-out S4U executed native Git and read the owner repository"}
	}
	network := limitation{Status: "fail", Reason: "logged-out S4U could not establish outbound TCP"}
	if address, readErr := os.ReadFile(reportPath + ".network"); readErr != nil {
		network.Reason += ": " + readErr.Error()
	} else if connection, dialErr := net.DialTimeout("tcp", strings.TrimSpace(string(address)), 5*time.Second); dialErr != nil {
		network.Reason += ": " + dialErr.Error()
	} else {
		_ = connection.Close()
		network = limitation{Status: "pass", Reason: "logged-out S4U established outbound TCP with the owner environment"}
	}
	codex := limitation{Status: "fail", Reason: "logged-out S4U could not execute native Codex"}
	if codexPath, readErr := os.ReadFile(reportPath + ".codex-path"); readErr != nil {
		codex.Reason += ": " + readErr.Error()
	} else if output, codexErr := exec.Command(strings.TrimSpace(string(codexPath)), "--version").CombinedOutput(); codexErr != nil {
		codex.Reason += ": " + codexErr.Error() + ": " + strings.TrimSpace(string(output))
	} else if !strings.HasPrefix(strings.TrimSpace(string(output)), "codex-cli ") {
		codex.Reason += ": malformed version output"
	} else {
		codex = limitation{Status: "pass", Reason: "logged-out S4U executed the supported native Codex binary"}
	}
	record := report{
		Schema:             "paperboat.windows-s4u-qualification/v1",
		OwnerSID:           ownerSID,
		ChildPID:           uint32(os.Getpid()),
		DescendantPID:      uint32(descendant.Process.Pid),
		SessionID:          sessionID,
		Profile:            profile{Home: home, Exists: true, UserProfile: os.Getenv("USERPROFILE"), AppData: os.Getenv("APPDATA"), LocalAppData: os.Getenv("LOCALAPPDATA")},
		Environment:        environment{OwnerWorkload: os.Getenv("PAPERBOAT_S4U_QUALIFICATION")},
		JobCleanupExpected: true,
		Limitations: limitations{
			SMB:            limitation{Status: "not_qualified", Reason: "S4U does not retain reusable user network credentials; credentialed SMB requires a separate native qualification."},
			DPAPI:          dpapi,
			DPAPIMigration: dpapiMigration,
			EFS:            efs,
			Git:            git,
			Network:        network,
			Codex:          codex,
		},
	}
	if err := writeReport(reportPath, record); err != nil {
		return err
	}
	return nil
}

func writeReport(path string, value report) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	//paperboat:allow-source-policy atomic-replacement owner=windows-s4u-qualification reason=same-directory-report-staging
	temporary, err := os.CreateTemp(directory, ".paperboat-s4u-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=windows-s4u-qualification reason=same-directory-report-publication
	return os.Rename(temporaryPath, path)
}
