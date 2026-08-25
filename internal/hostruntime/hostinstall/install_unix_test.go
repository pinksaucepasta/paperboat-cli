//go:build darwin || linux

package hostinstall

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
)

func TestDecodeRejectsUnknownAndTrailingFields(t *testing.T) {
	for _, input := range []string{
		`{"schema":"paperboat.host-install/v1","command":"sh"}`,
		`{"schema":"paperboat.host-install/v1"} {}`,
	} {
		if _, err := Decode(bytes.NewBufferString(input)); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("input accepted: %s: %v", input, err)
		}
	}
}

func TestRemoveInstalledFilesDeletesOnlyAllowlistedHostState(t *testing.T) {
	root, state := filepath.Join(t.TempDir(), "install"), filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := installPaths{root: root, installerState: state, runtimeState: state, worker: filepath.Join(root, "pb"), metadata: filepath.Join(state, "install-metadata.json")}
	updateRoot := filepath.Join(state, "privileged-updates")
	if err := os.Mkdir(updateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	removed := []string{paths.worker, paths.metadata, filepath.Join(state, "power-baseline.json"), filepath.Join(state, "availability-policy.json"), filepath.Join(state, "update-current.json"), filepath.Join(state, "update-journal.json"), filepath.Join(state, "update-rollbacks.json"), filepath.Join(updateRoot, "update-current.json"), filepath.Join(updateRoot, "update-journal.json"), filepath.Join(updateRoot, "update-rollbacks.json")}
	for _, path := range removed {
		if err := os.WriteFile(path, []byte("owned"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	unrelated := filepath.Join(state, "unrelated")
	if err := os.WriteFile(unrelated, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeInstalledFiles(paths); err != nil {
		t.Fatal(err)
	}
	for _, path := range removed {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("allowlisted path retained: %s (%v)", path, err)
		}
	}
	if _, err := os.Lstat(updateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("privileged update directory retained: %v", err)
	}
	if body, err := os.ReadFile(unrelated); err != nil || string(body) != "preserve" {
		t.Fatalf("unrelated file changed: %q, %v", body, err)
	}
}

func TestPlatformPathsKeepLinuxInstallerStateOutsideSystemdStateDirectory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("systemd path contract is Linux-specific")
	}
	paths := platformPaths()
	if paths.installerState == paths.runtimeState || filepath.Dir(paths.journal) != paths.installerState || filepath.Dir(paths.metadata) != paths.installerState {
		t.Fatalf("installer state overlaps runtime state: %+v", paths)
	}
	if paths.legacyMetadata != filepath.Join(paths.runtimeState, "install-metadata.json") {
		t.Fatalf("legacy metadata path=%q", paths.legacyMetadata)
	}
}

func TestLoadInstallMetadataPreservesNotExist(t *testing.T) {
	_, err := loadInstallMetadata(filepath.Join(t.TempDir(), "missing.json"), os.Getuid())
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error=%v", err)
	}
}

func TestValidateBindsSignedArtifactAndInvokingUID(t *testing.T) {
	request := validRequest(t)
	if err := Validate(request, request.UID); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Request){
		"wrong invoking uid": func(r *Request) { r.UID++ },
		"network listener":   func(r *Request) { r.HelperListenAddress = "0.0.0.0:8080" },
		"control downgrade":  func(r *Request) { r.ControlURL = "http://control.example.test" },
		"relative state":     func(r *Request) { r.StateRoot = "state" },
		"environment path":   func(r *Request) { r.Path += "\nLD_PRELOAD=/tmp/x" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			if err := Validate(changed, request.UID); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	if err := os.WriteFile(request.Executable, []byte("tampered"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Validate(request, request.UID); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("tampered artifact error=%v", err)
	}
}

func TestValidRunIdentityAllowsOnlyNormalUsersOrRoot(t *testing.T) {
	for _, test := range []struct {
		name    string
		request Request
		want    bool
	}{
		{name: "normal user", request: Request{User: "alice", UID: 1000, GID: 1000}, want: true},
		{name: "root", request: Request{User: "root", UID: 0, GID: 0}, want: true},
		{name: "zero uid non-root", request: Request{User: "alice", UID: 0, GID: 0}},
		{name: "root name with non-root ids", request: Request{User: "root", UID: 1000, GID: 1000}, want: true},
		{name: "zero group", request: Request{User: "alice", UID: 1000, GID: 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validRunIdentity(test.request); got != test.want {
				t.Fatalf("validRunIdentity()=%v want %v", got, test.want)
			}
		})
	}
}

func TestValidateRejectsSymlinkedArtifact(t *testing.T) {
	request := validRequest(t)
	link := filepath.Join(t.TempDir(), "pb")
	if err := os.Symlink(request.Executable, link); err != nil {
		t.Fatal(err)
	}
	request.Executable = link
	if err := Validate(request, request.UID); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("symlink error=%v", err)
	}
}

func validRequest(t *testing.T) Request {
	t.Helper()
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	group, err := user.LookupGroupId(account.Gid)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 32)
	if runtime.GOOS == "linux" {
		copy(body, "\x7fELF")
		body[4], body[5] = 2, 1
		machine := uint16(62)
		if runtime.GOARCH == "arm64" {
			machine = 183
		}
		binary.LittleEndian.PutUint16(body[18:20], machine)
	} else {
		binary.LittleEndian.PutUint32(body[:4], 0xfeedfacf)
		cpu := uint32(0x01000007)
		if runtime.GOARCH == "arm64" {
			cpu = 0x0100000c
		}
		binary.LittleEndian.PutUint32(body[4:8], cpu)
	}
	executable := filepath.Join(t.TempDir(), "pb")
	if err := os.WriteFile(executable, body, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := bootstrap.ArtifactTarget{Schema: bootstrap.ArtifactTargetSchemaV1, Kind: bootstrap.ArtifactKindPB, Version: "test", Platform: runtime.GOOS, Architecture: runtime.GOARCH, RepositoryURL: "https://updates.example.test/paperboat", TargetPath: releaseindex.AssetName(runtime.GOOS, runtime.GOARCH)}
	state := t.TempDir()
	state, err = filepath.EvalSymlinks(state)
	if err != nil {
		t.Fatal(err)
	}
	shell, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	return Request{
		SetupMode: "host",
		Schema:    SchemaV1, Platform: runtime.GOOS, User: account.Username, UID: uid, Group: group.Name, GID: gid,
		Executable: executable, Artifact: manifest,
		Home: account.HomeDir, Path: "/usr/bin:/bin", StateRoot: state, WorkspaceRoot: account.HomeDir,
		ControlURL: "https://control.example.test", UserMachineID: "um_test", Shell: shell,
		HelperListenAddress: "127.0.0.1:8080",
	}
}
