//go:build windows

package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// The service and workload roles are passed as ordinary go test flags because
// SCM does not provide a safe service-specific environment block. The normal
// test process leaves these flags empty and therefore never enters a service
// or workload role.
var (
	nativeWindowsServiceRoleFlag            = flag.String("paperboat-native-service-role", "", "native Windows qualification service role")
	nativeWindowsServiceNameFlag            = flag.String("paperboat-native-service-name", "", "native Windows qualification service name")
	nativeWindowsServiceOwnerSIDFlag        = flag.String("paperboat-native-service-owner-sid", "", "native Windows qualification owner SID")
	nativeWindowsServiceHealthFlag          = flag.String("paperboat-native-service-health", "", "native Windows qualification health address")
	nativeWindowsServiceFailureFlag         = flag.String("paperboat-native-service-failure", "", "native Windows qualification service failure path")
	nativeWindowsServiceWorkloadFailureFlag = flag.String("paperboat-native-service-workload-failure", "", "native Windows qualification workload failure path")
	nativeWindowsWorkloadRoleFlag           = flag.String("paperboat-native-workload-role", "", "native Windows qualification workload role")
	nativeWindowsWorkloadHealthFlag         = flag.String("paperboat-native-workload-health", "", "native Windows qualification workload health address")
	nativeWindowsWorkloadFailureFlag        = flag.String("paperboat-native-workload-failure", "", "native Windows qualification workload failure path")
)

const (
	nativeWindowsServiceTestPrefix    = "paperboat-trk34-"
	nativeWindowsLifecycleTimeout     = 45 * time.Second
	nativeWindowsRebootMetadataPrefix = "paperboat-trk34-reboot-"
	nativeWindowsRebootMetadataSchema = "paperboat.windows-reboot-qualification/v1"
	nativeWindowsRebootPhaseEnv       = "PAPERBOAT_NATIVE_REBOOT_PHASE"
	nativeWindowsRebootMetadataEnv    = "PAPERBOAT_NATIVE_REBOOT_METADATA"
)

// nativeWindowsRebootMetadata is deliberately limited to fixture identity and
// content hashes. It is persisted between the two phases across one reboot;
// it never contains tokens, credentials, or service environment values.
type nativeWindowsRebootMetadata struct {
	Schema                  string `json:"schema"`
	Instance                string `json:"instance"`
	OwnerSID                string `json:"owner_sid"`
	ExecutableRoot          string `json:"executable_root"`
	Executable              string `json:"executable"`
	ConfigRoot              string `json:"config_root"`
	StateRoot               string `json:"state_root"`
	HostdName               string `json:"hostd_name"`
	UpdaterName             string `json:"updater_name"`
	HostdDefinition         string `json:"hostd_definition"`
	UpdaterDefinition       string `json:"updater_definition"`
	HostdDefinitionSHA256   string `json:"hostd_definition_sha256"`
	UpdaterDefinitionSHA256 string `json:"updater_definition_sha256"`
	HostdHealth             string `json:"hostd_health"`
	UpdaterHealth           string `json:"updater_health"`
	HostdWorkloadFailure    string `json:"hostd_workload_failure"`
	UpdaterWorkloadFailure  string `json:"updater_workload_failure"`
}

// TestNativeWindowsServiceProcess is the executable entry used by the
// disposable SCM services. It launches the workload through the production
// RunWindowsService path, which obtains the enrolled user token and puts the
// workload in a kill-on-close Job Object.
func TestNativeWindowsServiceProcess(t *testing.T) {
	role := *nativeWindowsServiceRoleFlag
	if role == "" {
		t.Skip("native Windows service child only")
	}
	if role != "hostd" && role != "updater" {
		t.Fatalf("unknown native Windows service role %q", role)
	}
	if *nativeWindowsServiceNameFlag == "" || *nativeWindowsServiceOwnerSIDFlag == "" || *nativeWindowsServiceHealthFlag == "" || *nativeWindowsServiceFailureFlag == "" || *nativeWindowsServiceWorkloadFailureFlag == "" {
		t.Fatal("native Windows service child is missing its bounded identity arguments")
	}
	recordFailure := func(message string) {
		file, err := os.OpenFile(*nativeWindowsServiceFailureFlag, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return
		}
		_, _ = file.WriteString(message + "\n")
		_ = file.Close()
	}
	recordFailure("service-test-entered")
	recordFailure("workload-config role=" + role + " health=" + *nativeWindowsServiceHealthFlag + " failure=" + *nativeWindowsServiceWorkloadFailureFlag)
	appendNativeWindowsFailure(*nativeWindowsServiceWorkloadFailureFlag, "service-before-workload-launch")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := RunWindowsService(ServiceEntryConfig{
		Name:          *nativeWindowsServiceNameFlag,
		Executable:    executable,
		EnrolledSID:   *nativeWindowsServiceOwnerSIDFlag,
		LaunchFailure: func(err error) { recordFailure("launch-failure: " + err.Error()) },
		Arguments: []string{
			"-test.run=TestNativeWindowsServiceWorkload",
			"-test.timeout=1h",
			"-test.v",
			"-paperboat-native-workload-role=" + role,
			"-paperboat-native-workload-health=" + *nativeWindowsServiceHealthFlag,
			"-paperboat-native-workload-failure=" + *nativeWindowsServiceWorkloadFailureFlag,
		},
		Environment: map[string]string{
			"PAPERBOAT_NATIVE_WORKLOAD_ROLE":    role,
			"PAPERBOAT_NATIVE_WORKLOAD_HEALTH":  *nativeWindowsServiceHealthFlag,
			"PAPERBOAT_NATIVE_WORKLOAD_FAILURE": *nativeWindowsServiceWorkloadFailureFlag,
		},
	}); err != nil {
		recordFailure("service-run-error: " + err.Error())
		t.Fatal(err)
	}
	recordFailure("service-test-returned")
	appendNativeWindowsFailure(*nativeWindowsServiceWorkloadFailureFlag, "service-after-workload-return")
}

// TestNativeWindowsServiceWorkload is started by serviceEntry under the
// enrolled user. Keeping the process alive makes the service stop path prove
// that Job Object termination removes the owner workload too.
func TestNativeWindowsServiceWorkload(t *testing.T) {
	role := *nativeWindowsWorkloadRoleFlag
	if role == "" {
		role = os.Getenv("PAPERBOAT_NATIVE_WORKLOAD_ROLE")
	}
	if role == "" {
		t.Skip("native Windows workload child only")
	}
	if role != "hostd" && role != "updater" {
		t.Fatalf("unknown native Windows workload role %q", role)
	}
	healthAddress := *nativeWindowsWorkloadHealthFlag
	if healthAddress == "" {
		healthAddress = os.Getenv("PAPERBOAT_NATIVE_WORKLOAD_HEALTH")
	}
	failurePath := *nativeWindowsWorkloadFailureFlag
	if failurePath == "" {
		failurePath = os.Getenv("PAPERBOAT_NATIVE_WORKLOAD_FAILURE")
	}
	if healthAddress == "" || failurePath == "" {
		t.Fatal("native Windows workload is missing its bounded health/failure address")
	}
	appendNativeWindowsFailure(failurePath, "workload-test-entered role="+role+" health="+healthAddress)
	listener, err := net.Listen("tcp", healthAddress)
	if err != nil {
		appendNativeWindowsFailure(failurePath, "workload-listen-error: "+err.Error())
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte(`{"live":true}`))
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	appendNativeWindowsFailure(failurePath, "workload-test-ready")
	select {}
}

func appendNativeWindowsFailure(path, message string) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	_, _ = file.WriteString(message + "\n")
	_ = file.Close()
}

// TestNativeWindowsComposedLifecycle is intentionally opt-in. Every SCM name
// and declaration path is unique to this invocation. The test fails closed on
// a collision and never adopts or deletes a pre-existing Paperboat service.
func TestNativeWindowsComposedLifecycle(t *testing.T) {
	if os.Getenv("PAPERBOAT_NATIVE_SERVICE_TEST") != "1" {
		t.Skip("set PAPERBOAT_NATIVE_SERVICE_TEST=1 in an elevated isolated Windows session")
	}

	executable, executableRoot := installNativeWindowsServiceTestExecutable(t)
	ownerSID := nativeWindowsCurrentUserSID(t)
	instance := nativeWindowsUniqueInstance(t)
	hostdName := windowsServiceName(HostdKind, instance)
	updaterName := windowsServiceName(UpdaterKind, instance)
	foreignInstance := instance + "-foreign"
	foreignName := windowsServiceName(HostdKind, foreignInstance)
	serviceNames := []string{hostdName, updaterName, foreignName}
	for _, name := range serviceNames {
		if !strings.Contains(strings.ToLower(name), "-trk34-") {
			t.Fatalf("generated service name escaped qualification marker: %q", name)
		}
		exists, err := nativeWindowsServiceExists(name)
		if err != nil {
			t.Fatalf("inspect service collision %q: %v", name, err)
		}
		if exists {
			t.Fatalf("refusing to replace pre-existing service %q", name)
		}
	}

	hostdHealth := nativeWindowsHealthAddress(t)
	updaterHealth := nativeWindowsHealthAddress(t)
	hostdWorkloadFailure := filepath.Join(os.TempDir(), nativeWindowsServiceTestPrefix+instance+"-hostd-workload.failure.txt")
	updaterWorkloadFailure := filepath.Join(os.TempDir(), nativeWindowsServiceTestPrefix+instance+"-updater-workload.failure.txt")
	for _, path := range []string{hostdWorkloadFailure, updaterWorkloadFailure} {
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("refusing to replace pre-existing workload diagnostic %q", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("cleanup workload diagnostic %q: %v", path, err)
			}
		})
	}
	configRoot := filepath.Join(executableRoot, "config")
	stateRoot := filepath.Join(executableRoot, "lifecycle")
	hostd, err := New(Config{
		Platform: "windows", Kind: HostdKind, Instance: instance, ConfigRoot: configRoot,
		Executable: executable, User: "SYSTEM", Group: "SYSTEM",
		Arguments: []string{
			"-test.run=^TestNativeWindowsServiceProcess$", "-test.v",
			"-paperboat-native-service-role=hostd",
			"-paperboat-native-service-name=" + hostdName,
			"-paperboat-native-service-owner-sid=" + ownerSID,
			"-paperboat-native-service-health=" + hostdHealth,
			"-paperboat-native-service-failure=" + filepath.Join(executableRoot, "hostd.failure.txt"),
			"-paperboat-native-service-workload-failure=" + hostdWorkloadFailure,
		},
		Controller: WindowsController{},
	})
	if err != nil {
		t.Fatal(err)
	}
	updater, err := New(Config{
		Platform: "windows", Kind: UpdaterKind, Instance: instance, ConfigRoot: configRoot,
		Executable: executable, User: "SYSTEM", Group: "SYSTEM",
		Arguments: []string{
			"-test.run=^TestNativeWindowsServiceProcess$", "-test.v",
			"-paperboat-native-service-role=updater",
			"-paperboat-native-service-name=" + updaterName,
			"-paperboat-native-service-owner-sid=" + ownerSID,
			"-paperboat-native-service-health=" + updaterHealth,
			"-paperboat-native-service-failure=" + filepath.Join(executableRoot, "updater.failure.txt"),
			"-paperboat-native-service-workload-failure=" + updaterWorkloadFailure,
		},
		Controller: WindowsController{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{hostd.DefinitionPath(), updater.DefinitionPath()} {
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("refusing to replace pre-existing declaration %q", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}

	// Exercise the collision boundary with a disposable foreign SCM entry.
	// Apply, Enable, Inspect, Start, Stop, Disable, and Remove must all refuse
	// it without changing its command line or deleting its registration.
	foreign, err := New(Config{
		Platform: "windows", Kind: HostdKind, Instance: foreignInstance, ConfigRoot: configRoot,
		Executable: executable, User: "SYSTEM", Group: "SYSTEM",
		Arguments:  []string{"-test.run=^TestNativeWindowsServiceProcess$", "-test.v"},
		Controller: WindowsController{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := foreign.writeDefinition(context.Background()); err != nil {
		t.Fatal(err)
	}
	foreignDefinition := true
	foreignCreated := false
	t.Cleanup(func() {
		if foreignCreated {
			if err := deleteNativeWindowsService(foreignName); err != nil {
				t.Errorf("cleanup foreign service %q: %v", foreignName, err)
			}
		}
		if foreignDefinition {
			if err := os.Remove(foreign.DefinitionPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("cleanup foreign definition %q: %v", foreign.DefinitionPath(), err)
			}
		}
	})
	foreignCreated, err = createNativeWindowsForeignService(foreignName)
	if err != nil {
		t.Fatal(err)
	}
	foreignCreated = true
	foreignBefore := nativeWindowsServiceConfig(t, foreignName)
	foreignOps := []struct {
		name string
		call func(context.Context, string) error
	}{
		{"apply", func(ctx context.Context, path string) error { return WindowsController{}.Apply(ctx, path, false) }},
		{"enable", WindowsController{}.Enable},
		{"inspect", func(ctx context.Context, path string) error {
			_, err := WindowsController{}.Inspect(ctx, path)
			return err
		}},
		{"start", WindowsController{}.Start},
		{"stop", WindowsController{}.Stop},
		{"disable", WindowsController{}.Disable},
		{"remove", WindowsController{}.Remove},
	}
	for _, operation := range foreignOps {
		err := operation.call(context.Background(), foreign.DefinitionPath())
		if !errors.Is(err, ErrInvalidDefinition) {
			t.Fatalf("foreign service %s returned %v, want ErrInvalidDefinition", operation.name, err)
		}
	}
	foreignAfter := nativeWindowsServiceConfig(t, foreignName)
	if foreignBefore.BinaryPathName != foreignAfter.BinaryPathName || foreignBefore.StartType != foreignAfter.StartType || foreignBefore.ServiceStartName != foreignAfter.ServiceStartName {
		t.Fatalf("foreign service changed after refusal: before=%+v after=%+v", foreignBefore, foreignAfter)
	}
	if err := deleteNativeWindowsService(foreignName); err != nil {
		t.Fatal(err)
	}
	foreignCreated = false
	if err := foreign.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	foreignDefinition = false

	hostProbe, err := NewHTTPReadinessProbe("http://" + hostdHealth + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	updaterProbe, err := NewHTTPReadinessProbe("http://" + updaterHealth + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	hostReady := nativeWindowsRetryReadiness(hostProbe)
	updaterReady := nativeWindowsRetryReadiness(updaterProbe)
	manager, err := NewHostLifecycleManager(HostLifecycleConfig{
		StateRoot: stateRoot, Hostd: hostd, Updater: updater,
		HostdProbe: hostReady, UpdaterProbe: updaterReady,
	})
	if err != nil {
		t.Fatal(err)
	}
	installed := false
	t.Cleanup(func() {
		if installed {
			ctx, cancel := context.WithTimeout(context.Background(), nativeWindowsLifecycleTimeout)
			defer cancel()
			if err := manager.Uninstall(ctx); err != nil {
				t.Errorf("cleanup composed Windows services: %v", err)
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), nativeWindowsLifecycleTimeout)
	installErr := manager.Install(ctx)
	cancel()
	if installErr != nil {
		t.Fatalf("install: %v; service launch failures: %s", installErr, nativeWindowsServiceFailureDetails(executableRoot, hostdWorkloadFailure, updaterWorkloadFailure))
	}
	installed = true
	assertNativeWindowsServiceConfiguration(t, hostdName, hostd, true)
	assertNativeWindowsServiceConfiguration(t, updaterName, updater, true)
	initialStatuses, err := manager.Inspect(context.Background())
	if err != nil || len(initialStatuses) != 2 {
		t.Fatalf("initial statuses=%+v err=%v", initialStatuses, err)
	}
	childPIDs := make(map[uint32]struct{})
	for _, name := range []string{hostdName, updaterName} {
		pid := nativeWindowsServicePID(t, name)
		if pid == 0 {
			t.Fatalf("service %q has no SCM process id", name)
		}
		for _, child := range nativeWindowsChildPIDs(t, pid, 10*time.Second) {
			childPIDs[child] = struct{}{}
		}
	}
	if len(childPIDs) != 2 {
		t.Fatalf("expected one Job Object workload per service, child pids=%v", childPIDs)
	}

	nativeWindowsLifecycleOperation(t, "repair", manager.Repair)
	if err := hostReady(context.Background()); err != nil {
		t.Fatalf("hostd readiness after repair: %v", err)
	}
	if err := updaterReady(context.Background()); err != nil {
		t.Fatalf("updater readiness after repair: %v", err)
	}

	nativeWindowsLifecycleOperation(t, "stop", manager.Stop)
	stoppedStatuses, err := manager.Inspect(context.Background())
	if err != nil || len(stoppedStatuses) != len(initialStatuses) {
		t.Fatalf("stopped statuses=%+v err=%v", stoppedStatuses, err)
	}
	for index, status := range stoppedStatuses {
		if !status.Installed || !status.Enabled || status.Running || status.Ready || !sameComponentStatusExceptRunning(initialStatuses[index], status) {
			t.Fatalf("stop did not preserve declaration/enablement: initial=%+v stopped=%+v", initialStatuses[index], status)
		}
	}
	for pid := range childPIDs {
		if err := waitNativeWindowsProcessGone(pid, 15*time.Second); err != nil {
			t.Fatalf("Job Object child pid %d survived stop: %v", pid, err)
		}
	}

	nativeWindowsLifecycleOperation(t, "repair after stop", manager.Repair)
	if err := hostReady(context.Background()); err != nil {
		t.Fatalf("hostd readiness after stop/repair: %v", err)
	}
	if err := updaterReady(context.Background()); err != nil {
		t.Fatalf("updater readiness after stop/repair: %v", err)
	}
	nativeWindowsLifecycleOperation(t, "uninstall", manager.Uninstall)
	installed = false
	for _, name := range []string{hostdName, updaterName} {
		exists, err := nativeWindowsServiceExists(name)
		if err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatalf("service %q remains after uninstall", name)
		}
	}
	for _, path := range []string{hostd.DefinitionPath(), updater.DefinitionPath()} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("declaration %q remains after uninstall: %v", path, err)
		}
	}
}

// TestNativeWindowsRebootPersistence is intentionally split into two
// invocations. Phase one installs a unique fixture and leaves it running;
// the caller reboots the host and reconnects through the independent SSH
// service before invoking phase two. The metadata file contains only fixture
// paths, identities, and hashes, never credentials or service secrets.
func TestNativeWindowsRebootPersistence(t *testing.T) {
	if os.Getenv("PAPERBOAT_NATIVE_SERVICE_TEST") != "1" {
		t.Skip("set PAPERBOAT_NATIVE_SERVICE_TEST=1 in an elevated isolated Windows session")
	}
	switch os.Getenv(nativeWindowsRebootPhaseEnv) {
	case "1":
		nativeWindowsRebootPhaseOne(t)
	case "2":
		nativeWindowsRebootPhaseTwo(t)
	default:
		t.Skip("set " + nativeWindowsRebootPhaseEnv + " to 1 or 2")
	}
}

type nativeWindowsRebootFixture struct {
	metadataPath string
	metadata     nativeWindowsRebootMetadata
	hostd        *Installer
	updater      *Installer
	root         string
}

func nativeWindowsRebootPhaseOne(t *testing.T) {
	t.Helper()
	executable, root := installNativeWindowsServiceTestExecutableWithCleanup(t, false)
	instance := nativeWindowsRebootInstance(t)
	ownerSID := nativeWindowsCurrentUserSID(t)
	hostdName := windowsServiceName(HostdKind, instance)
	updaterName := windowsServiceName(UpdaterKind, instance)
	hostdHealth := nativeWindowsHealthAddress(t)
	updaterHealth := nativeWindowsHealthAddress(t)
	suffix := strings.TrimPrefix(instance, "trk34-reboot-")
	hostdWorkloadFailure := filepath.Join(os.TempDir(), nativeWindowsRebootMetadataPrefix+suffix+"-hostd-workload.failure.txt")
	updaterWorkloadFailure := filepath.Join(os.TempDir(), nativeWindowsRebootMetadataPrefix+suffix+"-updater-workload.failure.txt")
	metadataPath := filepath.Join(root, "reboot-state.json")
	fixture := nativeWindowsRebootFixture{
		metadataPath: metadataPath,
		root:         root,
		metadata: nativeWindowsRebootMetadata{
			Schema:                 nativeWindowsRebootMetadataSchema,
			Instance:               instance,
			OwnerSID:               ownerSID,
			ExecutableRoot:         root,
			Executable:             executable,
			ConfigRoot:             filepath.Join(root, "config"),
			StateRoot:              filepath.Join(root, "lifecycle"),
			HostdName:              hostdName,
			UpdaterName:            updaterName,
			HostdDefinition:        filepath.Join(windowsServiceDefinitionRoot, hostdName+".json"),
			UpdaterDefinition:      filepath.Join(windowsServiceDefinitionRoot, updaterName+".json"),
			HostdHealth:            hostdHealth,
			UpdaterHealth:          updaterHealth,
			HostdWorkloadFailure:   hostdWorkloadFailure,
			UpdaterWorkloadFailure: updaterWorkloadFailure,
		},
	}
	cleanupNeeded := true
	defer func() {
		if cleanupNeeded {
			if err := cleanupNativeWindowsRebootFixture(fixture.metadata, fixture.hostd, fixture.updater); err != nil {
				t.Errorf("cleanup failed phase-one fixture: %v", err)
			}
		}
	}()
	nativeWindowsRefuseRebootCollisions(t, fixture.metadata)
	for _, path := range []string{hostdWorkloadFailure, updaterWorkloadFailure} {
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("refusing to replace pre-existing workload diagnostic %q", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	var err error
	fixture.hostd, err = nativeWindowsRebootInstaller(t, fixture.metadata, HostdKind, "hostd")
	if err != nil {
		t.Fatal(err)
	}
	fixture.updater, err = nativeWindowsRebootInstaller(t, fixture.metadata, UpdaterKind, "updater")
	if err != nil {
		t.Fatal(err)
	}
	hostdDefinition, err := fixture.hostd.render()
	if err != nil {
		t.Fatal(err)
	}
	updaterDefinition, err := fixture.updater.render()
	if err != nil {
		t.Fatal(err)
	}
	fixture.metadata.HostdDefinitionSHA256 = nativeWindowsBytesSHA256(hostdDefinition)
	fixture.metadata.UpdaterDefinitionSHA256 = nativeWindowsBytesSHA256(updaterDefinition)
	manager, err := NewHostLifecycleManager(HostLifecycleConfig{
		StateRoot: fixture.metadata.StateRoot, Hostd: fixture.hostd, Updater: fixture.updater,
		HostdProbe:   nativeWindowsRebootProbe(t, fixture.metadata.HostdHealth),
		UpdaterProbe: nativeWindowsRebootProbe(t, fixture.metadata.UpdaterHealth),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), nativeWindowsLifecycleTimeout)
	err = manager.Install(ctx)
	cancel()
	if err != nil {
		t.Fatalf("phase-one install/readiness: %v", err)
	}
	assertNativeWindowsServiceConfiguration(t, fixture.metadata.HostdName, fixture.hostd, true)
	assertNativeWindowsServiceConfiguration(t, fixture.metadata.UpdaterName, fixture.updater, true)
	if err := nativeWindowsRebootDefinitionHashes(fixture.metadata); err != nil {
		t.Fatal(err)
	}
	metadataBody, err := json.MarshalIndent(fixture.metadata, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	metadataBody = append(metadataBody, '\n')
	if err := atomicfile.Write(metadataPath, metadataBody, atomicfile.CurrentOwnerOptions(0o600)); err != nil {
		t.Fatalf("persist non-secret reboot metadata: %v", err)
	}
	if _, err := readNativeWindowsRebootMetadata(metadataPath); err != nil {
		t.Fatalf("validate persisted reboot metadata: %v", err)
	}
	t.Logf("reboot_metadata_path=%s", metadataPath)
	t.Logf("reboot_instance=%s hostd=%s updater=%s", instance, hostdName, updaterName)
	cleanupNeeded = false
}

func nativeWindowsRebootPhaseTwo(t *testing.T) {
	t.Helper()
	metadataPath := os.Getenv(nativeWindowsRebootMetadataEnv)
	metadata, err := readNativeWindowsRebootMetadata(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture := nativeWindowsRebootFixture{metadataPath: metadataPath, metadata: metadata, root: metadata.ExecutableRoot}
	cleanupNeeded := true
	defer func() {
		if cleanupNeeded {
			if err := cleanupNativeWindowsRebootFixture(fixture.metadata, fixture.hostd, fixture.updater); err != nil {
				t.Errorf("cleanup failed phase-two fixture: %v", err)
			}
		}
	}()
	nativeWindowsValidateRebootFixturePresence(t, metadata)
	fixture.hostd, err = nativeWindowsRebootInstaller(t, metadata, HostdKind, "hostd")
	if err != nil {
		t.Fatal(err)
	}
	fixture.updater, err = nativeWindowsRebootInstaller(t, metadata, UpdaterKind, "updater")
	if err != nil {
		t.Fatal(err)
	}
	if err := nativeWindowsRebootDefinitionHashes(metadata); err != nil {
		t.Fatalf("definitions changed across reboot: %v", err)
	}
	hostProbe := nativeWindowsRebootProbe(t, metadata.HostdHealth)
	updaterProbe := nativeWindowsRebootProbe(t, metadata.UpdaterHealth)
	manager, err := NewHostLifecycleManager(HostLifecycleConfig{
		StateRoot: metadata.StateRoot, Hostd: fixture.hostd, Updater: fixture.updater,
		HostdProbe: hostProbe, UpdaterProbe: updaterProbe,
	})
	if err != nil {
		t.Fatal(err)
	}
	statuses := nativeWindowsWaitForRebootReady(t, manager, hostProbe, updaterProbe, 90*time.Second)
	if len(statuses) != 2 {
		t.Fatalf("post-reboot statuses=%+v", statuses)
	}
	assertNativeWindowsServiceConfiguration(t, metadata.HostdName, fixture.hostd, true)
	assertNativeWindowsServiceConfiguration(t, metadata.UpdaterName, fixture.updater, true)
	nativeWindowsLifecycleOperation(t, "repair after reboot", manager.Repair)
	_ = nativeWindowsWaitForRebootReady(t, manager, hostProbe, updaterProbe, 90*time.Second)
	if err := nativeWindowsRebootDefinitionHashes(metadata); err != nil {
		t.Fatalf("repair changed fixture declaration bytes: %v", err)
	}
	nativeWindowsLifecycleOperation(t, "uninstall after reboot", manager.Uninstall)
	for _, installer := range []*Installer{fixture.hostd, fixture.updater} {
		name := nativeWindowsInstallerName(installer)
		if exists, err := nativeWindowsServiceExists(name); err != nil {
			t.Fatal(err)
		} else if exists {
			t.Fatalf("service %q remains after reboot uninstall", name)
		}
		if _, err := os.Lstat(installer.DefinitionPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("declaration %q remains after reboot uninstall: %v", installer.DefinitionPath(), err)
		}
	}
	if err := cleanupNativeWindowsRebootFixture(metadata, fixture.hostd, fixture.updater); err != nil {
		t.Fatal(err)
	}
	cleanupNeeded = false
}

func nativeWindowsRebootInstance(t *testing.T) string {
	t.Helper()
	var random [10]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	instance := "trk34-reboot-" + hex.EncodeToString(random[:])
	if !nativeWindowsRebootInstanceValid(instance) {
		t.Fatalf("generated reboot instance is not bounded: %q", instance)
	}
	return instance
}

func nativeWindowsRebootInstanceValid(instance string) bool {
	const prefix = "trk34-reboot-"
	if !strings.HasPrefix(instance, prefix) || len(instance) != len(prefix)+20 {
		return false
	}
	_, err := hex.DecodeString(instance[len(prefix):])
	return err == nil
}

func nativeWindowsRebootInstaller(t *testing.T, metadata nativeWindowsRebootMetadata, kind, role string) (*Installer, error) {
	t.Helper()
	if (kind != HostdKind && kind != UpdaterKind) || (role != "hostd" && role != "updater") {
		return nil, ErrInvalidDefinition
	}
	name := windowsServiceName(kind, metadata.Instance)
	if role == "hostd" && name != metadata.HostdName || role == "updater" && name != metadata.UpdaterName {
		return nil, ErrInvalidDefinition
	}
	workloadFailure := metadata.HostdWorkloadFailure
	definitionPath := metadata.HostdDefinition
	health := metadata.HostdHealth
	if role == "updater" {
		workloadFailure = metadata.UpdaterWorkloadFailure
		definitionPath = metadata.UpdaterDefinition
		health = metadata.UpdaterHealth
	}
	if definitionPath != filepath.Join(windowsServiceDefinitionRoot, name+".json") {
		return nil, ErrInvalidDefinition
	}
	return New(Config{
		Platform: "windows", Kind: kind, Instance: metadata.Instance, ConfigRoot: metadata.ConfigRoot,
		Executable: metadata.Executable, User: "SYSTEM", Group: "SYSTEM",
		Arguments: []string{
			"-test.run=^TestNativeWindowsServiceProcess$", "-test.v",
			"-paperboat-native-service-role=" + role,
			"-paperboat-native-service-name=" + name,
			"-paperboat-native-service-owner-sid=" + metadata.OwnerSID,
			"-paperboat-native-service-health=" + health,
			"-paperboat-native-service-failure=" + filepath.Join(metadata.ExecutableRoot, role+".failure.txt"),
			"-paperboat-native-service-workload-failure=" + workloadFailure,
		},
		Controller: WindowsController{},
	})
}

func nativeWindowsRebootProbe(t *testing.T, address string) func(context.Context) error {
	t.Helper()
	probe, err := NewHTTPReadinessProbe("http://" + address + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	return nativeWindowsRetryReadiness(probe)
}

func nativeWindowsRebootDefinitionHashes(metadata nativeWindowsRebootMetadata) error {
	for _, expected := range []struct {
		path string
		hash string
		role string
	}{
		{path: metadata.HostdDefinition, hash: metadata.HostdDefinitionSHA256, role: "hostd"},
		{path: metadata.UpdaterDefinition, hash: metadata.UpdaterDefinitionSHA256, role: "updater"},
	} {
		actual, err := nativeWindowsFileSHA256(expected.path)
		if err != nil {
			return fmt.Errorf("hash %s declaration: %w", expected.role, err)
		}
		if !strings.EqualFold(actual, expected.hash) {
			return fmt.Errorf("%s declaration hash changed: got %s want %s", expected.role, actual, expected.hash)
		}
	}
	return nil
}

func nativeWindowsFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func nativeWindowsBytesSHA256(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func nativeWindowsRefuseRebootCollisions(t *testing.T, metadata nativeWindowsRebootMetadata) {
	t.Helper()
	for _, name := range []string{metadata.HostdName, metadata.UpdaterName} {
		exists, err := nativeWindowsServiceExists(name)
		if err != nil {
			t.Fatalf("inspect reboot service collision %q: %v", name, err)
		}
		if exists {
			t.Fatalf("refusing to replace pre-existing reboot service %q", name)
		}
	}
	for _, path := range []string{metadata.HostdDefinition, metadata.UpdaterDefinition, metadata.metadataPath()} {
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("refusing to replace pre-existing reboot fixture path %q", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
}

func nativeWindowsValidateRebootFixturePresence(t *testing.T, metadata nativeWindowsRebootMetadata) {
	t.Helper()
	for _, name := range []string{metadata.HostdName, metadata.UpdaterName} {
		exists, err := nativeWindowsServiceExists(name)
		if err != nil {
			t.Fatalf("inspect reboot service after reboot %q: %v", name, err)
		}
		if !exists {
			t.Fatalf("reboot service %q is absent", name)
		}
	}
	for _, path := range []string{metadata.HostdDefinition, metadata.UpdaterDefinition, metadata.metadataPath()} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("reboot fixture path %q is absent: %v", path, err)
		}
	}
}

func (metadata nativeWindowsRebootMetadata) metadataPath() string {
	return filepath.Join(metadata.ExecutableRoot, "reboot-state.json")
}

func nativeWindowsWaitForRebootReady(t *testing.T, manager *LifecycleManager, hostProbe, updaterProbe func(context.Context) error, timeout time.Duration) []NativeComponentStatus {
	t.Helper()
	if manager == nil || hostProbe == nil || updaterProbe == nil || timeout <= 0 {
		t.Fatal(ErrLifecycleInvalid)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		statuses, err := manager.Inspect(ctx)
		if err == nil && len(statuses) == 2 && statuses[0].Installed && statuses[0].Enabled && statuses[0].Running && statuses[0].Ready && statuses[1].Installed && statuses[1].Enabled && statuses[1].Running && statuses[1].Ready {
			if err := hostProbe(ctx); err == nil {
				if err := updaterProbe(ctx); err == nil {
					return statuses
				} else {
					lastErr = err
				}
			} else {
				lastErr = err
			}
		} else if err != nil {
			lastErr = err
		} else {
			lastErr = ErrLifecycleNotReady
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("reboot services did not become ready: %v; statuses=%+v", lastErr, statuses)
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Fatalf("reboot readiness timed out: %v", lastErr)
		case <-timer.C:
		}
	}
}

func cleanupNativeWindowsRebootFixture(metadata nativeWindowsRebootMetadata, installers ...*Installer) error {
	if err := validateNativeWindowsRebootMetadata(metadata, metadata.metadataPath()); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	byName := make(map[string]*Installer, len(installers))
	for _, installer := range installers {
		if installer != nil {
			byName[nativeWindowsInstallerName(installer)] = installer
		}
	}
	for _, item := range []struct {
		name string
		path string
		hash string
	}{
		{name: metadata.HostdName, path: metadata.HostdDefinition, hash: metadata.HostdDefinitionSHA256},
		{name: metadata.UpdaterName, path: metadata.UpdaterDefinition, hash: metadata.UpdaterDefinitionSHA256},
	} {
		if _, err := os.Lstat(item.path); err == nil {
			actual, hashErr := nativeWindowsFileSHA256(item.path)
			if hashErr != nil {
				return hashErr
			}
			if !strings.EqualFold(actual, item.hash) {
				return fmt.Errorf("refusing to remove changed %s declaration", item.name)
			}
			if err := (WindowsController{}).Remove(ctx, item.path); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		} else if exists, existsErr := nativeWindowsServiceExists(item.name); existsErr != nil {
			return existsErr
		} else if exists {
			installer := byName[item.name]
			if installer == nil {
				return fmt.Errorf("%w: service %q has no declaration", ErrInvalidDefinition, item.name)
			}
			definitionBody, renderErr := installer.render()
			if renderErr != nil {
				return renderErr
			}
			var definition windowsServiceDefinition
			if err := json.Unmarshal(definitionBody, &definition); err != nil {
				return err
			}
			config, configErr := nativeWindowsServiceConfigByName(item.name)
			if configErr != nil || !windowsServiceConfigurationOwnsDefinition(config, definition) {
				return errors.Join(ErrInvalidDefinition, configErr)
			}
			if err := deleteNativeWindowsService(item.name); err != nil {
				return err
			}
		}
		if _, err := os.Lstat(item.path); err == nil {
			if err := os.Remove(item.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, path := range []string{metadata.HostdWorkloadFailure, metadata.UpdaterWorkloadFailure} {
		if err := removeNativeWindowsRebootDiagnostic(path); err != nil {
			return err
		}
	}
	return cleanupNativeWindowsTestRoot(metadata.ExecutableRoot)
}

func removeNativeWindowsRebootDiagnostic(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.EqualFold(filepath.Dir(path), filepath.Clean(os.TempDir())) || !strings.HasPrefix(strings.ToLower(filepath.Base(path)), nativeWindowsRebootMetadataPrefix) {
		return ErrInvalidDefinition
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		if err == nil {
			err = ErrInvalidDefinition
		}
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func nativeWindowsServiceConfigByName(name string) (mgr.Config, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return mgr.Config{}, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(name)
	if err != nil {
		return mgr.Config{}, err
	}
	defer service.Close()
	return service.Config()
}

func nativeWindowsInstallerName(installer *Installer) string {
	if installer == nil {
		return ""
	}
	return windowsServiceName(installer.config.Kind, installer.config.Instance)
}

func readNativeWindowsRebootMetadata(path string) (nativeWindowsRebootMetadata, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nativeWindowsRebootMetadata{}, ErrInvalidDefinition
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nativeWindowsRebootMetadata{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 16<<10 {
		return nativeWindowsRebootMetadata{}, ErrInvalidDefinition
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nativeWindowsRebootMetadata{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var metadata nativeWindowsRebootMetadata
	if err := decoder.Decode(&metadata); err != nil {
		return nativeWindowsRebootMetadata{}, ErrInvalidDefinition
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nativeWindowsRebootMetadata{}, ErrInvalidDefinition
	}
	if err := validateNativeWindowsRebootMetadata(metadata, path); err != nil {
		return nativeWindowsRebootMetadata{}, err
	}
	return metadata, nil
}

func validateNativeWindowsRebootMetadata(metadata nativeWindowsRebootMetadata, metadataPath string) error {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	if err := validateNativeWindowsRebootMetadataShape(metadata, metadataPath, programData); err != nil {
		return err
	}
	root := filepath.Clean(metadata.ExecutableRoot)
	if err := validateWindowsDirectoryNoReparse(root); err != nil {
		return err
	}
	if err := validateWindowsRegularFileNoReparse(metadata.Executable, false); err != nil {
		return err
	}
	return nil
}

func validateNativeWindowsRebootMetadataShape(metadata nativeWindowsRebootMetadata, metadataPath, programData string) error {
	if metadata.Schema != nativeWindowsRebootMetadataSchema || !nativeWindowsRebootInstanceValid(metadata.Instance) {
		return ErrInvalidDefinition
	}
	if _, err := windows.StringToSid(metadata.OwnerSID); err != nil {
		return ErrInvalidDefinition
	}
	root := filepath.Clean(metadata.ExecutableRoot)
	if !filepath.IsAbs(metadata.ExecutableRoot) || root != metadata.ExecutableRoot || !strings.EqualFold(filepath.Dir(root), filepath.Clean(programData)) || !strings.HasPrefix(strings.ToLower(filepath.Base(root)), nativeWindowsServiceTestPrefix) {
		return ErrInvalidDefinition
	}
	if metadata.Executable != filepath.Join(root, "service.test.exe") || metadata.ConfigRoot != filepath.Join(root, "config") || metadata.StateRoot != filepath.Join(root, "lifecycle") || metadataPath != filepath.Join(root, "reboot-state.json") {
		return ErrInvalidDefinition
	}
	if err := validateWindowsDirectoryNoReparse(root); err != nil {
		return err
	}
	if err := validateWindowsRegularFileNoReparse(metadata.Executable, false); err != nil {
		return err
	}
	if metadata.HostdName != windowsServiceName(HostdKind, metadata.Instance) || metadata.UpdaterName != windowsServiceName(UpdaterKind, metadata.Instance) || !strings.Contains(strings.ToLower(metadata.HostdName), "-trk34-reboot-") || !strings.Contains(strings.ToLower(metadata.UpdaterName), "-trk34-reboot-") {
		return ErrInvalidDefinition
	}
	if metadata.HostdDefinition != filepath.Join(windowsServiceDefinitionRoot, metadata.HostdName+".json") || metadata.UpdaterDefinition != filepath.Join(windowsServiceDefinitionRoot, metadata.UpdaterName+".json") {
		return ErrInvalidDefinition
	}
	for _, hash := range []string{metadata.HostdDefinitionSHA256, metadata.UpdaterDefinitionSHA256} {
		decoded, err := hex.DecodeString(hash)
		if err != nil || len(decoded) != sha256.Size {
			return ErrInvalidDefinition
		}
	}
	if !nativeWindowsRebootHealthAddressValid(metadata.HostdHealth) || !nativeWindowsRebootHealthAddressValid(metadata.UpdaterHealth) {
		return ErrInvalidDefinition
	}
	suffix := strings.TrimPrefix(metadata.Instance, "trk34-reboot-")
	if metadata.HostdWorkloadFailure != filepath.Join(os.TempDir(), nativeWindowsRebootMetadataPrefix+suffix+"-hostd-workload.failure.txt") || metadata.UpdaterWorkloadFailure != filepath.Join(os.TempDir(), nativeWindowsRebootMetadataPrefix+suffix+"-updater-workload.failure.txt") {
		return ErrInvalidDefinition
	}
	return nil
}

func nativeWindowsRebootHealthAddressValid(address string) bool {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return false
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port > 0 && port <= 65535
}

func nativeWindowsLifecycleOperation(t *testing.T, name string, operation func(context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), nativeWindowsLifecycleTimeout)
	defer cancel()
	if err := operation(ctx); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func nativeWindowsRetryReadiness(probe func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		if ctx == nil || probe == nil {
			return ErrLifecycleInvalid
		}
		deadline := time.Now().Add(15 * time.Second)
		var lastErr error
		for {
			lastErr = probe(ctx)
			if lastErr == nil {
				return nil
			}
			if !time.Now().Before(deadline) {
				return lastErr
			}
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
}

func nativeWindowsServiceFailureDetails(root string, workloadPaths ...string) string {
	var details []string
	for _, role := range []string{"hostd", "updater"} {
		path := filepath.Join(root, role+".failure.txt")
		body, err := os.ReadFile(path)
		if err == nil && len(body) > 0 {
			details = append(details, role+"="+strings.TrimSpace(string(body)))
		}
	}
	for _, path := range workloadPaths {
		body, err := os.ReadFile(path)
		if err == nil && len(body) > 0 {
			details = append(details, filepath.Base(path)+"="+strings.TrimSpace(string(body)))
		}
	}
	if len(details) == 0 {
		return "none"
	}
	return strings.Join(details, "; ")
}

func installNativeWindowsServiceTestExecutable(t *testing.T) (string, string) {
	return installNativeWindowsServiceTestExecutableWithCleanup(t, true)
}

func installNativeWindowsServiceTestExecutableWithCleanup(t *testing.T, cleanup bool) (string, string) {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsExecutable(source, false); err != nil {
		t.Fatalf("invalid native test executable %q: %v", source, err)
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	root, err := os.MkdirTemp(programData, nativeWindowsServiceTestPrefix)
	if err != nil {
		t.Fatalf("create native test executable root: %v", err)
	}
	if err := prepareAtomicDirectory(root); err != nil {
		_ = os.RemoveAll(root)
		t.Fatalf("protect native test executable root: %v", err)
	}
	if cleanup {
		t.Cleanup(func() {
			if err := cleanupNativeWindowsTestRoot(root); err != nil {
				t.Errorf("cleanup native test executable root %q: %v", root, err)
			}
		})
	}
	destination := filepath.Join(root, "service.test.exe")
	if err := copyNativeWindowsTestExecutable(source, destination); err != nil {
		t.Fatalf("copy native test executable: %v", err)
	}
	return destination, root
}

func copyNativeWindowsTestExecutable(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return err
	}
	if _, err := output.ReadFrom(input); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	return validateWindowsExecutable(destination, false)
}

func cleanupNativeWindowsTestRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || !strings.HasPrefix(strings.ToLower(filepath.Base(root)), nativeWindowsServiceTestPrefix) {
		return ErrInvalidDefinition
	}
	if err := validateWindowsDirectoryNoReparse(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		err := os.RemoveAll(root)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func nativeWindowsUniqueInstance(t *testing.T) string {
	t.Helper()
	var bytes [10]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		t.Fatal(err)
	}
	instance := "trk34-" + hex.EncodeToString(bytes[:])
	if !safeWindowsServiceKind(HostdKind, instance) || len(instance) > windowsServiceInstanceMax {
		t.Fatalf("generated instance is not bounded: %q", instance)
	}
	return instance
}

func nativeWindowsHealthAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func nativeWindowsCurrentUserSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current user SID: %v", err)
	}
	return user.User.Sid.String()
}

func nativeWindowsHasSelectableOwnerSession(t *testing.T, ownerSID string) bool {
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

func nativeWindowsServiceExists(name string) (bool, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return true, service.Close()
}

func createNativeWindowsForeignService(name string) (bool, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer manager.Disconnect()
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	foreignExecutable := filepath.Join(systemRoot, "System32", "cmd.exe")
	service, err := manager.CreateService(name, foreignExecutable, mgr.Config{
		ServiceType: windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:   mgr.StartManual, ErrorControl: mgr.ErrorNormal,
		DisplayName: name, Description: "foreign qualification fixture",
		ServiceStartName: "LocalSystem",
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, "/d", "/s", "/c", "exit", "0")
	if err != nil {
		return false, err
	}
	return true, service.Close()
}

func deleteNativeWindowsService(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), nativeWindowsLifecycleTimeout)
	defer cancel()
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	service, err := manager.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		_ = manager.Disconnect()
		return nil
	}
	if err != nil {
		_ = manager.Disconnect()
		return err
	}
	stopErr := stopWindowsService(ctx, service)
	if stopErr != nil && !errors.Is(stopErr, windows.ERROR_SERVICE_NOT_ACTIVE) {
		_ = service.Close()
		_ = manager.Disconnect()
		return stopErr
	}
	deleteErr := service.Delete()
	closeErr := service.Close()
	disconnectErr := manager.Disconnect()
	if deleteErr != nil && !errors.Is(deleteErr, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return errors.Join(deleteErr, closeErr, disconnectErr)
	}
	return errors.Join(closeErr, disconnectErr, waitWindowsServiceDeletion(ctx, name))
}

func nativeWindowsServiceConfig(t *testing.T, name string) mgr.Config {
	t.Helper()
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(name)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	config, err := service.Config()
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func assertNativeWindowsServiceConfiguration(t *testing.T, name string, installer *Installer, running bool) {
	t.Helper()
	config := nativeWindowsServiceConfig(t, name)
	definition, err := readWindowsServiceDefinition(installer.DefinitionPath())
	if err != nil {
		t.Fatal(err)
	}
	wantPath := windows.ComposeCommandLine(append([]string{definition.Executable}, definition.Arguments...))
	if !strings.EqualFold(config.BinaryPathName, wantPath) || config.StartType != mgr.StartAutomatic || !isWindowsSystemAccount(config.ServiceStartName) || config.SidType != windows.SERVICE_SID_TYPE_UNRESTRICTED {
		t.Fatalf("service %q config=%+v, want automatic LocalSystem owned declaration", name, config)
	}
	actions, err := func() ([]mgr.RecoveryAction, error) {
		manager, err := mgr.Connect()
		if err != nil {
			return nil, err
		}
		defer manager.Disconnect()
		service, err := manager.OpenService(name)
		if err != nil {
			return nil, err
		}
		defer service.Close()
		return service.RecoveryActions()
	}()
	if err != nil || len(actions) != 3 {
		t.Fatalf("service %q recovery actions=%v err=%v", name, actions, err)
	}
	for index, action := range actions {
		wantDelay := []time.Duration{5 * time.Second, 15 * time.Second, time.Minute}[index]
		if action.Type != mgr.ServiceRestart || action.Delay != wantDelay {
			t.Fatalf("service %q recovery action %d=%+v", name, index, action)
		}
	}
	nonCrash, err := func() (bool, error) {
		manager, err := mgr.Connect()
		if err != nil {
			return false, err
		}
		defer manager.Disconnect()
		service, err := manager.OpenService(name)
		if err != nil {
			return false, err
		}
		defer service.Close()
		return service.RecoveryActionsOnNonCrashFailures()
	}()
	if err != nil || !nonCrash {
		t.Fatalf("service %q non-crash recovery=%v err=%v", name, nonCrash, err)
	}
	status, err := WindowsController{}.Inspect(context.Background(), installer.DefinitionPath())
	if err != nil || status.Running != running || status.Ready != running || !status.Enabled {
		t.Fatalf("service %q status=%+v err=%v running=%v", name, status, err, running)
	}
}

func nativeWindowsServicePID(t *testing.T, name string) uint32 {
	t.Helper()
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(name)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		t.Fatal(err)
	}
	return status.ProcessId
}

type nativeWindowsProcess struct {
	PID       uint32
	ParentPID uint32
}

func nativeWindowsProcessSnapshot(t *testing.T) []nativeWindowsProcess {
	t.Helper()
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snapshot, &entry); err != nil {
		t.Fatal(err)
	}
	result := []nativeWindowsProcess{{PID: entry.ProcessID, ParentPID: entry.ParentProcessID}}
	for {
		err := windows.Process32Next(snapshot, &entry)
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return result
		}
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, nativeWindowsProcess{PID: entry.ProcessID, ParentPID: entry.ParentProcessID})
	}
}

func nativeWindowsChildPIDs(t *testing.T, parentPID uint32, timeout time.Duration) []uint32 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		children := make([]uint32, 0, 1)
		for _, process := range nativeWindowsProcessSnapshot(t) {
			if process.ParentPID == parentPID {
				children = append(children, process.PID)
			}
		}
		if len(children) > 0 {
			return children
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("service process %d has no owner workload child", parentPID)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func waitNativeWindowsProcessGone(pid uint32, timeout time.Duration) error {
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
		closeErr := windows.Close(process)
		if waitErr != nil {
			return errors.Join(waitErr, closeErr)
		}
		if result == windows.WAIT_OBJECT_0 {
			return closeErr
		}
		if closeErr != nil {
			return closeErr
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("process %d remained alive", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func sameComponentStatusExceptRunning(left, right NativeComponentStatus) bool {
	return left.ID == right.ID && left.Installed == right.Installed && left.Enabled == right.Enabled && bytesEqual(left.Definition, right.Definition)
}
