//go:build darwin || linux

package hostinstall

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/binarytarget"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/environmentkey"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostservice"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

const SchemaV1 = "paperboat.host-install/v1"

const journalSchemaV1 = "paperboat.host-install-journal/v1"

var (
	ErrInvalidRequest = errors.New("invalid privileged installation request")
	ErrNotPrivileged  = errors.New("privileged installation requires administrator approval")
)

// Request is the complete allowlist accepted by the privileged installer.
// It deliberately has no generic command, argument, path, or environment fields.
type Request struct {
	Schema                 string                   `json:"schema"`
	Platform               string                   `json:"platform"`
	User                   string                   `json:"user"`
	UID                    int                      `json:"uid"`
	Group                  string                   `json:"group"`
	GID                    int                      `json:"gid"`
	Executable             string                   `json:"executable"`
	Artifact               bootstrap.ArtifactTarget `json:"artifact"`
	Home                   string                   `json:"home"`
	Path                   string                   `json:"path"`
	StateRoot              string                   `json:"state_root"`
	WorkspaceRoot          string                   `json:"workspace_root"`
	ControlURL             string                   `json:"control_url"`
	UserMachineID          string                   `json:"machine_id"`
	Shell                  string                   `json:"shell"`
	HelperListenAddress    string                   `json:"helper_listen_address"`
	SetupMode              string                   `json:"setup_mode"`
	InstallationGeneration int64                    `json:"installation_generation"`
}

func Decode(reader io.Reader) (Request, error) {
	var request Request
	decoder := json.NewDecoder(io.LimitReader(reader, 128<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return Request{}, fmt.Errorf("%w: decode request: %v", ErrInvalidRequest, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Request{}, fmt.Errorf("%w: multiple request values", ErrInvalidRequest)
		}
		return Request{}, fmt.Errorf("%w: finish request: %v", ErrInvalidRequest, err)
	}
	return request, nil
}

func Install(ctx context.Context, request Request) error {
	if os.Geteuid() != 0 {
		return ErrNotPrivileged
	}
	if err := Validate(request, invokingUID()); err != nil {
		return err
	}
	paths := platformPaths()
	var err error
	var legacyHost *service.Installer
	if request.SetupMode == "host" {
		legacyHost, err = hostInstallerWithMissing(request, paths, true)
		if err != nil {
			return errors.Join(ErrInvalidRequest, err)
		}
	}
	hostd, updater, err := pendingInstallers(request, paths)
	if err != nil {
		return errors.Join(ErrInvalidRequest, err)
	}
	lifecycle, err := newLifecycleManager(request, paths, legacyHost, hostd, updater)
	if err != nil {
		return errors.Join(ErrInvalidRequest, err)
	}
	// This is deliberately the first stateful operation. A corrupt or stale
	// service journal must stop the install before token, directory, binary, or
	// native declaration changes begin.
	if err := lifecycle.Recover(ctx); err != nil {
		return err
	}
	if err := ensureHostdToken(paths, request); err != nil {
		return err
	}
	if err := ensureManagedDirectories(paths, request); err != nil {
		return err
	}
	if _, err := ensureEnvironmentHostCredential(ctx, paths, request); err != nil {
		return err
	}
	interrupted, err := recoverInterrupted(paths)
	if err != nil {
		return err
	}
	if err := stageBinary(request.Executable, paths.workerNext, request.Artifact); err != nil {
		return err
	}
	journal := installJournal{Schema: journalSchemaV1, Stage: "prepared", HadWorker: regularFile(paths.worker), UpdatedAt: time.Now().UTC()}
	if err := writeJournal(paths.journal, journal); err != nil {
		return err
	}
	if err := activateBinary(paths.worker, paths.workerNext, paths.workerRollback); err != nil {
		return errors.Join(err, rollbackFiles(paths, journal))
	}
	journal.Stage, journal.UpdatedAt = "binaries_activated", time.Now().UTC()
	if err := writeJournal(paths.journal, journal); err != nil {
		return errors.Join(err, rollbackFiles(paths, journal))
	}
	if interrupted {
		// The binary journal predates the native lifecycle journal. Bring any
		// roles left by that older transaction back through the same durable
		// manager before preparing the new install.
		if err := lifecycle.Uninstall(ctx); err != nil {
			return err
		}
	}
	// Migrate away from the pre-hostd monolithic worker service. Leaving it
	// active would start a second runtime against the same control endpoint.
	legacyWorker, legacyErr := legacyWorkerInstaller(request, paths)
	if legacyErr != nil {
		return errors.Join(legacyErr, rollbackFiles(paths, journal))
	}
	_, legacyWorkerWasInstalledErr := os.Lstat(legacyWorker.DefinitionPath())
	legacyWorkerWasInstalled := legacyWorkerWasInstalledErr == nil
	if err := legacyWorker.Uninstall(ctx); err != nil {
		return errors.Join(err, rollbackFiles(paths, journal))
	}
	restoreLegacyWorker := func(base error) error {
		if !legacyWorkerWasInstalled {
			return base
		}
		return errors.Join(base, legacyWorker.Install(ctx))
	}
	if err := lifecycle.Install(ctx); err != nil {
		return restoreLegacyWorker(errors.Join(err, rollbackFiles(paths, journal)))
	}
	if request.SetupMode == "client" {
		obsoleteHost, hostErr := hostInstaller(request, paths)
		if hostErr != nil {
			return restoreLegacyWorker(errors.Join(hostErr, lifecycle.Uninstall(ctx), rollbackFiles(paths, journal)))
		}
		_, statErr := os.Lstat(obsoleteHost.DefinitionPath())
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return restoreLegacyWorker(errors.Join(statErr, lifecycle.Uninstall(ctx), rollbackFiles(paths, journal)))
		}
		if statErr == nil {
			if err := obsoleteHost.Uninstall(ctx); err != nil {
				return restoreLegacyWorker(errors.Join(err, lifecycle.Uninstall(ctx), rollbackFiles(paths, journal)))
			}
		}
	}
	journal.Stage, journal.UpdatedAt = "services_started", time.Now().UTC()
	return writeJournal(paths.journal, journal)
}

func Commit(request Request) error {
	if os.Geteuid() != 0 {
		return ErrNotPrivileged
	}
	if err := Validate(request, invokingUID()); err != nil {
		return err
	}
	paths := platformPaths()
	journal, err := loadJournal(paths.journal)
	if err != nil || journal.Stage != "services_started" {
		return ErrInvalidRequest
	}
	for _, pair := range [][2]string{{paths.workerRollback, paths.workerPrevious}} {
		if err := replacePrevious(pair[0], pair[1]); err != nil {
			return err
		}
	}
	if err := writeInstallMetadata(paths.metadata, request); err != nil {
		return err
	}
	return removeJournal(paths.journal)
}

func Uninstall(ctx context.Context, request Request) error {
	if os.Geteuid() != 0 {
		return ErrNotPrivileged
	}
	if err := Validate(request, invokingUID()); err != nil {
		return err
	}
	return uninstallValidated(ctx, request, platformPaths())
}

func UninstallPersisted(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return ErrNotPrivileged
	}
	paths := platformPaths()
	request, err := loadInstallMetadata(paths.metadata, invokingUID())
	if errors.Is(err, os.ErrNotExist) && paths.legacyMetadata != "" {
		request, err = loadInstallMetadata(paths.legacyMetadata, invokingUID())
	}
	if err != nil {
		return err
	}
	return uninstallValidated(ctx, request, paths)
}

// Repair re-applies both native role declarations as one transaction. The
// lifecycle journal is recovered before any declaration or service-manager
// mutation, so a stale/corrupt prior operation fails closed.
func Repair(ctx context.Context, request Request) error {
	if os.Geteuid() != 0 {
		return ErrNotPrivileged
	}
	if err := Validate(request, invokingUID()); err != nil {
		return err
	}
	paths := platformPaths()
	hostd, updater, err := pendingInstallers(request, paths)
	if err != nil {
		return errors.Join(ErrInvalidRequest, err)
	}
	var legacyHost *service.Installer
	if request.SetupMode == "host" {
		legacyHost, err = hostInstallerWithMissing(request, paths, true)
		if err != nil {
			return errors.Join(ErrInvalidRequest, err)
		}
	}
	lifecycle, err := newLifecycleManager(request, paths, legacyHost, hostd, updater)
	if err != nil {
		return errors.Join(ErrInvalidRequest, err)
	}
	if err := lifecycle.Recover(ctx); err != nil {
		return err
	}
	if err := ensureHostdToken(paths, request); err != nil {
		return err
	}
	if err := ensureManagedDirectories(paths, request); err != nil {
		return err
	}
	credentialCreated, err := ensureEnvironmentHostCredential(ctx, paths, request)
	if err != nil {
		return err
	}
	if !regularFile(paths.worker) {
		return fmt.Errorf("%w: installed runtime binary is missing", ErrInvalidRequest)
	}
	if credentialCreated {
		// A running systemd service cannot gain a newly declared credential
		// without a process restart. Repair is the explicit user-authorized
		// maintenance path for this one-time cutover.
		if err := lifecycle.Stop(ctx); err != nil {
			return err
		}
	}
	return lifecycle.Repair(ctx)
}

// RepairPersisted restores the exact previously installed host role without
// accepting caller-selected paths, commands, identities, or service names.
// It is the safe recovery path used by `pb tunnel create` when the durable
// host runtime is enrolled but stopped or damaged.
func RepairPersisted(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return ErrNotPrivileged
	}
	paths := platformPaths()
	request, err := loadInstallMetadata(paths.metadata, invokingUID())
	if errors.Is(err, os.ErrNotExist) && paths.legacyMetadata != "" {
		request, err = loadInstallMetadata(paths.legacyMetadata, invokingUID())
	}
	if err != nil {
		return err
	}
	return Repair(ctx, request)
}

// Stop stops hostd and updated in dependency order without removing their
// declarations. Recovery is always performed first so an interrupted prior
// install/repair cannot be hidden by a new stop request.
func Stop(ctx context.Context, request Request) error {
	if os.Geteuid() != 0 {
		return ErrNotPrivileged
	}
	if err := Validate(request, invokingUID()); err != nil {
		return err
	}
	paths := platformPaths()
	hostd, updater, err := pendingInstallers(request, paths)
	if err != nil {
		return errors.Join(ErrInvalidRequest, err)
	}
	var legacyHost *service.Installer
	if request.SetupMode == "host" {
		legacyHost, err = hostInstallerWithMissing(request, paths, true)
		if err != nil {
			return errors.Join(ErrInvalidRequest, err)
		}
	}
	lifecycle, err := newLifecycleManager(request, paths, legacyHost, hostd, updater)
	if err != nil {
		return errors.Join(ErrInvalidRequest, err)
	}
	if err := lifecycle.Recover(ctx); err != nil {
		return err
	}
	return lifecycle.Stop(ctx)
}

func uninstallValidated(ctx context.Context, request Request, paths installPaths) error {
	hostd, updater, err := pendingInstallers(request, paths)
	if err != nil {
		return errors.Join(ErrInvalidRequest, err)
	}
	var legacyHost *service.Installer
	if request.SetupMode == "host" {
		legacyHost, err = hostInstallerWithMissing(request, paths, true)
		if err != nil {
			return errors.Join(ErrInvalidRequest, err)
		}
	}
	lifecycle, err := newLifecycleManager(request, paths, legacyHost, hostd, updater)
	if err != nil {
		return errors.Join(ErrInvalidRequest, err)
	}
	// Recovery is intentionally before the first stop/remove operation. A
	// malformed or stale journal therefore leaves native declarations intact
	// for an explicit repair decision.
	if err := lifecycle.Recover(ctx); err != nil {
		return err
	}
	restorePower := func(context.Context) error { return nil }
	if request.SetupMode == "host" {
		restorePower = func(restoreCtx context.Context) error {
			return hostservice.NewPlatformApplier(filepath.Join(paths.runtimeState, "power-baseline.json")).Apply(restoreCtx, hostservice.AllowSleep)
		}
	}
	return finalizeUninstall(ctx, request, paths, lifecycle.Uninstall, restorePower)
}

// finalizeUninstall is the only path allowed to remove installed binaries and
// metadata. Native removal and host power restoration must both succeed first;
// otherwise an active or partially restored service could be left pointing at
// files that have already been deleted.
func finalizeUninstall(ctx context.Context, request Request, paths installPaths, uninstallService func(context.Context) error, restorePower func(context.Context) error) error {
	if ctx == nil || uninstallService == nil || restorePower == nil {
		return ErrInvalidRequest
	}
	if err := uninstallService(ctx); err != nil {
		return err
	}
	if err := restorePower(ctx); err != nil {
		return err
	}
	journal, journalErr := loadJournal(paths.journal)
	if journalErr == nil {
		return rollbackFiles(paths, journal)
	}
	if !errors.Is(journalErr, os.ErrNotExist) {
		return journalErr
	}
	return removeInstalledFiles(paths)
}

func installers(request Request, paths installPaths) (*service.Installer, *service.Installer, error) {
	return installersWithMissing(request, paths, false)
}

func pendingInstallers(request Request, paths installPaths) (*service.Installer, *service.Installer, error) {
	return installersWithMissing(request, paths, true)
}

func installersWithMissing(request Request, paths installPaths, allowMissingExecutable bool) (*service.Installer, *service.Installer, error) {
	layout, err := componentLayout(paths)
	if err != nil {
		return nil, nil, err
	}
	hostdController, err := service.ComponentController(request.Platform, service.HostdKind, request.UID, service.ExecRunner{})
	if err != nil {
		return nil, nil, err
	}
	hostdConfig := service.ComponentConfig{
		Layout: layout, User: request.User, Group: request.Group, UID: request.UID, GID: request.GID,
		HostdTokenFile: paths.hostdToken, Environment: workerEnvironment(request), Controller: hostdController,
	}
	if request.Platform == "linux" && request.SetupMode == "host" {
		hostdConfig.EncryptedCredentials = map[string]string{environmentkey.CredentialName: paths.environmentCredential}
	}
	var hostd *service.Installer
	if allowMissingExecutable {
		hostd, err = service.NewHostdInstallerPending(hostdConfig)
	} else {
		hostd, err = service.NewHostdInstaller(hostdConfig)
	}
	if err != nil {
		return nil, nil, err
	}
	updaterController, err := service.ComponentController(request.Platform, service.UpdaterKind, request.UID, service.ExecRunner{})
	if err != nil {
		return nil, nil, err
	}
	updaterConfig := service.ComponentConfig{
		Layout: layout, User: request.User, Group: request.Group, UID: request.UID, GID: request.GID,
		HostdTokenFile: paths.hostdToken, ReleaseRepository: request.Artifact.RepositoryURL, MachineID: request.UserMachineID,
		HealthURL: "http://" + request.HelperListenAddress + "/healthz", Controller: updaterController,
	}
	var updater *service.Installer
	if allowMissingExecutable {
		updater, err = service.NewUpdaterInstallerPending(updaterConfig)
	} else {
		updater, err = service.NewUpdaterInstaller(updaterConfig)
	}
	if err != nil {
		return nil, nil, err
	}
	return hostd, updater, nil
}

func newLifecycleManager(request Request, paths installPaths, host, hostd, updater *service.Installer) (*service.LifecycleManager, error) {
	if hostd == nil || updater == nil {
		return nil, service.ErrLifecycleInvalid
	}
	probe, err := service.NewHTTPReadinessProbe("http://" + request.HelperListenAddress + "/healthz")
	if err != nil {
		return nil, err
	}
	return service.NewHostLifecycleManager(service.HostLifecycleConfig{
		StateRoot:  filepath.Join(paths.installerState, "service-lifecycle"),
		Host:       host,
		Hostd:      hostd,
		Updater:    updater,
		HostdProbe: probe,
		// updated has no public HTTP health endpoint. Its native ready state and
		// authenticated hostd/update control transaction are the readiness
		// boundary; do not invent a second loopback endpoint.
		UpdaterProbe: nil,
	})
}

func legacyWorkerInstaller(request Request, paths installPaths) (*service.Installer, error) {
	controller := service.Controller(service.SystemdController{Runner: service.ExecRunner{}})
	if runtime.GOOS == "darwin" {
		controller = service.LaunchdController{Runner: service.ExecRunner{}, UID: request.UID}
	}
	return service.New(service.Config{
		Platform: request.Platform, Kind: service.WorkerKind, ConfigRoot: string(os.PathSeparator), Executable: paths.worker,
		User: request.User, Group: request.Group, Arguments: []string{"__runtime-host"}, Controller: controller,
		Environment: workerEnvironment(request),
	})
}

func componentLayout(paths installPaths) (service.Layout, error) {
	layout, err := service.DefaultLayout(runtime.GOOS)
	if err != nil {
		return service.Layout{}, err
	}
	layout.InstallRoot = paths.root
	layout.ReleasesRoot = filepath.Join(paths.root, "releases")
	layout.Binary = paths.worker
	layout.BinaryRollback = paths.workerRollback
	layout.BinaryStaged = paths.workerNext
	layout.UpdateStateRoot = paths.updateState
	layout.HostdSocket = paths.hostdSocket
	if err := layout.Validate(); err != nil {
		return service.Layout{}, err
	}
	return layout, nil
}

func hostInstaller(request Request, paths installPaths) (*service.Installer, error) {
	return hostInstallerWithMissing(request, paths, false)
}

func hostInstallerWithMissing(request Request, paths installPaths, allowMissingExecutable bool) (*service.Installer, error) {
	hostController := service.Controller(service.SystemdController{Runner: service.ExecRunner{}, Unit: "paperboat-runtime-privileged.service"})
	rootGroup := "root"
	if runtime.GOOS == "darwin" {
		rootGroup = "wheel"
		hostController = service.LaunchdController{Runner: service.ExecRunner{}, UID: request.UID, Label: service.HostLabel}
	}
	config := service.Config{
		Platform: request.Platform, Kind: service.HostKind, ConfigRoot: string(os.PathSeparator), Executable: paths.worker,
		User: "root", Group: rootGroup, Arguments: []string{
			"__runtime-host-service", "--uid", strconv.Itoa(request.UID), "--gid", strconv.Itoa(request.GID),
			"--listen-address", request.HelperListenAddress,
		}, Controller: hostController,
	}
	var host *service.Installer
	var err error
	if allowMissingExecutable {
		host, err = service.NewPending(config)
	} else {
		host, err = service.New(config)
	}
	if err != nil {
		return nil, err
	}
	return host, nil
}

type installPaths struct {
	root, installerState, runtimeState                   string
	worker, workerNext, workerRollback, workerPrevious   string
	journal, metadata, legacyMetadata                    string
	hostdToken, hostdSocket, updaterSocket, updateState  string
	environmentCredentialDirectory                       string
	environmentCredential, environmentCredentialMetadata string
}
type installJournal struct {
	Schema    string    `json:"schema"`
	Stage     string    `json:"stage"`
	HadWorker bool      `json:"had_worker"`
	UpdatedAt time.Time `json:"updated_at"`
}

func platformPaths() installPaths {
	root := "/usr/local/libexec/paperboat"
	installerState, runtimeState := "/var/lib/paperboat-installer", "/var/lib/paperboat"
	legacyMetadata := filepath.Join(runtimeState, "install-metadata.json")
	if runtime.GOOS == "darwin" {
		root = "/Library/PrivilegedHelperTools/Paperboat"
		installerState = "/Library/Application Support/Paperboat"
		runtimeState = installerState
		legacyMetadata = ""
	}
	p := installPaths{root: root, installerState: installerState, runtimeState: runtimeState, legacyMetadata: legacyMetadata}
	p.worker = filepath.Join(root, "pb")
	// Release slots are kept in a dedicated root-owned directory so the
	// updater can atomically stage, promote, and roll back without touching the
	// command path or relying on a caller-controlled location.
	releases := filepath.Join(root, "releases")
	p.workerNext = filepath.Join(releases, "pb.staged")
	p.workerRollback = filepath.Join(releases, "pb.rollback")
	p.workerPrevious = filepath.Join(releases, "pb.previous")
	p.journal = filepath.Join(installerState, "install-journal.json")
	p.metadata = filepath.Join(installerState, "install-metadata.json")
	p.hostdToken = filepath.Join(runtimeState, "hostd.token")
	p.hostdSocket = "/var/run/paperboat-hostd/hostd.sock"
	p.updaterSocket = "/var/run/paperboat-updated/control.sock"
	p.updateState = "/var/lib/paperboat-updated"
	if runtime.GOOS == "darwin" {
		p.updateState = filepath.Join(runtimeState, "updated")
	} else {
		p.environmentCredentialDirectory = filepath.Join(installerState, "environment")
		p.environmentCredential = filepath.Join(p.environmentCredentialDirectory, "host-key.cred")
		p.environmentCredentialMetadata = filepath.Join(p.environmentCredentialDirectory, "host-key.json")
	}
	return p
}

func ensureHostdToken(paths installPaths, request Request) error {
	// Hostd runs as the enrolled user, while the token directory is root-owned.
	// Keep the directory non-writable to that user but traversable so hostd can
	// read its 0600 token file.
	if err := secureRootDirectory(filepath.Dir(paths.hostdToken), 0o755); err != nil {
		return err
	}
	info, err := os.Lstat(paths.hostdToken)
	if errors.Is(err, os.ErrNotExist) {
		token := make([]byte, 32)
		if _, err := rand.Read(token); err != nil {
			return err
		}
		if err := os.WriteFile(paths.hostdToken, token, 0o600); err != nil {
			return err
		}
	} else if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return ErrInvalidRequest
	}
	if err := os.Chown(paths.hostdToken, request.UID, request.GID); err != nil {
		return err
	}
	return os.Chmod(paths.hostdToken, 0o600)
}

func ensureManagedDirectories(paths installPaths, request Request) error {
	// hostd runs as the enrolled account and must be able to create its
	// authenticated socket and fence state. The updater remains root-owned.
	hostdDir := filepath.Dir(paths.hostdSocket)
	if err := secureManagedUserDirectory(hostdDir, 0o700, request.UID, request.GID); err != nil {
		return err
	}
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Dir(paths.updaterSocket), 0o755},
		{paths.updateState, 0o700},
		{filepath.Join(paths.root, "releases"), 0o755},
	} {
		if err := secureRootDirectory(item.path, item.mode); err != nil {
			return err
		}
	}
	return nil
}

func ensureEnvironmentHostCredential(ctx context.Context, paths installPaths, request Request) (bool, error) {
	if request.SetupMode != "host" || request.Platform != "linux" {
		return false, nil
	}
	if request.InstallationGeneration < 1 {
		return false, ErrInvalidRequest
	}
	return environmentkey.EnsureSystemdCredential(ctx, environmentkey.ProvisionConfig{
		CiphertextPath: paths.environmentCredential,
		MachineID:      request.UserMachineID, Generation: uint64(request.InstallationGeneration),
	})
}

// secureManagedUserDirectory accepts the two owners that can safely have
// created a runtime socket directory: root from a prior installation, or the
// enrolled account from a running hostd. It rejects every other owner and
// never follows symlinks before transferring ownership to the enrolled user.
func secureManagedUserDirectory(path string, mode os.FileMode, uid, gid int) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalidRequest
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, mode); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return ErrInvalidRequest
	}
	owner := ownerUID(info)
	if owner != 0 && owner != uid {
		return ErrInvalidRequest
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func writeInstallMetadata(path string, request Request) error {
	if err := secureRootDirectory(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	return atomicfile.Write(path, body, atomicfile.Options{Mode: 0o600, OwnerUID: os.Geteuid(), OwnerGID: -1})
}

func loadInstallMetadata(path string, sudoUID int) (Request, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Request{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || ownerUID(info) != 0 || info.Size() < 1 || info.Size() > 128<<10 {
		return Request{}, ErrInvalidRequest
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return Request{}, err
	}
	request, err := Decode(strings.NewReader(string(body)))
	if err != nil || request.Schema != SchemaV1 || request.Platform != runtime.GOOS || !validRunIdentity(request) || request.UID != sudoUID {
		return Request{}, ErrInvalidRequest
	}
	account, err := user.Lookup(request.User)
	if err != nil || account.Uid != strconv.Itoa(request.UID) || account.Gid != strconv.Itoa(request.GID) || account.HomeDir != request.Home {
		return Request{}, ErrInvalidRequest
	}
	group, err := user.LookupGroup(request.Group)
	if err != nil || group.Gid != strconv.Itoa(request.GID) {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

func stageBinary(source, destination string, manifest bootstrap.ArtifactTarget) error {
	if err := secureRootDirectory(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	//paperboat:allow-source-policy atomic-replacement owner=host-install reason=streamed-binary-staging
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".binary-*")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	if err := temporary.Chmod(0o755); err != nil {
		temporary.Close()
		return err
	}
	written, err := io.Copy(temporary, io.LimitReader(input, 256<<20+1))
	if err != nil || written < 1 || written > 256<<20 {
		temporary.Close()
		return ErrInvalidRequest
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=host-install reason=verified-stage-publication
	if err := os.Rename(path, destination); err != nil {
		return err
	}
	return nil
}

func activateBinary(current, next, rollback string) error {
	if err := os.Remove(rollback); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if info, err := os.Lstat(current); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || ownerUID(info) != 0 {
			return ErrInvalidRequest
		}
		//paperboat:allow-source-policy atomic-replacement owner=host-install reason=current-binary-rollback-stage
		if err := os.Rename(current, rollback); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=host-install reason=verified-binary-activation
	return os.Rename(next, current)
}

func rollbackFiles(paths installPaths, journal installJournal) error {
	var result error
	for _, item := range []struct {
		current, rollback string
		had               bool
	}{{paths.worker, paths.workerRollback, journal.HadWorker}} {
		rollbackExists := regularFile(item.rollback)
		if rollbackExists || !item.had {
			if err := os.Remove(item.current); err != nil && !errors.Is(err, os.ErrNotExist) {
				result = errors.Join(result, err)
			}
		}
		if item.had && rollbackExists {
			//paperboat:allow-source-policy atomic-replacement owner=host-install reason=journaled-install-rollback
			if err := os.Rename(item.rollback, item.current); err != nil {
				result = errors.Join(result, err)
			}
		} else if !item.had {
			_ = os.Remove(item.rollback)
		}
	}
	_ = os.Remove(paths.workerNext)
	return errors.Join(result, removeJournal(paths.journal))
}

func recoverInterrupted(paths installPaths) (bool, error) {
	journal, err := loadJournal(paths.journal)
	if errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(paths.workerNext)
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, rollbackFiles(paths, journal)
}

func writeJournal(path string, journal installJournal) error {
	if err := secureRootDirectory(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return atomicfile.Write(path, body, atomicfile.Options{Mode: 0o600, OwnerUID: os.Geteuid(), OwnerGID: -1})
}

func loadJournal(path string) (installJournal, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return installJournal{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 4096 || ownerUID(info) != 0 {
		return installJournal{}, ErrInvalidRequest
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return installJournal{}, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var journal installJournal
	if decoder.Decode(&journal) != nil || journal.Schema != journalSchemaV1 || !slices.Contains([]string{"prepared", "binaries_activated", "services_started"}, journal.Stage) {
		return installJournal{}, ErrInvalidRequest
	}
	return journal, nil
}

func replacePrevious(rollback, previous string) error {
	if _, err := os.Lstat(rollback); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := os.Remove(previous); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	//paperboat:allow-source-policy atomic-replacement owner=host-install reason=verified-previous-retention
	return os.Rename(rollback, previous)
}
func removeJournal(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
func removeInstalledFiles(paths installPaths) error {
	var result error
	for _, path := range []string{
		paths.worker, paths.workerNext, paths.workerRollback, paths.workerPrevious,
		paths.metadata, paths.legacyMetadata,
		paths.hostdToken, paths.hostdSocket, paths.updaterSocket,
		paths.environmentCredential, paths.environmentCredentialMetadata,
		filepath.Join(paths.runtimeState, "power-baseline.json"),
		filepath.Join(paths.runtimeState, "availability-policy.json"),
		filepath.Join(paths.runtimeState, "update-current.json"),
		filepath.Join(paths.runtimeState, "update-journal.json"),
		filepath.Join(paths.runtimeState, "update-rollbacks.json"),
		filepath.Join(paths.runtimeState, "privileged-updates", "update-current.json"),
		filepath.Join(paths.runtimeState, "privileged-updates", "update-journal.json"),
		filepath.Join(paths.runtimeState, "privileged-updates", "update-rollbacks.json"),
		filepath.Join(paths.runtimeState, "privileged-updates"),
	} {
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	for _, directory := range []string{paths.environmentCredentialDirectory, paths.updateState, filepath.Dir(paths.hostdSocket), filepath.Dir(paths.updaterSocket), filepath.Join(paths.root, "releases")} {
		if directory == "" || directory == "." || directory == string(filepath.Separator) || !filepath.IsAbs(directory) {
			continue
		}
		if err := os.RemoveAll(directory); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}
func regularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
func secureRootDirectory(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || ownerUID(info) != 0 {
		return ErrInvalidRequest
	}
	return os.Chmod(path, mode)
}

func Validate(request Request, sudoUID int) error {
	if request.Schema != SchemaV1 || request.Platform != runtime.GOOS || !validRunIdentity(request) || sudoUID != request.UID ||
		request.UserMachineID == "" || !slices.Contains([]string{"client", "host"}, request.SetupMode) || strings.ContainsAny(request.UserMachineID, "\x00\r\n") ||
		request.SetupMode == "host" && request.InstallationGeneration < 1 {
		return fmt.Errorf("%w: identity contract", ErrInvalidRequest)
	}
	account, err := user.Lookup(request.User)
	if err != nil || account.Uid != strconv.Itoa(request.UID) || account.Gid != strconv.Itoa(request.GID) || account.HomeDir != request.Home {
		return fmt.Errorf("%w: user account", ErrInvalidRequest)
	}
	group, err := user.LookupGroup(request.Group)
	if err != nil || group.Gid != strconv.Itoa(request.GID) {
		return fmt.Errorf("%w: user group", ErrInvalidRequest)
	}
	if err := bootstrap.VerifyArtifactTarget(request.Artifact); err != nil || request.Artifact.Platform != request.Platform {
		return fmt.Errorf("%w: TUF target descriptor", ErrInvalidRequest)
	}
	if err := verifyArtifact(request.Executable, request.UID, request.Platform); err != nil {
		return fmt.Errorf("%w: TUF target file", ErrInvalidRequest)
	}
	if err := binarytarget.Validate(request.Executable, request.Platform, request.Artifact.Architecture); err != nil {
		return fmt.Errorf("%w: target architecture", ErrInvalidRequest)
	}
	for _, path := range []string{request.Home, request.StateRoot, request.WorkspaceRoot} {
		if !canonicalOwnedDirectory(path, request.UID) {
			return fmt.Errorf("%w: owned directory %q", ErrInvalidRequest, path)
		}
	}
	if !canonicalExecutable(request.Shell) {
		return fmt.Errorf("%w: login shell", ErrInvalidRequest)
	}
	if !pathListValid(request.Path) {
		return fmt.Errorf("%w: service PATH", ErrInvalidRequest)
	}
	parsed, err := url.Parse(request.ControlURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("%w: control URL", ErrInvalidRequest)
	}
	host, port, err := net.SplitHostPort(request.HelperListenAddress)
	if err != nil || port == "" || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("%w: helper listen address", ErrInvalidRequest)
	}
	return nil
}

func validRunIdentity(request Request) bool {
	return request.UID > 0 && request.GID > 0 || request.UID == 0 && request.GID == 0 && request.User == "root"
}

func workerEnvironment(request Request) map[string]string {
	return map[string]string{
		"HOME": request.Home, "PATH": request.Path, "PAPERBOAT_RUNTIME_PROFILE": "byod",
		"PAPERBOAT_RUNTIME_STATE_ROOT": request.StateRoot, "PAPERBOAT_WORKSPACE_ROOT": request.WorkspaceRoot,
		"PAPERBOAT_CONTROL_URL": request.ControlURL, "PAPERBOAT_MACHINE_ID": request.UserMachineID,
		"PAPERBOAT_SHELL": request.Shell, "PAPERBOAT_RUNTIME_LISTEN_ADDRESS": request.HelperListenAddress,
		"PAPERBOAT_RUNTIME_SERVICE_SCOPE": "system",
		"PAPERBOAT_SETUP_MODE":            request.SetupMode,
	}
}

func invokingUID() int {
	value := os.Getenv("SUDO_UID")
	if value == "" {
		value = os.Getenv("PAPERBOAT_INVOKING_UID")
	}
	uid, err := strconv.Atoi(value)
	if err != nil {
		return -1
	}
	return uid
}

func verifyArtifact(path string, uid int, platform string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalidRequest
	}
	lstat, err := os.Lstat(path)
	rootOwnedDarwinPackageBinary := platform == "darwin" && filepath.Clean(path) == "/usr/local/bin/pb" && ownerUID(lstat) == 0
	if err != nil || !lstat.Mode().IsRegular() || lstat.Mode()&os.ModeSymlink != 0 || lstat.Mode().Perm()&0o022 != 0 || (ownerUID(lstat) != uid && !rootOwnedDarwinPackageBinary) {
		return ErrInvalidRequest
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 256<<20 || (ownerUID(info) != uid && !rootOwnedDarwinPackageBinary) {
		return ErrInvalidRequest
	}
	return nil
}

func canonicalOwnedDirectory(path string, uid int) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0 && ownerUID(info) == uid
}

func canonicalExecutable(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o111 != 0 && info.Mode().Perm()&0o022 == 0
}

func pathListValid(value string) bool {
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for _, path := range filepath.SplitList(value) {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return false
		}
	}
	return true
}

func ownerUID(info os.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}

func (r Request) String() string {
	return fmt.Sprintf("%s for uid %d", r.Schema, r.UID)
}
