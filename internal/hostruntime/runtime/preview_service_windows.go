//go:build windows

package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	hostservice "github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	servepkg "github.com/pinksaucepasta/paperboat/internal/serve"
	"golang.org/x/sys/windows"
)

type ServeRuntimeDescriptor struct {
	SourcePath     string              `json:"source_path"`
	SourceKind     servepkg.SourceKind `json:"source_kind"`
	SourceIdentity string              `json:"source_identity"`
	SPA            bool                `json:"spa"`
	OwnerMode      string              `json:"owner_mode"`
	Visibility     string              `json:"visibility"`
	ListenPort     uint16              `json:"listen_port,omitempty"`
}
type PreviewRuntimeDescriptor struct {
	Schema            string                           `json:"schema"`
	Name              string                           `json:"name"`
	BindAddress       string                           `json:"bind_address,omitempty"`
	Port              uint16                           `json:"port"`
	ServiceGeneration uint64                           `json:"service_generation,omitempty"`
	Indefinite        bool                             `json:"indefinite"`
	ExpiresAt         *time.Time                       `json:"expires_at,omitempty"`
	ServiceDefinition string                           `json:"service_definition"`
	Record            *preview.ControlRecord           `json:"record,omitempty"`
	Failure           *PreviewRuntimeFailure           `json:"failure,omitempty"`
	Serve             *ServeRuntimeDescriptor          `json:"serve,omitempty"`
	PrivateRemote     *PrivatePreviewRuntimeDescriptor `json:"private_remote,omitempty"`
}
type PreviewRuntimeFailure struct {
	Code string `json:"code"`
}
type PrivatePreviewRuntimeDescriptor struct {
	MachineID         string `json:"machine_id"`
	MachineName       string `json:"machine_name"`
	EnvironmentID     string `json:"environment_id"`
	MachineGeneration uint64 `json:"machine_generation"`
	TargetPort        uint16 `json:"target_port"`
	ListenPort        uint16 `json:"listen_port,omitempty"`
}

var ErrPreviewAlreadyActive = errors.New("preview name is already active")
var ErrPreviewServiceMissing = errors.New("preview service is missing")
var ErrPreviewServiceFailed = errors.New("preview service failed")

type PreviewServiceFailureError struct{ Code string }

func (e *PreviewServiceFailureError) Error() string {
	if e == nil || e.Code == "" {
		return ErrPreviewServiceFailed.Error()
	}
	return ErrPreviewServiceFailed.Error() + ": " + e.Code
}
func (*PreviewServiceFailureError) Unwrap() error { return ErrPreviewServiceFailed }

var windowsPreviewLocks sync.Map

// These seams keep orphan cleanup deterministic in unit tests while the
// production implementation remains the native SCM/declaration path.
var (
	removeWindowsPreviewService            = hostservice.RemoveWindowsPreviewService
	listWindowsPreviewServiceArtifacts     = hostservice.ListWindowsPreviewServiceArtifacts
	validateWindowsPreviewServiceOwnership = hostservice.ValidateWindowsPreviewServiceOwnership
)

func lockWindowsPreviewStateRoot(root string) func() {
	lockAny, _ := windowsPreviewLocks.LoadOrStore(root, &sync.Mutex{})
	lock := lockAny.(*sync.Mutex)
	lock.Lock()
	return lock.Unlock
}

func previewDescriptorPath(root, name string) string {
	sum := sha256.Sum256([]byte(name))
	return filepath.Join(root, "previews", "active", hex.EncodeToString(sum[:8])+".json")
}
func previewServiceInstance(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:8])
}

// WindowsPreviewServiceName returns the single authoritative SCM name used by
// both service registration and the privileged service entry.
func WindowsPreviewServiceName(name string) (string, error) {
	_, serviceName, err := previewServiceDefinition("", name, "windows")
	return serviceName, err
}

func InstallPreviewService(ctx context.Context, executable, stateRoot, name string, port uint16, expires *time.Time, indefinite bool) (PreviewRuntimeDescriptor, error) {
	return installWindowsPreviewService(ctx, executable, stateRoot, name, port, expires, indefinite, nil, nil, 0)
}
func InstallPrivatePreviewService(ctx context.Context, executable, stateRoot, name string, remote PrivatePreviewRuntimeDescriptor, expires *time.Time, indefinite bool, maximum int) (PreviewRuntimeDescriptor, error) {
	if !validPrivatePreviewRuntimeDescriptor(&remote) || maximum < 1 || maximum > 20 {
		return PreviewRuntimeDescriptor{}, ErrProductionInvalid
	}
	return installWindowsPreviewService(ctx, executable, stateRoot, name, 0, expires, indefinite, nil, &remote, maximum)
}
func InstallServeService(ctx context.Context, executable, stateRoot, name string, source servepkg.Source, spa bool, expires *time.Time, indefinite, public bool, listenPort uint16) (PreviewRuntimeDescriptor, error) {
	identity, err := source.Identity()
	if err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	visibility := "private"
	if public {
		visibility = "public"
		if listenPort != 0 {
			return PreviewRuntimeDescriptor{}, ErrProductionInvalid
		}
	} else if listenPort == 0 {
		return PreviewRuntimeDescriptor{}, ErrProductionInvalid
	}
	serve := &ServeRuntimeDescriptor{SourcePath: source.Path, SourceKind: source.Kind, SourceIdentity: identity, SPA: spa, OwnerMode: "detached", Visibility: visibility, ListenPort: listenPort}
	return installWindowsPreviewService(ctx, executable, stateRoot, name, 0, expires, indefinite, serve, nil, 0)
}
func installWindowsPreviewService(ctx context.Context, executable, root, name string, port uint16, expires *time.Time, indefinite bool, served *ServeRuntimeDescriptor, remote *PrivatePreviewRuntimeDescriptor, maximum int) (PreviewRuntimeDescriptor, error) {
	kinds := 0
	if port != 0 {
		kinds++
	}
	if served != nil {
		kinds++
	}
	if remote != nil {
		kinds++
	}
	if ctx == nil || !filepath.IsAbs(executable) || !filepath.IsAbs(root) || name == "" || kinds != 1 || indefinite == (expires != nil) {
		return PreviewRuntimeDescriptor{}, ErrProductionInvalid
	}
	layout, err := hostservice.DefaultLayout("windows")
	if err != nil || !exactWindowsPreviewPath(executable, layout.RuntimeCurrent) {
		return PreviewRuntimeDescriptor{}, errors.Join(ErrProductionInvalid, err)
	}
	defer lockWindowsPreviewStateRoot(root)()
	if maximum > 0 {
		active, err := activePrivatePreviewServices(root, time.Now().UTC())
		if err != nil {
			return PreviewRuntimeDescriptor{}, err
		}
		if active >= maximum {
			return PreviewRuntimeDescriptor{}, ErrPreviewAlreadyActive
		}
	}
	if err := validateWindowsPreviewDirectoryPath(filepath.Join(root, "previews", "active"), true); err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	path := previewDescriptorPath(root, name)
	if current, err := readPreviewRuntimeDescriptor(path); err == nil && (current.Indefinite || current.ExpiresAt != nil && current.ExpiresAt.After(time.Now().UTC())) {
		return PreviewRuntimeDescriptor{}, ErrPreviewAlreadyActive
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return PreviewRuntimeDescriptor{}, err
	}
	definition, serviceName, err := previewServiceDefinition(root, name, runtime.GOOS)
	if err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	if err := hostservice.ValidateWindowsPreviewServiceOwnership(ctx, serviceName, root); err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	descriptor := PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: name, BindAddress: "127.0.0.1", Port: port, ServiceGeneration: uint64(time.Now().UTC().UnixNano()), Indefinite: indefinite, ExpiresAt: expires, ServiceDefinition: definition, Serve: served, PrivateRemote: remote}
	if err := writePreviewRuntimeDescriptor(path, descriptor); err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	args := []string{"__runtime-preview", "--state-root", root, "--name", name, "--descriptor", path, "--service-definition", definition}
	if served != nil {
		args[0] = "__runtime-serve"
	} else if remote != nil {
		args[0] = "__runtime-private-preview"
	} else {
		args = append(args, "--port", strconv.Itoa(int(port)))
	}
	if indefinite {
		args = append(args, "--indefinite")
	} else {
		args = append(args, "--expires-at", expires.UTC().Format(time.RFC3339Nano))
	}
	installer, err := hostservice.New(hostservice.Config{Platform: "windows", Kind: hostservice.PreviewKind, Instance: previewServiceInstance(name), ConfigRoot: root, Executable: executable, User: "SYSTEM", Group: "Administrators", Arguments: args, Environment: map[string]string{"PAPERBOAT_RUNTIME_SERVICE_SCOPE": "system"}, Controller: hostservice.WindowsController{}})
	if err != nil {
		return PreviewRuntimeDescriptor{}, errors.Join(err, removeWindowsPreviewDescriptor(path))
	}
	if installer.DefinitionPath() != definition {
		return PreviewRuntimeDescriptor{}, errors.Join(ErrProductionInvalid, removeWindowsPreviewDescriptor(path))
	}
	if err := installer.Install(ctx); err != nil {
		return PreviewRuntimeDescriptor{}, errors.Join(err, removeWindowsPreviewDescriptor(path))
	}
	return descriptor, nil
}

func removeWindowsPreviewDescriptor(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
func activePrivatePreviewServices(root string, now time.Time) (int, error) {
	entries, err := os.ReadDir(filepath.Join(root, "previews", "active"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		d, e := readPreviewRuntimeDescriptor(filepath.Join(root, "previews", "active", entry.Name()))
		if e == nil && (d.Indefinite || d.ExpiresAt != nil && d.ExpiresAt.After(now)) && (d.PrivateRemote != nil || d.Serve != nil && d.Serve.Visibility == "private") {
			n++
		}
	}
	return n, nil
}
func previewServiceDefinition(_ string, name, platform string) (string, string, error) {
	if name == "" || platform != "windows" {
		return "", "", ErrProductionInvalid
	}
	instance := previewServiceInstance(name)
	return filepath.Join(`C:\ProgramData\Paperboat\services`, "PaperboatPreview-"+instance+`.json`), "PaperboatPreview-" + instance, nil
}
func retirePreviewServiceWithRoot(ctx context.Context, root, name, definition string, _ hostservice.Runner) error {
	expected, _, err := previewServiceDefinition("", name, "windows")
	if ctx == nil || !validWindowsPreviewStateRoot(root) || err != nil || !exactWindowsPreviewPath(expected, definition) {
		return errors.Join(ErrProductionInvalid, err)
	}
	if os.Getenv("PAPERBOAT_WINDOWS_PREVIEW_OWNER_WORKLOAD") == "1" && os.Getenv("PAPERBOAT_RUNTIME_SERVICE_SCOPE") == "user" {
		// The LocalSystem service parent owns SCM deletion after this enrolled
		// owner child exits. The child may remove only its user-state descriptor.
		return nil
	}
	_, serviceName, err := previewServiceDefinition("", name, "windows")
	if err != nil {
		return errors.Join(ErrProductionInvalid, err)
	}
	return removeWindowsPreviewService(ctx, serviceName, root)
}

func exactWindowsPreviewPath(left, right string) bool {
	return filepath.IsAbs(left) && filepath.IsAbs(right) && filepath.Clean(left) == left && filepath.Clean(right) == right && strings.EqualFold(left, right)
}

func validateWindowsPreviewDirectoryPath(path string, allowMissingTail bool) error {
	if !filepath.IsAbs(path) {
		return ErrProductionInvalid
	}
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && allowMissingTail {
			parent := filepath.Dir(current)
			if parent == current {
				return nil
			}
			current = parent
			continue
		}
		if err != nil {
			return errors.Join(ErrProductionInvalid, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrProductionInvalid
		}
		attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(current))
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.Join(ErrProductionInvalid, err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func readWindowsPreviewActiveEntries(root string) ([]os.DirEntry, error) {
	active := filepath.Join(root, "previews", "active")
	if err := validateWindowsPreviewDirectoryPath(active, true); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(active)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return entries, err
}

func validateWindowsPreviewDescriptorAncestors(path string) error {
	if !filepath.IsAbs(path) {
		return ErrProductionInvalid
	}
	current := filepath.Dir(filepath.Clean(path))
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return errors.Join(ErrProductionInvalid, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrProductionInvalid
		}
		attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(current))
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.Join(ErrProductionInvalid, err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func validateWindowsPreviewDescriptorPath(path, root, name string) error {
	if !exactWindowsPreviewPath(path, previewDescriptorPath(root, name)) {
		return ErrProductionInvalid
	}
	return validateWindowsPreviewDescriptorAncestors(path)
}

func retireCompletedServeService(ctx context.Context, name, path, definition string, runner hostservice.Runner) error {
	root, err := windowsPreviewStateRootFromDescriptorPath(path)
	if err != nil {
		return err
	}
	return retireCompletedServeServiceWithRoot(ctx, root, name, path, definition, runner)
}

func retireCompletedServeServiceWithRoot(ctx context.Context, root, name, path, definition string, runner hostservice.Runner) error {
	if ctx == nil || !validWindowsPreviewStateRoot(root) || name == "" || !filepath.IsAbs(path) || definition == "" {
		return ErrProductionInvalid
	}
	if err := validatePlannedWindowsPreviewDescriptor(path, root, name, definition); err != nil {
		return err
	}
	if err := retirePreviewServiceWithRoot(ctx, root, name, definition, runner); err != nil {
		return err
	}
	if err := validatePlannedWindowsPreviewDescriptor(path, root, name, definition); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func validatePlannedWindowsPreviewDescriptor(path, root, name, definition string) error {
	if err := validateWindowsPreviewDescriptorPath(path, root, name); err != nil {
		return err
	}
	descriptor, err := readPreviewRuntimeDescriptor(path)
	if err != nil {
		return errors.Join(ErrProductionInvalid, err)
	}
	if descriptor.Name != name || !exactWindowsPreviewPath(descriptor.ServiceDefinition, definition) {
		return ErrProductionInvalid
	}
	return nil
}
func RemovePreviewService(ctx context.Context, root, name string) error {
	if ctx == nil || !validWindowsPreviewStateRoot(root) || name == "" {
		return ErrProductionInvalid
	}
	defer lockWindowsPreviewStateRoot(root)()
	path := previewDescriptorPath(root, name)
	d, err := readPreviewRuntimeDescriptor(path)
	if errors.Is(err, os.ErrNotExist) {
		_, serviceName, nameErr := previewServiceDefinition("", name, "windows")
		if nameErr != nil {
			return errors.Join(ErrProductionInvalid, nameErr)
		}
		return removeWindowsPreviewService(ctx, serviceName, root)
	}
	if err != nil || d.Name != name {
		return errors.Join(ErrProductionInvalid, err)
	}
	return retireCompletedServeServiceWithRoot(ctx, root, name, path, d.ServiceDefinition, hostservice.ExecRunner{})
}

type windowsPreviewCleanupPlan struct {
	root             string
	name             string
	serviceName      string
	descriptorPath   string
	definition       string
	removeDescriptor bool
}

func preflightWindowsPreviewDescriptor(root, path string, descriptor PreviewRuntimeDescriptor) (windowsPreviewCleanupPlan, error) {
	if descriptor.Name == "" || descriptor.ServiceDefinition == "" {
		return windowsPreviewCleanupPlan{}, ErrProductionInvalid
	}
	expectedDefinition, serviceName, err := previewServiceDefinition("", descriptor.Name, "windows")
	if err != nil || !exactWindowsPreviewPath(path, previewDescriptorPath(root, descriptor.Name)) || !exactWindowsPreviewPath(descriptor.ServiceDefinition, expectedDefinition) {
		return windowsPreviewCleanupPlan{}, errors.Join(ErrProductionInvalid, err)
	}
	return windowsPreviewCleanupPlan{
		root: root, name: descriptor.Name, serviceName: serviceName,
		descriptorPath: path, definition: descriptor.ServiceDefinition, removeDescriptor: true,
	}, nil
}

func windowsPreviewArtifactMap(artifacts []hostservice.WindowsPreviewServiceArtifact) (map[string]hostservice.WindowsPreviewServiceArtifact, error) {
	byName := make(map[string]hostservice.WindowsPreviewServiceArtifact, len(artifacts))
	for _, artifact := range artifacts {
		if !isWindowsPreviewArtifactName(artifact.Name) {
			return nil, fmt.Errorf("invalid preview service artifact %q: %w", artifact.Name, ErrProductionInvalid)
		}
		key := strings.ToLower(artifact.Name)
		if _, exists := byName[key]; exists {
			return nil, fmt.Errorf("duplicate preview service artifact %q: %w", artifact.Name, ErrProductionInvalid)
		}
		byName[key] = artifact
	}
	return byName, nil
}

func isWindowsPreviewArtifactName(name string) bool {
	if !strings.HasPrefix(name, "PaperboatPreview-") {
		return false
	}
	instance := strings.TrimPrefix(name, "PaperboatPreview-")
	if len(instance) != 16 {
		return false
	}
	for _, character := range instance {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func preflightWindowsPreviewArtifact(ctx context.Context, root string, artifact hostservice.WindowsPreviewServiceArtifact) (windowsPreviewCleanupPlan, error) {
	if !artifact.HasDeclaration {
		if artifact.HasService {
			return windowsPreviewCleanupPlan{}, fmt.Errorf("preview service %s has no declaration: %w", artifact.Name, ErrProductionInvalid)
		}
		return windowsPreviewCleanupPlan{}, nil
	}
	if !validWindowsPreviewStateRoot(artifact.DeclarationRoot) || !strings.EqualFold(filepath.Clean(artifact.DeclarationRoot), filepath.Clean(root)) {
		return windowsPreviewCleanupPlan{}, nil
	}
	if err := validateWindowsPreviewServiceOwnership(ctx, artifact.Name, root); err != nil {
		return windowsPreviewCleanupPlan{}, err
	}
	return windowsPreviewCleanupPlan{root: root, name: artifact.Name, serviceName: artifact.Name}, nil
}

func validateWindowsPreviewArtifactForDescriptor(artifact hostservice.WindowsPreviewServiceArtifact, root string) error {
	if !artifact.HasDeclaration && artifact.HasService {
		return fmt.Errorf("preview service %s has no declaration: %w", artifact.Name, ErrProductionInvalid)
	}
	if artifact.HasDeclaration && (!validWindowsPreviewStateRoot(artifact.DeclarationRoot) || !strings.EqualFold(filepath.Clean(artifact.DeclarationRoot), filepath.Clean(root))) {
		return fmt.Errorf("preview service %s has a conflicting declaration root: %w", artifact.Name, ErrProductionInvalid)
	}
	if !artifact.HasDeclaration && !artifact.HasService {
		return fmt.Errorf("preview service %s has no ownership artifact: %w", artifact.Name, ErrProductionInvalid)
	}
	return nil
}

func applyWindowsPreviewCleanupPlan(ctx context.Context, plan windowsPreviewCleanupPlan) error {
	if plan.removeDescriptor {
		if err := retireCompletedServeServiceWithRoot(ctx, plan.root, plan.name, plan.descriptorPath, plan.definition, hostservice.ExecRunner{}); err != nil {
			return err
		}
		return nil
	}
	return removeWindowsPreviewService(ctx, plan.serviceName, plan.root)
}

func RemoveAllPreviewServices(ctx context.Context, root string) error {
	if ctx == nil || !validWindowsPreviewStateRoot(root) {
		return ErrProductionInvalid
	}
	defer lockWindowsPreviewStateRoot(root)()
	artifacts, err := listWindowsPreviewServiceArtifacts()
	if err != nil {
		return err
	}
	artifactByName, err := windowsPreviewArtifactMap(artifacts)
	if err != nil {
		return err
	}
	entries, err := readWindowsPreviewActiveEntries(root)
	if err != nil {
		return err
	}
	var preflightErr error
	plans := make([]windowsPreviewCleanupPlan, 0, len(entries)+len(artifacts))
	ownedArtifacts := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			if strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
				preflightErr = errors.Join(preflightErr, fmt.Errorf("preview descriptor %s is a directory: %w", entry.Name(), ErrProductionInvalid))
			}
			continue
		}
		if !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			continue
		}
		path := filepath.Join(root, "previews", "active", entry.Name())
		d, e := readPreviewRuntimeDescriptor(path)
		if e != nil {
			preflightErr = errors.Join(preflightErr, fmt.Errorf("read preview service %s: %w", entry.Name(), e))
			continue
		}
		plan, e := preflightWindowsPreviewDescriptor(root, path, d)
		if e != nil {
			preflightErr = errors.Join(preflightErr, fmt.Errorf("validate preview service %s: %w", entry.Name(), e))
			continue
		}
		artifact, ok := artifactByName[strings.ToLower(plan.serviceName)]
		if !ok {
			preflightErr = errors.Join(preflightErr, fmt.Errorf("preview service %s has no ownership artifact: %w", plan.serviceName, ErrProductionInvalid))
			continue
		}
		if e := validateWindowsPreviewArtifactForDescriptor(artifact, root); e != nil {
			preflightErr = errors.Join(preflightErr, e)
			continue
		}
		if e := validateWindowsPreviewServiceOwnership(ctx, plan.serviceName, root); e != nil {
			preflightErr = errors.Join(preflightErr, fmt.Errorf("validate preview service %s ownership: %w", plan.serviceName, e))
			continue
		}
		ownedArtifacts[strings.ToLower(plan.serviceName)] = true
		plans = append(plans, plan)
	}
	for _, artifact := range artifacts {
		key := strings.ToLower(artifact.Name)
		if ownedArtifacts[key] {
			continue
		}
		plan, e := preflightWindowsPreviewArtifact(ctx, root, artifact)
		if e != nil {
			preflightErr = errors.Join(preflightErr, fmt.Errorf("validate preview artifact %s: %w", artifact.Name, e))
			continue
		}
		if plan.serviceName != "" {
			plans = append(plans, plan)
		}
	}
	if preflightErr != nil {
		// Every service, declaration, and descriptor is checked before the first
		// mutation. A later ownership conflict therefore cannot leave a partial
		// uninstall behind.
		return preflightErr
	}
	for _, plan := range plans {
		if err := applyWindowsPreviewCleanupPlan(ctx, plan); err != nil {
			return err
		}
	}
	return nil
}
func ReconcileExpiredPreviewServices(ctx context.Context, root string, now time.Time) error {
	if ctx == nil || !validWindowsPreviewStateRoot(root) || now.IsZero() {
		return ErrProductionInvalid
	}
	defer lockWindowsPreviewStateRoot(root)()
	entries, err := readWindowsPreviewActiveEntries(root)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	artifacts, err := listWindowsPreviewServiceArtifacts()
	if err != nil {
		return err
	}
	artifactByName, err := windowsPreviewArtifactMap(artifacts)
	if err != nil {
		return err
	}
	var preflightErr error
	plans := make([]windowsPreviewCleanupPlan, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			if strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
				preflightErr = errors.Join(preflightErr, fmt.Errorf("preview descriptor %s is a directory: %w", entry.Name(), ErrProductionInvalid))
			}
			continue
		}
		if !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			continue
		}
		path := filepath.Join(root, "previews", "active", entry.Name())
		d, e := readPreviewRuntimeDescriptor(path)
		if e != nil {
			preflightErr = errors.Join(preflightErr, fmt.Errorf("read preview service %s: %w", entry.Name(), e))
			continue
		}
		plan, e := preflightWindowsPreviewDescriptor(root, path, d)
		if e != nil {
			preflightErr = errors.Join(preflightErr, fmt.Errorf("validate preview service %s: %w", entry.Name(), e))
			continue
		}
		if d.Indefinite || d.ExpiresAt == nil || d.ExpiresAt.After(now) {
			continue
		}
		artifact, ok := artifactByName[strings.ToLower(plan.serviceName)]
		if !ok {
			preflightErr = errors.Join(preflightErr, fmt.Errorf("expired preview service %s has no ownership artifact: %w", plan.serviceName, ErrProductionInvalid))
			continue
		}
		if e := validateWindowsPreviewArtifactForDescriptor(artifact, root); e != nil {
			preflightErr = errors.Join(preflightErr, e)
			continue
		}
		if e := validateWindowsPreviewServiceOwnership(ctx, plan.serviceName, root); e != nil {
			preflightErr = errors.Join(preflightErr, fmt.Errorf("validate expired preview service %s ownership: %w", plan.serviceName, e))
			continue
		}
		plans = append(plans, plan)
	}
	if preflightErr != nil {
		return preflightErr
	}
	for _, plan := range plans {
		if err := applyWindowsPreviewCleanupPlan(ctx, plan); err != nil {
			return err
		}
	}
	return nil
}
func WaitPreviewServiceReady(ctx context.Context, root, name string) (preview.ControlRecord, error) {
	path := previewDescriptorPath(root, name)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		d, err := readPreviewRuntimeDescriptor(path)
		if errors.Is(err, os.ErrNotExist) {
			return preview.ControlRecord{}, errors.Join(ErrPreviewServiceMissing, err)
		}
		if err != nil {
			return preview.ControlRecord{}, err
		}
		if d.Record != nil && d.Record.URL != "" {
			return *d.Record, nil
		}
		if d.Record != nil && d.Record.State == "failed" {
			code := ""
			if d.Failure != nil {
				code = d.Failure.Code
			}
			return preview.ControlRecord{}, &PreviewServiceFailureError{Code: code}
		}
		select {
		case <-ctx.Done():
			return preview.ControlRecord{}, ctx.Err()
		case <-tick.C:
		}
	}
}
func ReadPrivatePreviewService(root, name string) (PrivatePreviewRuntimeDescriptor, error) {
	d, err := readPreviewRuntimeDescriptor(previewDescriptorPath(root, name))
	if err != nil || d.Name != name || d.PrivateRemote == nil {
		return PrivatePreviewRuntimeDescriptor{}, errors.Join(ErrProductionInvalid, err)
	}
	return *d.PrivateRemote, nil
}
func BeginPrivatePreviewService(root, name string) error {
	return mutatePrivate(root, name, func(d *PreviewRuntimeDescriptor) error { d.Port = 0; d.Record = nil; d.Failure = nil; return nil })
}
func MarkPrivatePreviewServiceReady(root, name, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" {
		return ErrProductionInvalid
	}
	port, e := strconv.ParseUint(parsed.Port(), 10, 16)
	if e != nil || port == 0 {
		return ErrProductionInvalid
	}
	return mutatePrivate(root, name, func(d *PreviewRuntimeDescriptor) error {
		d.Port = uint16(port)
		d.Record = &preview.ControlRecord{LogicalName: name, URL: raw, TargetPort: int32(d.PrivateRemote.TargetPort), State: "ready", ExpiresAt: d.ExpiresAt}
		d.Failure = nil
		return nil
	})
}
func MarkPrivatePreviewServiceFailed(root, name string, cause error) error {
	if cause == nil {
		return ErrProductionInvalid
	}
	return mutatePrivate(root, name, func(d *PreviewRuntimeDescriptor) error {
		code := "preview_worker_start_failed"
		var n *net.OpError
		if errors.As(cause, &n) && n.Op == "listen" {
			code = "preview_listener_unavailable"
		}
		d.Port = 0
		d.Record = &preview.ControlRecord{LogicalName: name, TargetPort: int32(d.PrivateRemote.TargetPort), State: "failed", ExpiresAt: d.ExpiresAt}
		d.Failure = &PreviewRuntimeFailure{Code: code}
		return nil
	})
}
func CompletePrivatePreviewService(ctx context.Context, root, name string) error {
	if ctx == nil || !validWindowsPreviewStateRoot(root) || name == "" {
		return ErrProductionInvalid
	}
	defer lockWindowsPreviewStateRoot(root)()
	path := previewDescriptorPath(root, name)
	d, err := readPreviewRuntimeDescriptor(path)
	if err != nil || d.Name != name || d.PrivateRemote == nil {
		return errors.Join(ErrProductionInvalid, err)
	}
	return retireCompletedServeServiceWithRoot(ctx, root, name, path, d.ServiceDefinition, hostservice.ExecRunner{})
}

func validWindowsPreviewStateRoot(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.VolumeName(path) != ""
}

func windowsPreviewStateRootFromDescriptorPath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", ErrProductionInvalid
	}
	active := filepath.Dir(path)
	if filepath.Base(active) != "active" || filepath.Base(filepath.Dir(active)) != "previews" {
		return "", ErrProductionInvalid
	}
	root := filepath.Dir(filepath.Dir(active))
	if !validWindowsPreviewStateRoot(root) {
		return "", ErrProductionInvalid
	}
	return root, nil
}
func mutatePrivate(root, name string, mutate func(*PreviewRuntimeDescriptor) error) error {
	if !validWindowsPreviewStateRoot(root) || name == "" || mutate == nil {
		return ErrProductionInvalid
	}
	defer lockWindowsPreviewStateRoot(root)()
	path := previewDescriptorPath(root, name)
	d, err := readPreviewRuntimeDescriptor(path)
	if err != nil || d.Name != name || d.PrivateRemote == nil {
		return errors.Join(ErrProductionInvalid, err)
	}
	if err := mutate(&d); err != nil {
		return err
	}
	return writePreviewRuntimeDescriptor(path, d)
}
func writePreviewRuntimeDescriptor(path string, d PreviewRuntimeDescriptor) error {
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	sddl, err := previewDescriptorSDDL(path)
	if err != nil {
		return err
	}
	return atomicfile.Write(path, data, atomicfile.Options{Mode: 0600, OwnerUID: -1, OwnerGID: -1, SecurityDescriptor: sddl})
}
func readPreviewRuntimeDescriptor(path string) (PreviewRuntimeDescriptor, error) {
	if err := validatePreviewDescriptorSecurity(path); err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	var d PreviewRuntimeDescriptor
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var extra any
	if dec.Decode(&d) != nil || dec.Decode(&extra) != io.EOF || d.Schema != "paperboat.preview-runtime/v1" || d.Name == "" || d.Indefinite == (d.ExpiresAt != nil) || d.ServiceDefinition != "" && !filepath.IsAbs(d.ServiceDefinition) {
		return PreviewRuntimeDescriptor{}, ErrProductionInvalid
	}
	valid := d.Port != 0 && d.Serve == nil && d.PrivateRemote == nil || validServeRuntimeDescriptor(d.Serve) && d.BindAddress == "127.0.0.1" && d.ServiceGeneration > 0 || validPrivatePreviewRuntimeDescriptor(d.PrivateRemote) && d.Serve == nil && d.BindAddress == "127.0.0.1" && d.ServiceGeneration > 0
	if !valid {
		return PreviewRuntimeDescriptor{}, ErrProductionInvalid
	}
	return d, nil
}

func previewDescriptorSID(path string) (*windows.SID, error) {
	if install, err := hostinstall.LoadWindowsRuntimeConfig(); err == nil {
		relative, relErr := filepath.Rel(install.StateRoot, path)
		if relErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return windows.StringToSid(install.OwnerSID)
		}
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, ErrProductionInvalid
	}
	return user.User.Sid, nil
}

func previewDescriptorSDDL(path string) (string, error) {
	sid, err := previewDescriptorSID(path)
	if err != nil {
		return "", err
	}
	return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + sid.String() + ")", nil
}

func validatePreviewDescriptorSecurity(path string) error {
	if err := validateWindowsPreviewDescriptorAncestors(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrProductionInvalid, err)
	}
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(ErrProductionInvalid, err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return errors.Join(ErrProductionInvalid, err)
	}
	control, _, err := descriptor.Control()
	wantSDDL, wantErr := previewDescriptorSDDL(path)
	want, parseErr := windows.SecurityDescriptorFromString(wantSDDL)
	if err != nil || wantErr != nil || parseErr != nil || control&windows.SE_DACL_PROTECTED == 0 || previewDescriptorDACL(descriptor.String()) != previewDescriptorDACL(want.String()) {
		return ErrProductionInvalid
	}
	return nil
}

func previewDescriptorDACL(value string) string {
	index := strings.Index(value, "D:")
	if index < 0 {
		return ""
	}
	open := strings.IndexByte(value[index:], '(')
	if open < 0 {
		return ""
	}
	return "D:" + value[index+open:]
}
func validPrivatePreviewRuntimeDescriptor(d *PrivatePreviewRuntimeDescriptor) bool {
	return d != nil && d.MachineID != "" && d.MachineName != "" && d.EnvironmentID != "" && d.MachineGeneration > 0 && d.TargetPort > 0
}
func validServeRuntimeDescriptor(d *ServeRuntimeDescriptor) bool {
	return d != nil && filepath.IsAbs(d.SourcePath) && d.SourceIdentity != "" && (d.SourceKind == servepkg.SourceFile || d.SourceKind == servepkg.SourceDirectory) && d.OwnerMode == "detached" && (d.Visibility == "private" || d.Visibility == "public") && (d.Visibility == "private" || d.ListenPort == 0) && (!d.SPA || d.SourceKind == servepkg.SourceDirectory)
}
