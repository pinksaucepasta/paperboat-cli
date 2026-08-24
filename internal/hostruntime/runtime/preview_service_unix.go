//go:build darwin || linux

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	hostservice "github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
	servepkg "github.com/pinksaucepasta/paperboat/internal/serve"
)

var ErrPreviewAlreadyActive = errors.New("preview name is already active")
var ErrPreviewServiceMissing = errors.New("preview service is missing")
var ErrPreviewServiceFailed = errors.New("preview service failed")

type PreviewServiceFailureError struct {
	Code string
}

func (e *PreviewServiceFailureError) Error() string {
	if e == nil || e.Code == "" {
		return ErrPreviewServiceFailed.Error()
	}
	return ErrPreviewServiceFailed.Error() + ": " + e.Code
}

func (e *PreviewServiceFailureError) Unwrap() error { return ErrPreviewServiceFailed }

func InstallPreviewService(ctx context.Context, executable, stateRoot, name string, port uint16, expiresAt *time.Time, indefinite bool) (PreviewRuntimeDescriptor, error) {
	return installPreviewService(ctx, executable, stateRoot, name, port, expiresAt, indefinite, nil, nil, 0)
}

func InstallPrivatePreviewService(ctx context.Context, executable, stateRoot, name string, remote PrivatePreviewRuntimeDescriptor, expiresAt *time.Time, indefinite bool, maximumPrivate int) (PreviewRuntimeDescriptor, error) {
	if remote.MachineID == "" || remote.MachineName == "" || remote.EnvironmentID == "" || remote.MachineGeneration == 0 || remote.TargetPort == 0 || maximumPrivate < 1 || maximumPrivate > 20 {
		return PreviewRuntimeDescriptor{}, ErrProductionInvalid
	}
	return installPreviewService(ctx, executable, stateRoot, name, 0, expiresAt, indefinite, nil, &remote, maximumPrivate)
}

func activePrivatePreviewServices(stateRoot string, now time.Time) (int, error) {
	entries, err := os.ReadDir(filepath.Join(stateRoot, "previews", "active"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		descriptor, readErr := readPreviewRuntimeDescriptor(filepath.Join(stateRoot, "previews", "active", entry.Name()))
		if readErr != nil || !descriptor.Indefinite && (descriptor.ExpiresAt == nil || !descriptor.ExpiresAt.After(now)) {
			continue
		}
		if descriptor.PrivateRemote != nil || descriptor.Serve != nil && descriptor.Serve.Visibility == "private" {
			count++
		}
	}
	return count, nil
}

func InstallServeService(ctx context.Context, executable, stateRoot, name string, source servepkg.Source, spa bool, expiresAt *time.Time, indefinite bool, public bool, listenPort uint16) (PreviewRuntimeDescriptor, error) {
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
	}
	descriptor := &ServeRuntimeDescriptor{SourcePath: source.Path, SourceKind: source.Kind, SourceIdentity: identity, SPA: spa, OwnerMode: "detached", Visibility: visibility, ListenPort: listenPort}
	return installPreviewService(ctx, executable, stateRoot, name, 0, expiresAt, indefinite, descriptor, nil, 0)
}

func installPreviewService(ctx context.Context, executable, stateRoot, name string, port uint16, expiresAt *time.Time, indefinite bool, served *ServeRuntimeDescriptor, privateRemote *PrivatePreviewRuntimeDescriptor, maximumPrivate int) (PreviewRuntimeDescriptor, error) {
	kinds := 0
	if port != 0 {
		kinds++
	}
	if served != nil {
		kinds++
	}
	if privateRemote != nil {
		kinds++
	}
	if !filepath.IsAbs(executable) || !filepath.IsAbs(stateRoot) || name == "" || kinds != 1 || indefinite == (expiresAt != nil) {
		return PreviewRuntimeDescriptor{}, ErrProductionInvalid
	}
	release, err := acquirePreviewInstallLock(ctx, stateRoot)
	if err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	defer release()
	if maximumPrivate > 0 {
		active, countErr := activePrivatePreviewServices(stateRoot, time.Now().UTC())
		if countErr != nil {
			return PreviewRuntimeDescriptor{}, countErr
		}
		if active >= maximumPrivate {
			return PreviewRuntimeDescriptor{}, fmt.Errorf("%w: %d private previews are already active; stop one with `pb preview revoke <name> --yes`", ErrPreviewAlreadyActive, active)
		}
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return PreviewRuntimeDescriptor{}, errors.Join(ErrProductionInvalid, err)
	}
	account, err := user.Current()
	if err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	group, err := user.LookupGroupId(account.Gid)
	if err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	instance := previewServiceInstance(name)
	descriptorPath := filepath.Join(stateRoot, "previews", "active", instance+".json")
	definitionPath, label, err := previewServiceDefinition(home, name, runtime.GOOS)
	if err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	if existing, readErr := readPreviewRuntimeDescriptor(descriptorPath); readErr == nil && (existing.Indefinite || existing.ExpiresAt != nil && existing.ExpiresAt.After(time.Now().UTC())) {
		return PreviewRuntimeDescriptor{}, ErrPreviewAlreadyActive
	} else if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return PreviewRuntimeDescriptor{}, readErr
	}
	runner := hostservice.ExecRunner{}
	var controller hostservice.Controller
	switch runtime.GOOS {
	case "darwin":
		uid, parseErr := strconv.Atoi(account.Uid)
		if parseErr != nil {
			return PreviewRuntimeDescriptor{}, parseErr
		}
		controller = hostservice.LaunchdController{Runner: runner, UID: uid, Label: label, UserDomain: true}
	case "linux":
		controller = hostservice.SystemdController{Runner: runner, Unit: "paperboat-preview-" + instance + ".service", User: true}
	default:
		return PreviewRuntimeDescriptor{}, hostservice.ErrUnsupportedPlatform
	}
	descriptor := PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: name, BindAddress: "127.0.0.1", Port: port, ServiceGeneration: uint64(time.Now().UTC().UnixNano()), Indefinite: indefinite, ExpiresAt: expiresAt, ServiceDefinition: definitionPath, Serve: served, PrivateRemote: privateRemote}
	if err := writePreviewRuntimeDescriptor(descriptorPath, descriptor); err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	entrypoint := "__runtime-preview"
	args := []string{entrypoint, "--state-root", stateRoot, "--name", name, "--descriptor", descriptorPath, "--service-definition", definitionPath}
	if served == nil {
		if privateRemote == nil {
			args = append(args, "--port", strconv.Itoa(int(port)))
		} else {
			args[0] = "__runtime-private-preview"
		}
	} else {
		args[0] = "__runtime-serve"
	}
	if indefinite {
		args = append(args, "--indefinite")
	} else {
		args = append(args, "--expires-at", expiresAt.UTC().Format(time.RFC3339Nano))
	}
	installer, err := hostservice.New(hostservice.Config{Platform: runtime.GOOS, Kind: hostservice.PreviewKind, Instance: instance, ConfigRoot: home, Executable: executable, User: account.Username, Group: group.Name, Arguments: args, Environment: map[string]string{"HOME": home}, Controller: controller})
	if err != nil {
		_ = os.Remove(descriptorPath)
		return PreviewRuntimeDescriptor{}, err
	}
	if installer.DefinitionPath() != definitionPath {
		_ = os.Remove(descriptorPath)
		return PreviewRuntimeDescriptor{}, ErrProductionInvalid
	}
	if err := installer.Install(ctx); err != nil {
		_ = os.Remove(descriptorPath)
		return PreviewRuntimeDescriptor{}, err
	}
	return descriptor, nil
}

func acquirePreviewInstallLock(ctx context.Context, stateRoot string) (func(), error) {
	if ctx == nil || !filepath.IsAbs(stateRoot) {
		return nil, ErrProductionInvalid
	}
	directory := filepath.Join(stateRoot, "previews")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(directory, "install.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, err
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = file.Close()
			return nil, ctx.Err()
		}
	}
}

func previewServiceInstance(name string) string {
	digest := sha256.Sum256([]byte(name))
	return hex.EncodeToString(digest[:8])
}

func safePreviewInstance(value string) bool {
	if len(value) != 16 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func previewServiceDefinition(home, name, goos string) (path, label string, err error) {
	if !filepath.IsAbs(home) || name == "" {
		return "", "", ErrProductionInvalid
	}
	instance := previewServiceInstance(name)
	label = "com.pinksaucepasta.paperboat.runtime-preview." + instance
	switch goos {
	case "darwin":
		return filepath.Join(home, "Library", "LaunchAgents", label+".plist"), label, nil
	case "linux":
		return filepath.Join(home, ".config", "systemd", "user", "paperboat-preview-"+instance+".service"), label, nil
	default:
		return "", "", hostservice.ErrUnsupportedPlatform
	}
}

func retirePreviewService(ctx context.Context, name, definition string, runner hostservice.Runner) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	expected, label, err := previewServiceDefinition(home, name, runtime.GOOS)
	if err != nil || definition != expected || runner == nil {
		return errors.Join(ErrProductionInvalid, err)
	}
	if runtime.GOOS == "linux" {
		unit := "paperboat-preview-" + previewServiceInstance(name) + ".service"
		return (hostservice.SystemdController{Runner: runner, Unit: unit, User: true}).Remove(ctx, definition)
	}
	account, err := user.Current()
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	removeErr := os.Remove(definition)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	return errors.Join(removeErr, (hostservice.LaunchdController{Runner: runner, UID: uid, Label: label, UserDomain: true}).Remove(ctx, definition))
}

func retirePreviewServiceWithRoot(ctx context.Context, _ string, name, definition string, runner hostservice.Runner) error {
	return retirePreviewService(ctx, name, definition, runner)
}

func retireCompletedServeService(ctx context.Context, name, descriptorPath, definition string, runner hostservice.Runner) error {
	if ctx == nil || name == "" || !filepath.IsAbs(descriptorPath) || definition != "" && !filepath.IsAbs(definition) {
		return ErrProductionInvalid
	}
	if definition == "" {
		err := os.Remove(descriptorPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if runner == nil {
		runner = hostservice.ExecRunner{}
	}
	home, homeErr := os.UserHomeDir()
	expected, _, err := previewServiceDefinition(home, name, runtime.GOOS)
	err = errors.Join(err, homeErr)
	if err != nil || definition != expected {
		return errors.Join(ErrProductionInvalid, err)
	}
	if runtime.GOOS == "linux" {
		unit := "paperboat-preview-" + previewServiceInstance(name) + ".service"
		disableErr := runner.Run(ctx, "systemctl", "--user", "disable", unit)
		if disableErr != nil && !previewSystemdUnitAbsent(disableErr) {
			return disableErr
		}
	}
	removeDescriptorErr := os.Remove(descriptorPath)
	if errors.Is(removeDescriptorErr, os.ErrNotExist) {
		removeDescriptorErr = nil
	}
	removeDefinitionErr := os.Remove(definition)
	if errors.Is(removeDefinitionErr, os.ErrNotExist) {
		removeDefinitionErr = nil
	}
	if runtime.GOOS == "linux" {
		unit := "paperboat-preview-" + previewServiceInstance(name) + ".service"
		return errors.Join(removeDescriptorErr, removeDefinitionErr, runner.Run(ctx, "systemctl", "--user", "daemon-reload"), runner.Run(ctx, "systemctl", "--user", "reset-failed", unit))
	}
	return errors.Join(removeDescriptorErr, removeDefinitionErr)
}

func RemovePreviewService(ctx context.Context, stateRoot, name string) error {
	return removePreviewService(ctx, stateRoot, name, hostservice.ExecRunner{})
}

func removePreviewService(ctx context.Context, stateRoot, name string, runner hostservice.Runner) error {
	if ctx == nil || !filepath.IsAbs(stateRoot) || name == "" {
		return ErrProductionInvalid
	}
	digest := sha256.Sum256([]byte(name))
	path := filepath.Join(stateRoot, "previews", "active", hex.EncodeToString(digest[:8])+".json")
	descriptor, err := readPreviewRuntimeDescriptor(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if descriptor.Name != name || descriptor.ServiceDefinition == "" {
		return ErrProductionInvalid
	}
	if err := retirePreviewService(ctx, name, descriptor.ServiceDefinition, runner); err != nil {
		return err
	}
	removeErr := os.Remove(path)
	if errors.Is(removeErr, os.ErrNotExist) {
		return nil
	}
	return removeErr
}

func RemoveAllPreviewServices(ctx context.Context, stateRoot string) error {
	return removeAllPreviewServices(ctx, stateRoot, hostservice.ExecRunner{})
}

func ReconcileExpiredPreviewServices(ctx context.Context, stateRoot string, now time.Time) error {
	return reconcileExpiredPreviewServices(ctx, stateRoot, now, hostservice.ExecRunner{})
}

func reconcileExpiredPreviewServices(ctx context.Context, stateRoot string, now time.Time, runner hostservice.Runner) error {
	if ctx == nil || !filepath.IsAbs(stateRoot) || now.IsZero() || runner == nil {
		return ErrProductionInvalid
	}
	directory := filepath.Join(stateRoot, "previews", "active")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var result error
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		descriptor, readErr := readPreviewRuntimeDescriptor(path)
		if readErr != nil {
			result = errors.Join(result, fmt.Errorf("read preview service %s: %w", entry.Name(), readErr))
			continue
		}
		if descriptor.ServiceDefinition == "" || descriptor.Indefinite || descriptor.ExpiresAt == nil || descriptor.ExpiresAt.After(now) {
			continue
		}
		if retireErr := retirePreviewService(ctx, descriptor.Name, descriptor.ServiceDefinition, runner); retireErr != nil {
			result = errors.Join(result, fmt.Errorf("retire expired preview service %s: %w", entry.Name(), retireErr))
			continue
		}
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("remove expired preview service %s: %w", entry.Name(), removeErr))
		}
	}
	if runtime.GOOS == "linux" {
		result = errors.Join(result, resetFailedPreviewServices(ctx, runner))
	}
	return result
}

func resetFailedPreviewServices(ctx context.Context, runner hostservice.Runner) error {
	outputRunner, ok := runner.(hostservice.OutputRunner)
	if !ok {
		return nil
	}
	output, err := outputRunner.Output(ctx, "systemctl", "--user", "list-units", "--state=failed", "--plain", "--no-legend", "paperboat-preview-*.service")
	if err != nil {
		return fmt.Errorf("list failed preview service state: %w", err)
	}
	var result error
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		unit := fields[0]
		if unit == "●" && len(fields) > 1 {
			unit = fields[1]
		}
		instance := strings.TrimSuffix(strings.TrimPrefix(unit, "paperboat-preview-"), ".service")
		if unit != "paperboat-preview-"+instance+".service" || !safePreviewInstance(instance) {
			continue
		}
		if resetErr := runner.Run(ctx, "systemctl", "--user", "reset-failed", unit); resetErr != nil && !previewSystemdUnitAbsent(resetErr) {
			result = errors.Join(result, fmt.Errorf("reset stale preview service %s: %w", unit, resetErr))
		}
	}
	return result
}

func removeAllPreviewServices(ctx context.Context, stateRoot string, runner hostservice.Runner) error {
	if ctx == nil || !filepath.IsAbs(stateRoot) || runner == nil {
		return ErrProductionInvalid
	}
	directory := filepath.Join(stateRoot, "previews", "active")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var result error
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		descriptor, readErr := readPreviewRuntimeDescriptor(path)
		if readErr != nil {
			result = errors.Join(result, fmt.Errorf("read preview service %s: %w", entry.Name(), readErr))
			continue
		}
		if descriptor.ServiceDefinition == "" {
			continue
		}
		if retireErr := retirePreviewService(ctx, descriptor.Name, descriptor.ServiceDefinition, runner); retireErr != nil {
			result = errors.Join(result, fmt.Errorf("retire preview service %s: %w", entry.Name(), retireErr))
			continue
		}
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("remove preview service %s: %w", entry.Name(), removeErr))
		}
	}
	return result
}

func WaitPreviewServiceReady(ctx context.Context, stateRoot, name string) (preview.ControlRecord, error) {
	return waitPreviewServiceReady(ctx, stateRoot, name, hostservice.ExecRunner{})
}

func waitPreviewServiceReady(ctx context.Context, stateRoot, name string, runner hostservice.Runner) (preview.ControlRecord, error) {
	if ctx == nil || !filepath.IsAbs(stateRoot) || name == "" {
		return preview.ControlRecord{}, ErrProductionInvalid
	}
	digest := sha256.Sum256([]byte(name))
	path := filepath.Join(stateRoot, "previews", "active", hex.EncodeToString(digest[:8])+".json")
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		descriptor, err := readPreviewRuntimeDescriptor(path)
		if err == nil && descriptor.Record != nil && descriptor.Record.URL != "" {
			return *descriptor.Record, nil
		}
		if errors.Is(err, os.ErrNotExist) {
			return preview.ControlRecord{}, errors.Join(ErrPreviewServiceMissing, err)
		}
		if err == nil && descriptor.Record != nil && descriptor.Record.State == "failed" {
			failure := &PreviewServiceFailureError{}
			if descriptor.Failure != nil {
				failure.Code = descriptor.Failure.Code
			}
			return preview.ControlRecord{}, failure
		}
		if err == nil && descriptor.ServiceDefinition != "" {
			if _, statErr := os.Stat(descriptor.ServiceDefinition); errors.Is(statErr, os.ErrNotExist) {
				return preview.ControlRecord{}, errors.Join(ErrPreviewServiceMissing, statErr)
			} else if statErr != nil {
				return preview.ControlRecord{}, statErr
			}
			if failed, stateErr := previewServiceFailed(ctx, descriptor.Name, runner); stateErr != nil {
				return preview.ControlRecord{}, stateErr
			} else if failed {
				return preview.ControlRecord{}, ErrPreviewServiceFailed
			}
		}
		select {
		case <-ctx.Done():
			return preview.ControlRecord{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func previewServiceFailed(ctx context.Context, name string, runner hostservice.Runner) (bool, error) {
	if runner == nil {
		return false, ErrProductionInvalid
	}
	if runtime.GOOS == "linux" {
		unit := "paperboat-preview-" + previewServiceInstance(name) + ".service"
		if err := runner.Run(ctx, "systemctl", "--user", "is-active", "--quiet", unit); err == nil {
			return false, nil
		} else if previewSystemdUnitAbsent(err) {
			return false, errors.Join(ErrPreviewServiceMissing, err)
		}
		if err := runner.Run(ctx, "systemctl", "--user", "is-failed", "--quiet", unit); err == nil {
			return true, nil
		} else if previewSystemdUnitAbsent(err) {
			return false, errors.Join(ErrPreviewServiceMissing, err)
		}
		return false, nil
	}
	account, err := user.Current()
	if err != nil {
		return false, err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return false, err
	}
	label := "com.pinksaucepasta.paperboat.runtime-preview." + previewServiceInstance(name)
	if err := runner.Run(ctx, "launchctl", "print", "gui/"+strconv.Itoa(uid)+"/"+label); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "could not find service") || strings.Contains(strings.ToLower(err.Error()), "no such process") {
			return false, errors.Join(ErrPreviewServiceMissing, err)
		}
		return true, nil
	}
	return false, nil
}

func ReadPrivatePreviewService(stateRoot, name string) (PrivatePreviewRuntimeDescriptor, error) {
	if !filepath.IsAbs(stateRoot) || name == "" {
		return PrivatePreviewRuntimeDescriptor{}, ErrProductionInvalid
	}
	digest := sha256.Sum256([]byte(name))
	descriptor, err := readPreviewRuntimeDescriptor(filepath.Join(stateRoot, "previews", "active", hex.EncodeToString(digest[:8])+".json"))
	if err != nil || descriptor.Schema != "paperboat.preview-runtime/v1" || descriptor.Name != name || descriptor.BindAddress != "127.0.0.1" || descriptor.PrivateRemote == nil || descriptor.Serve != nil || descriptor.Record != nil && descriptor.Record.State != "ready" && descriptor.Record.State != "failed" {
		return PrivatePreviewRuntimeDescriptor{}, errors.Join(ErrProductionInvalid, err)
	}
	return *descriptor.PrivateRemote, nil
}

func MarkPrivatePreviewServiceReady(stateRoot, name, rawURL string) error {
	if !filepath.IsAbs(stateRoot) || name == "" {
		return ErrProductionInvalid
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.Join(ErrProductionInvalid, err)
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || port == 0 {
		return errors.Join(ErrProductionInvalid, err)
	}
	digest := sha256.Sum256([]byte(name))
	path := filepath.Join(stateRoot, "previews", "active", hex.EncodeToString(digest[:8])+".json")
	descriptor, err := readPreviewRuntimeDescriptor(path)
	if err != nil || descriptor.PrivateRemote == nil || descriptor.Name != name || descriptor.BindAddress != "127.0.0.1" {
		return errors.Join(ErrProductionInvalid, err)
	}
	descriptor.Port = uint16(port)
	descriptor.Record = &preview.ControlRecord{LogicalName: name, URL: rawURL, TargetPort: int32(descriptor.PrivateRemote.TargetPort), State: "ready", ExpiresAt: descriptor.ExpiresAt}
	descriptor.Failure = nil
	return writePreviewRuntimeDescriptor(path, descriptor)
}

func BeginPrivatePreviewService(stateRoot, name string) error {
	if !filepath.IsAbs(stateRoot) || name == "" {
		return ErrProductionInvalid
	}
	digest := sha256.Sum256([]byte(name))
	path := filepath.Join(stateRoot, "previews", "active", hex.EncodeToString(digest[:8])+".json")
	descriptor, err := readPreviewRuntimeDescriptor(path)
	if err != nil || descriptor.PrivateRemote == nil || descriptor.Name != name {
		return errors.Join(ErrProductionInvalid, err)
	}
	descriptor.Port = 0
	descriptor.Record = nil
	descriptor.Failure = nil
	return writePreviewRuntimeDescriptor(path, descriptor)
}

func MarkPrivatePreviewServiceFailed(stateRoot, name string, cause error) error {
	if !filepath.IsAbs(stateRoot) || name == "" || cause == nil {
		return ErrProductionInvalid
	}
	digest := sha256.Sum256([]byte(name))
	path := filepath.Join(stateRoot, "previews", "active", hex.EncodeToString(digest[:8])+".json")
	descriptor, err := readPreviewRuntimeDescriptor(path)
	if err != nil || descriptor.PrivateRemote == nil || descriptor.Name != name {
		return errors.Join(ErrProductionInvalid, err)
	}
	code := "preview_worker_start_failed"
	var networkErr *net.OpError
	if errors.As(cause, &networkErr) && networkErr.Op == "listen" {
		code = "preview_listener_unavailable"
	}
	descriptor.Port = 0
	descriptor.Record = &preview.ControlRecord{LogicalName: name, TargetPort: int32(descriptor.PrivateRemote.TargetPort), State: "failed", ExpiresAt: descriptor.ExpiresAt}
	descriptor.Failure = &PreviewRuntimeFailure{Code: code}
	return writePreviewRuntimeDescriptor(path, descriptor)
}

func CompletePrivatePreviewService(ctx context.Context, stateRoot, name string) error {
	if ctx == nil || !filepath.IsAbs(stateRoot) || name == "" {
		return ErrProductionInvalid
	}
	digest := sha256.Sum256([]byte(name))
	path := filepath.Join(stateRoot, "previews", "active", hex.EncodeToString(digest[:8])+".json")
	descriptor, err := readPreviewRuntimeDescriptor(path)
	if err != nil || descriptor.PrivateRemote == nil || descriptor.Name != name {
		return errors.Join(ErrProductionInvalid, err)
	}
	return retireCompletedServeService(ctx, name, path, descriptor.ServiceDefinition, hostservice.ExecRunner{})
}

func previewSystemdUnitAbsent(err error) bool {
	if err == nil {
		return false
	}
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "unit") && (strings.Contains(value, "not found") || strings.Contains(value, "not loaded") || strings.Contains(value, "does not exist"))
}

func writePreviewRuntimeDescriptor(path string, descriptor PreviewRuntimeDescriptor) error {
	data, err := json.Marshal(descriptor)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, data, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1})
}

func readPreviewRuntimeDescriptor(path string) (PreviewRuntimeDescriptor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	return DecodePreviewRuntimeDescriptor(data)
}
