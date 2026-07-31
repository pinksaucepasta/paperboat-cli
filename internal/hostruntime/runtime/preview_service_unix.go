//go:build darwin || linux

package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/preview"
	hostservice "github.com/pinksaucepasta/paperboat/internal/hostruntime/service"
)

type PreviewRuntimeDescriptor struct {
	Schema            string                 `json:"schema"`
	Name              string                 `json:"name"`
	Port              uint16                 `json:"port"`
	Indefinite        bool                   `json:"indefinite"`
	ExpiresAt         *time.Time             `json:"expires_at,omitempty"`
	ServiceDefinition string                 `json:"service_definition"`
	Record            *preview.ControlRecord `json:"record,omitempty"`
}

var ErrPreviewAlreadyActive = errors.New("preview name is already active")

func InstallPreviewService(ctx context.Context, executable, stateRoot, name string, port uint16, expiresAt *time.Time, indefinite bool) (PreviewRuntimeDescriptor, error) {
	if !filepath.IsAbs(executable) || !filepath.IsAbs(stateRoot) || name == "" || port == 0 || indefinite == (expiresAt != nil) {
		return PreviewRuntimeDescriptor{}, ErrProductionInvalid
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
	descriptor := PreviewRuntimeDescriptor{Schema: "paperboat.preview-runtime/v1", Name: name, Port: port, Indefinite: indefinite, ExpiresAt: expiresAt, ServiceDefinition: definitionPath}
	if err := writePreviewRuntimeDescriptor(descriptorPath, descriptor); err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	args := []string{"__runtime-preview", "--state-root", stateRoot, "--name", name, "--port", strconv.Itoa(int(port)), "--descriptor", descriptorPath, "--service-definition", definitionPath}
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

func previewServiceInstance(name string) string {
	digest := sha256.Sum256([]byte(name))
	return hex.EncodeToString(digest[:8])
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
	removeDefinition := func() error {
		removeErr := os.Remove(definition)
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		return removeErr
	}
	if runtime.GOOS == "linux" {
		unit := "paperboat-preview-" + previewServiceInstance(name) + ".service"
		return errors.Join(
			runner.Run(ctx, "systemctl", "--user", "disable", unit),
			removeDefinition(),
			runner.Run(ctx, "systemctl", "--user", "daemon-reload"),
		)
	}
	account, err := user.Current()
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	return errors.Join(removeDefinition(), runner.Run(ctx, "launchctl", "bootout", "gui/"+strconv.Itoa(uid)+"/"+label))
}

func WaitPreviewServiceReady(ctx context.Context, stateRoot, name string) (preview.ControlRecord, error) {
	digest := sha256.Sum256([]byte(name))
	path := filepath.Join(stateRoot, "previews", "active", hex.EncodeToString(digest[:8])+".json")
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		descriptor, err := readPreviewRuntimeDescriptor(path)
		if err == nil && descriptor.Record != nil && descriptor.Record.URL != "" {
			return *descriptor.Record, nil
		}
		select {
		case <-ctx.Done():
			return preview.ControlRecord{}, ctx.Err()
		case <-ticker.C:
		}
	}
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
	temporary, err := os.CreateTemp(directory, ".preview-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func readPreviewRuntimeDescriptor(path string) (PreviewRuntimeDescriptor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PreviewRuntimeDescriptor{}, err
	}
	var descriptor PreviewRuntimeDescriptor
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&descriptor) != nil || decoder.Decode(&struct{}{}) != io.EOF || descriptor.Schema != "paperboat.preview-runtime/v1" || descriptor.Name == "" || descriptor.Port == 0 || descriptor.ServiceDefinition != "" && !filepath.IsAbs(descriptor.ServiceDefinition) || descriptor.Indefinite == (descriptor.ExpiresAt != nil) {
		return PreviewRuntimeDescriptor{}, ErrProductionInvalid
	}
	return descriptor, nil
}
