//go:build windows

package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	lockAny, _ := windowsPreviewLocks.LoadOrStore(root, &sync.Mutex{})
	lock := lockAny.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	if maximum > 0 {
		active, err := activePrivatePreviewServices(root, time.Now().UTC())
		if err != nil {
			return PreviewRuntimeDescriptor{}, err
		}
		if active >= maximum {
			return PreviewRuntimeDescriptor{}, ErrPreviewAlreadyActive
		}
	}
	path := previewDescriptorPath(root, name)
	if current, err := readPreviewRuntimeDescriptor(path); err == nil && (current.Indefinite || current.ExpiresAt != nil && current.ExpiresAt.After(time.Now().UTC())) {
		return PreviewRuntimeDescriptor{}, ErrPreviewAlreadyActive
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return PreviewRuntimeDescriptor{}, err
	}
	definition, _, err := previewServiceDefinition(root, name, runtime.GOOS)
	if err != nil {
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
		_ = os.Remove(path)
		return PreviewRuntimeDescriptor{}, err
	}
	if installer.DefinitionPath() != definition {
		_ = os.Remove(path)
		return PreviewRuntimeDescriptor{}, ErrProductionInvalid
	}
	if err := installer.Install(ctx); err != nil {
		_ = os.Remove(path)
		return PreviewRuntimeDescriptor{}, err
	}
	return descriptor, nil
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
func retirePreviewService(ctx context.Context, name, definition string, _ hostservice.Runner) error {
	expected, _, err := previewServiceDefinition("", name, "windows")
	if err != nil || expected != definition {
		return ErrProductionInvalid
	}
	if os.Getenv("PAPERBOAT_WINDOWS_PREVIEW_OWNER_WORKLOAD") == "1" && os.Getenv("PAPERBOAT_RUNTIME_SERVICE_SCOPE") == "user" {
		// The LocalSystem service parent owns SCM deletion after this enrolled
		// owner child exits. The child may remove only its user-state descriptor.
		return nil
	}
	installer, err := hostservice.New(hostservice.Config{Platform: "windows", Kind: hostservice.PreviewKind, Instance: previewServiceInstance(name), ConfigRoot: `C:\ProgramData\Paperboat`, Executable: os.Args[0], User: "SYSTEM", Group: "Administrators", Arguments: []string{"__runtime-preview"}, Controller: hostservice.WindowsController{}})
	if err != nil {
		return err
	}
	return installer.Uninstall(ctx)
}
func retireCompletedServeService(ctx context.Context, name, path, definition string, runner hostservice.Runner) error {
	if definition != "" {
		if err := retirePreviewService(ctx, name, definition, runner); err != nil {
			return err
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
func RemovePreviewService(ctx context.Context, root, name string) error {
	d, err := readPreviewRuntimeDescriptor(previewDescriptorPath(root, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || d.Name != name {
		return errors.Join(ErrProductionInvalid, err)
	}
	return retireCompletedServeService(ctx, name, previewDescriptorPath(root, name), d.ServiceDefinition, hostservice.ExecRunner{})
}
func RemoveAllPreviewServices(ctx context.Context, root string) error {
	entries, err := os.ReadDir(filepath.Join(root, "previews", "active"))
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
		d, e := readPreviewRuntimeDescriptor(filepath.Join(root, "previews", "active", entry.Name()))
		if e == nil && d.ServiceDefinition != "" {
			result = errors.Join(result, retireCompletedServeService(ctx, d.Name, filepath.Join(root, "previews", "active", entry.Name()), d.ServiceDefinition, hostservice.ExecRunner{}))
		}
	}
	return result
}
func ReconcileExpiredPreviewServices(ctx context.Context, root string, now time.Time) error {
	entries, err := os.ReadDir(filepath.Join(root, "previews", "active"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var result error
	for _, entry := range entries {
		path := filepath.Join(root, "previews", "active", entry.Name())
		d, e := readPreviewRuntimeDescriptor(path)
		if e == nil && !d.Indefinite && d.ExpiresAt != nil && !d.ExpiresAt.After(now) {
			result = errors.Join(result, retireCompletedServeService(ctx, d.Name, path, d.ServiceDefinition, hostservice.ExecRunner{}))
		}
	}
	return result
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
	d, err := readPreviewRuntimeDescriptor(previewDescriptorPath(root, name))
	if err != nil || d.PrivateRemote == nil {
		return errors.Join(ErrProductionInvalid, err)
	}
	return retireCompletedServeService(ctx, name, previewDescriptorPath(root, name), d.ServiceDefinition, hostservice.ExecRunner{})
}
func mutatePrivate(root, name string, mutate func(*PreviewRuntimeDescriptor) error) error {
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
