package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type fakeNativeController struct {
	mu     sync.Mutex
	status NativeControllerStatus
	apply  int
	start  int
	stop   int
}

func (c *fakeNativeController) Apply(context.Context, string, bool) error { return nil }
func (c *fakeNativeController) Remove(context.Context, string) error      { return nil }

func (c *fakeNativeController) Inspect(context.Context, string) (NativeControllerStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status, nil
}

func (c *fakeNativeController) Enable(context.Context, string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.apply++
	c.status.Registered, c.status.Enabled = true, true
	return nil
}

func (c *fakeNativeController) Disable(context.Context, string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status.Enabled = false
	return nil
}

func (c *fakeNativeController) Start(context.Context, string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.start++
	c.status.Running, c.status.Ready = true, true
	return nil
}

func (c *fakeNativeController) Stop(context.Context, string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stop++
	c.status.Running, c.status.Ready = false, false
	return nil
}

func (c *fakeNativeController) snapshot() NativeControllerStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

func TestHTTPReadinessProbeRequiresLiveBoundedResponse(t *testing.T) {
	tests := []struct {
		name string
		body string
		code int
		want bool
	}{
		{name: "live", body: `{"live":true}`, code: http.StatusOK, want: true},
		{name: "not live", body: `{"live":false}`, code: http.StatusOK},
		{name: "wrong status", body: `{"live":true}`, code: http.StatusAccepted},
		{name: "trailing", body: `{"live":true}{}`, code: http.StatusOK},
		{name: "duplicate", body: `{"live":false,"live":true}`, code: http.StatusOK},
		{name: "oversized", body: `{"live":true,"padding":"` + string(make([]byte, readinessProbeBodyMax)) + `"}`, code: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.code)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			probe, err := NewHTTPReadinessProbe(server.URL + "/healthz")
			if err != nil {
				t.Fatal(err)
			}
			err = probe(context.Background())
			if (err == nil) != test.want || err != nil && !errors.Is(err, ErrLifecycleNotReady) {
				t.Fatalf("probe err=%v want=%v", err, test.want)
			}
		})
	}
	for _, endpoint := range []string{
		"https://127.0.0.1:8080/healthz", "http://localhost:8080/healthz",
		"http://127.0.0.1/healthz", "http://10.0.0.1:8080/healthz",
		"http://127.0.0.1:8080/healthz?x=1", "http://127.0.0.1:8080/other",
	} {
		if _, err := NewHTTPReadinessProbe(endpoint); !errors.Is(err, ErrLifecycleInvalid) {
			t.Fatalf("endpoint %q err=%v", endpoint, err)
		}
	}
}

func TestHTTPReadinessProbeRequiresSingleJSONContentTypeAndPreservesDefaultClient(t *testing.T) {
	originalRedirectSet := http.DefaultClient.CheckRedirect != nil
	originalTimeout := http.DefaultClient.Timeout
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		w.Header().Add("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"live":true}`))
	}))
	defer server.Close()
	probe, err := NewHTTPReadinessProbe(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if err := probe(context.Background()); !errors.Is(err, ErrLifecycleNotReady) {
		t.Fatalf("multiple content types err=%v", err)
	}
	if (http.DefaultClient.CheckRedirect != nil) != originalRedirectSet || http.DefaultClient.Timeout != originalTimeout {
		t.Fatal("readiness probe mutated the process-wide default HTTP client")
	}
}

func TestHTTPReadinessProbeDisablesRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			http.Redirect(w, r, "/secret", http.StatusFound)
			return
		}
		t.Fatal("redirect target must not be requested")
	}))
	defer server.Close()
	probe, err := NewHTTPReadinessProbe(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if err := probe(context.Background()); !errors.Is(err, ErrLifecycleNotReady) {
		t.Fatalf("redirect err=%v", err)
	}
}

func TestHostLifecycleManagerRollsBackExactBothComponentStateAfterProbeFailure(t *testing.T) {
	root := t.TempDir()
	layout := Layout{
		Platform:        "linux",
		InstallRoot:     filepath.Join(root, "install"),
		ReleasesRoot:    filepath.Join(root, "install", "releases"),
		Binary:          filepath.Join(root, "install", "pb"),
		BinaryRollback:  filepath.Join(root, "install", "releases", "rollback"),
		BinaryStaged:    filepath.Join(root, "install", "releases", "staged"),
		UpdateStateRoot: filepath.Join(root, "updated"),
		HostdSocket:     filepath.Join(root, "hostd", "hostd.sock"),
	}
	if err := os.MkdirAll(filepath.Dir(layout.Binary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.Binary, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := layout.Validate(); err != nil {
		t.Fatal(err)
	}
	hostdControl := &fakeNativeController{status: NativeControllerStatus{Registered: true, Enabled: true, Running: true, Ready: true}}
	updaterControl := &fakeNativeController{status: NativeControllerStatus{Registered: true, Enabled: true, Running: true, Ready: true}}
	hostd, err := New(Config{
		Platform: "linux", Kind: HostdKind, ConfigRoot: root, Executable: layout.Binary,
		User: "alice", Group: "staff", Arguments: []string{"__runtime-hostd"}, Controller: hostdControl,
	})
	if err != nil {
		t.Fatal(err)
	}
	updater, err := New(Config{
		Platform: "linux", Kind: UpdaterKind, ConfigRoot: root, Executable: layout.Binary,
		User: "root", Group: "root", Arguments: []string{"__runtime-updated"}, Controller: updaterControl,
	})
	if err != nil {
		t.Fatal(err)
	}
	oldHostd, oldUpdater := []byte("old hostd declaration"), []byte("old updater declaration")
	if err := atomicWrite(hostd.DefinitionPath(), oldHostd, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(updater.DefinitionPath(), oldUpdater, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewHostLifecycleManager(HostLifecycleConfig{
		StateRoot: filepath.Join(root, "service-state"), Hostd: hostd, Updater: updater,
		HostdProbe:   func(context.Context) error { return nil },
		UpdaterProbe: func(context.Context) error { return errors.New("updater health unavailable") },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Install(context.Background()); !errors.Is(err, ErrLifecycleNotReady) {
		t.Fatalf("install err=%v", err)
	}
	if got, _ := os.ReadFile(hostd.DefinitionPath()); !bytesEqual(got, oldHostd) {
		t.Fatalf("hostd declaration=%q want %q", got, oldHostd)
	}
	if got, _ := os.ReadFile(updater.DefinitionPath()); !bytesEqual(got, oldUpdater) {
		t.Fatalf("updater declaration=%q want %q", got, oldUpdater)
	}
	if hostdControl.snapshot() != (NativeControllerStatus{Registered: true, Enabled: true, Running: true, Ready: true}) || updaterControl.snapshot() != (NativeControllerStatus{Registered: true, Enabled: true, Running: true, Ready: true}) {
		t.Fatalf("native state hostd=%+v updater=%+v", hostdControl.snapshot(), updaterControl.snapshot())
	}
	if _, err := os.Stat(filepath.Join(root, "service-state", "service-lifecycle.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal remains: %v", err)
	}
	if hostdControl.start == 0 || updaterControl.start == 0 {
		t.Fatalf("both components must have reached start before probe failure: hostd=%d updater=%d", hostdControl.start, updaterControl.start)
	}
}

func TestHostLifecycleManagerIncludesPrivilegedHostBeforeSupervisor(t *testing.T) {
	root := t.TempDir()
	layout := Layout{
		Platform:        "linux",
		InstallRoot:     filepath.Join(root, "install"),
		ReleasesRoot:    filepath.Join(root, "install", "releases"),
		Binary:          filepath.Join(root, "install", "pb"),
		BinaryRollback:  filepath.Join(root, "install", "releases", "rollback"),
		BinaryStaged:    filepath.Join(root, "install", "releases", "staged"),
		UpdateStateRoot: filepath.Join(root, "updated"),
		HostdSocket:     filepath.Join(root, "hostd", "hostd.sock"),
	}
	if err := os.MkdirAll(filepath.Dir(layout.Binary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.Binary, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	hostControl := &fakeNativeController{}
	hostdControl := &fakeNativeController{}
	updaterControl := &fakeNativeController{}
	host, err := New(Config{Platform: "linux", Kind: HostKind, ConfigRoot: root, Executable: layout.Binary, User: "root", Group: "root", Arguments: []string{"__runtime-host-service"}, Controller: hostControl})
	if err != nil {
		t.Fatal(err)
	}
	hostd, err := New(Config{Platform: "linux", Kind: HostdKind, ConfigRoot: root, Executable: layout.Binary, User: "alice", Group: "staff", Arguments: []string{"__runtime-hostd"}, Controller: hostdControl})
	if err != nil {
		t.Fatal(err)
	}
	updater, err := New(Config{Platform: "linux", Kind: UpdaterKind, ConfigRoot: root, Executable: layout.Binary, User: "root", Group: "root", Arguments: []string{"__runtime-updated"}, Controller: updaterControl})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewHostLifecycleManager(HostLifecycleConfig{StateRoot: filepath.Join(root, "service-state"), Host: host, Hostd: hostd, Updater: updater})
	if err != nil {
		t.Fatal(err)
	}
	if len(manager.components) != 3 || manager.components[0].ID() != HostKind || manager.components[1].ID() != HostdKind || manager.components[2].ID() != UpdaterKind {
		t.Fatalf("component order=%v", []string{manager.components[0].ID(), manager.components[1].ID(), manager.components[2].ID()})
	}
}

func TestHostLifecycleManagerRollsBackPrivilegedHostWithSupervisorAndUpdater(t *testing.T) {
	root := t.TempDir()
	layout := Layout{
		Platform:        "linux",
		InstallRoot:     filepath.Join(root, "install"),
		ReleasesRoot:    filepath.Join(root, "install", "releases"),
		Binary:          filepath.Join(root, "install", "pb"),
		BinaryRollback:  filepath.Join(root, "install", "releases", "rollback"),
		BinaryStaged:    filepath.Join(root, "install", "releases", "staged"),
		UpdateStateRoot: filepath.Join(root, "updated"),
		HostdSocket:     filepath.Join(root, "hostd", "hostd.sock"),
	}
	if err := os.MkdirAll(filepath.Dir(layout.Binary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.Binary, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	controls := map[string]*fakeNativeController{
		HostKind:    {status: NativeControllerStatus{Registered: true, Enabled: true, Running: true, Ready: true}},
		HostdKind:   {status: NativeControllerStatus{Registered: true, Enabled: true, Running: true, Ready: true}},
		UpdaterKind: {status: NativeControllerStatus{Registered: true, Enabled: true, Running: true, Ready: true}},
	}
	newInstaller := func(kind, user, group, argument string) *Installer {
		installer, err := New(Config{Platform: "linux", Kind: kind, ConfigRoot: root, Executable: layout.Binary, User: user, Group: group, Arguments: []string{argument}, Controller: controls[kind]})
		if err != nil {
			t.Fatal(err)
		}
		return installer
	}
	host := newInstaller(HostKind, "root", "root", "__runtime-host-service")
	hostd := newInstaller(HostdKind, "alice", "staff", "__runtime-hostd")
	updater := newInstaller(UpdaterKind, "root", "root", "__runtime-updated")
	old := map[*Installer][]byte{host: []byte("old host"), hostd: []byte("old hostd"), updater: []byte("old updater")}
	for installer, definition := range old {
		if err := atomicWrite(installer.DefinitionPath(), definition, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	updaterFailure := errors.New("updater health unavailable")
	manager, err := NewHostLifecycleManager(HostLifecycleConfig{
		StateRoot: filepath.Join(root, "service-state"), Host: host, Hostd: hostd, Updater: updater,
		UpdaterProbe: func(context.Context) error { return updaterFailure },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Install(context.Background()); !errors.Is(err, ErrLifecycleNotReady) {
		t.Fatalf("install err=%v", err)
	}
	for installer, definition := range old {
		got, readErr := os.ReadFile(installer.DefinitionPath())
		if readErr != nil || !bytesEqual(got, definition) {
			t.Fatalf("definition for %s=%q err=%v want=%q", installer.config.Kind, got, readErr, definition)
		}
	}
	for kind, control := range controls {
		if got := control.snapshot(); got != (NativeControllerStatus{Registered: true, Enabled: true, Running: true, Ready: true}) {
			t.Fatalf("restored %s native state=%+v", kind, got)
		}
	}
	if controls[HostKind].start == 0 || controls[HostdKind].start == 0 || controls[UpdaterKind].start == 0 {
		t.Fatalf("all three components must reach start before updater probe failure: host=%d hostd=%d updater=%d", controls[HostKind].start, controls[HostdKind].start, controls[UpdaterKind].start)
	}
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
