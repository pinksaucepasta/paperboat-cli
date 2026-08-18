package workerupdate

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
)

// TUFSource is the production resolver/fetcher pair. It trusts only the
// embedded TUF root and a fixed stable release-index target; no current.json,
// redirect, caller-selected target path, or unsigned server field participates
// in update selection.
type TUFSource struct {
	RepositoryURL string
	StateRoot     string
	MachineID     string
	HTTP          *http.Client
	Now           func() time.Time
}

func (s TUFSource) Resolve(ctx context.Context) (Release, bool, error) {
	now := s.now()
	index, err := bootstrap.FetchVerifiedReleaseIndex(ctx, s.RepositoryURL, filepath.Join(s.StateRoot, "index"), s.HTTP, now)
	if err != nil {
		return Release{}, false, err
	}
	if index.SupervisorMaintenance || !index.Eligible(s.MachineID, now, false) {
		return Release{}, false, nil
	}
	release, ok := releaseFromIndex(index)
	if !ok {
		return Release{}, false, ErrInvalidRelease
	}
	return release, true, nil
}

// ResolveManual bypasses only the signed cohort delay. It still verifies TUF,
// revocations, compatibility metadata, and every artifact hash.
func (s TUFSource) ResolveManual(ctx context.Context) (Release, bool, error) {
	now := s.now()
	index, err := bootstrap.FetchVerifiedReleaseIndex(ctx, s.RepositoryURL, filepath.Join(s.StateRoot, "index"), s.HTTP, now)
	if err != nil {
		return Release{}, false, err
	}
	if index.SupervisorMaintenance || !index.Eligible(s.MachineID, now, true) {
		return Release{}, false, nil
	}
	release, ok := releaseFromIndex(index)
	if !ok {
		return Release{}, false, ErrInvalidRelease
	}
	return release, true, nil
}

// ResolveSupervisor resolves the newest signed supervisor release. A release
// can require maintenance even when its worker is otherwise eligible; the
// supervisor updater stages that release and waits for a protected-workload
// approval instead of silently restarting a host supervisor.
func (s TUFSource) ResolveSupervisor(ctx context.Context) (Release, bool, error) {
	return s.resolveSupervisor(ctx, false)
}

// ResolveSupervisorManual bypasses only the signed cohort delay. It still
// requires a fresh, valid TUF index and exact supervisor targets.
func (s TUFSource) ResolveSupervisorManual(ctx context.Context) (Release, bool, error) {
	return s.resolveSupervisor(ctx, true)
}

func (s TUFSource) resolveSupervisor(ctx context.Context, bypassCohort bool) (Release, bool, error) {
	now := s.now()
	index, err := bootstrap.FetchVerifiedReleaseIndex(ctx, s.RepositoryURL, filepath.Join(s.StateRoot, "index"), s.HTTP, now)
	if err != nil {
		return Release{}, false, err
	}
	if !index.Eligible(s.MachineID, now, bypassCohort) {
		return Release{}, false, nil
	}
	release, ok := releaseFromIndex(index)
	if !ok || release.Hostd.SHA256 == "" || release.Updater.SHA256 == "" || release.Launcher.SHA256 == "" {
		return Release{}, false, ErrInvalidRelease
	}
	return release, true, nil
}

// Active resolves the signed metadata for the runtime already selected by the
// stable launcher. Startup fails closed if that executable is not the exact
// signed active version; an updater never invents a hash for a local file.
func (s TUFSource) Active(ctx context.Context, version string) (Release, error) {
	now := s.now()
	index, err := bootstrap.FetchVerifiedReleaseIndex(ctx, s.RepositoryURL, filepath.Join(s.StateRoot, "index"), s.HTTP, now)
	if err != nil {
		return Release{}, err
	}
	release, ok := releaseFromIndex(index)
	if !ok || release.Version != version {
		return Release{}, ErrInvalidRelease
	}
	return release, nil
}

func (s TUFSource) Fetch(ctx context.Context, release Release) (io.ReadCloser, error) {
	return s.FetchComponent(ctx, release, "runtime")
}

func (s TUFSource) FetchComponent(ctx context.Context, release Release, component string) (io.ReadCloser, error) {
	if component != "runtime" && component != "cli" && component != "hostd" && component != "updater" && component != "launcher" {
		return nil, ErrInvalidRelease
	}
	now := s.now()
	index, err := bootstrap.FetchVerifiedReleaseIndex(ctx, s.RepositoryURL, filepath.Join(s.StateRoot, "index"), s.HTTP, now)
	if err != nil {
		return nil, err
	}
	selected, ok := releaseFromIndex(index)
	if !ok || !sameReleaseTargets(selected, release) {
		return nil, ErrInvalidRelease
	}
	path, err := bootstrap.FetchVerifiedReleaseComponent(ctx, s.RepositoryURL, filepath.Join(s.StateRoot, "targets"), index, component, s.HTTP, now)
	if err != nil {
		return nil, err
	}
	return openReadOnly(path)
}

func (s TUFSource) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func releaseFromIndex(index releaseindex.Index) (Release, bool) {
	runtimeTarget, runtimeOK := index.Component("runtime")
	cliTarget, cliOK := index.Component("cli")
	hostdTarget, hostdOK := index.Component("hostd")
	updaterTarget, updaterOK := index.Component("updater")
	launcherTarget, launcherOK := index.Component("launcher")
	if !runtimeOK || !cliOK || !hostdOK || !updaterOK || !launcherOK {
		return Release{}, false
	}
	return Release{
		Version: index.Version, SHA256: runtimeTarget.SHA256, Length: runtimeTarget.Length, Platform: runtimeTarget.Platform, Architecture: runtimeTarget.Architecture,
		CLISHA256: cliTarget.SHA256, CLILength: cliTarget.Length, CLIPlatform: cliTarget.Platform, CLIArchitecture: cliTarget.Architecture,
		HostdAPIMin: index.HostdAPIMin, HostdAPIMax: index.HostdAPIMax, RuntimeAPIMin: index.RuntimeAPIMin, RuntimeAPIMax: index.RuntimeAPIMax,
		Hostd:                 ComponentTarget{SHA256: hostdTarget.SHA256, Length: hostdTarget.Length, Platform: hostdTarget.Platform, Architecture: hostdTarget.Architecture},
		Updater:               ComponentTarget{SHA256: updaterTarget.SHA256, Length: updaterTarget.Length, Platform: updaterTarget.Platform, Architecture: updaterTarget.Architecture},
		Launcher:              ComponentTarget{SHA256: launcherTarget.SHA256, Length: launcherTarget.Length, Platform: launcherTarget.Platform, Architecture: launcherTarget.Architecture},
		SupervisorMaintenance: index.SupervisorMaintenance,
	}, true
}

func sameReleaseTargets(a, b Release) bool {
	return a.Version == b.Version && a.SHA256 == b.SHA256 && a.Length == b.Length && a.Platform == b.Platform && a.Architecture == b.Architecture &&
		a.CLISHA256 == b.CLISHA256 && a.CLILength == b.CLILength && a.CLIPlatform == b.CLIPlatform && a.CLIArchitecture == b.CLIArchitecture &&
		a.Hostd == b.Hostd && a.Updater == b.Updater && a.Launcher == b.Launcher && a.HostdAPIMin == b.HostdAPIMin && a.HostdAPIMax == b.HostdAPIMax && a.RuntimeAPIMin == b.RuntimeAPIMin && a.RuntimeAPIMax == b.RuntimeAPIMax && a.SupervisorMaintenance == b.SupervisorMaintenance
}

func openReadOnly(path string) (io.ReadCloser, error) { return os.Open(path) }
