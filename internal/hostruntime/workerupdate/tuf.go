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
	if !ok {
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
	if !activeVersionPermitted(index, version) {
		return Release{}, ErrReleaseRevoked
	}
	release, ok := releaseFromIndex(index)
	if !ok || release.Version != version {
		return Release{}, ErrInvalidRelease
	}
	return release, nil
}

func activeVersionPermitted(index releaseindex.Index, version string) bool {
	if !validVersion(version) || index.Version == version && index.Revoked || index.MinimumVersion != "" && compareVersion(version, index.MinimumVersion) < 0 {
		return false
	}
	for _, revoked := range index.RevokedVersions {
		if revoked == version {
			return false
		}
	}
	return true
}

func (s TUFSource) Fetch(ctx context.Context, release Release) (io.ReadCloser, error) {
	return s.FetchComponent(ctx, release, "pb")
}

func (s TUFSource) FetchComponent(ctx context.Context, release Release, component string) (io.ReadCloser, error) {
	// Windows' SCM activation keeps role-labelled journal entries for
	// compatibility, but every role is now the same signed pb artifact. Keep
	// that translation here so callers cannot accidentally fetch a legacy
	// component target that no longer exists in the signed index.
	switch component {
	case "pb", "runtime", "cli", "hostd", "updater", "launcher":
		component = "pb"
	default:
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
	target, ok := index.Component("pb")
	if !ok {
		return Release{}, false
	}
	component := ComponentTarget{SHA256: target.SHA256, Length: target.Length, Platform: target.Platform, Architecture: target.Architecture}
	return Release{
		Version: index.Version, SHA256: target.SHA256, Length: target.Length, Platform: target.Platform, Architecture: target.Architecture,
		CLISHA256: target.SHA256, CLILength: target.Length, CLIPlatform: target.Platform, CLIArchitecture: target.Architecture,
		Hostd: component, Updater: component, Launcher: component,
		HostdAPIMin: index.HostdAPIMin, HostdAPIMax: index.HostdAPIMax, RuntimeAPIMin: index.RuntimeAPIMin, RuntimeAPIMax: index.RuntimeAPIMax,
		SupervisorMaintenance: index.SupervisorMaintenance,
	}, true
}

func sameReleaseTargets(a, b Release) bool {
	return a.Version == b.Version && a.SHA256 == b.SHA256 && a.Length == b.Length && a.Platform == b.Platform && a.Architecture == b.Architecture &&
		a.HostdAPIMin == b.HostdAPIMin && a.HostdAPIMax == b.HostdAPIMax && a.RuntimeAPIMin == b.RuntimeAPIMin && a.RuntimeAPIMax == b.RuntimeAPIMax && a.SupervisorMaintenance == b.SupervisorMaintenance
}

func openReadOnly(path string) (io.ReadCloser, error) { return os.Open(path) }
