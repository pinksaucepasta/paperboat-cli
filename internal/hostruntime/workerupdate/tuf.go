package workerupdate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releasepolicy"
)

var (
	// ErrFailureDomainUnavailable is returned when the host cannot provide a
	// current, exact failure-domain observation. A wildcard or cached value is
	// never substituted because it would defeat cohort isolation.
	ErrFailureDomainUnavailable = errors.New("live failure domain is unavailable")
	// ErrDeferralUnavailable means a local deferral is malformed or cannot be
	// read. Runtime selection fails closed rather than treating an uncertain
	// deferral as permission to update.
	ErrDeferralUnavailable = errors.New("release deferral is unavailable")
)

// FailureDomainRequest binds the local observation to the exact signed
// release plan under consideration. Hostd implementations should resolve the
// current domain from their live carrier/runtime state and must not read it
// from an environment variable or a caller-selected value.
type FailureDomainRequest struct {
	ReleaseID      string
	Version        string
	ManifestSHA256 string
	PlanSHA256     string
	MachineID      string
	Platform       string
	Architecture   string
}

// FailureDomainSource is the narrow hostd-local seam used by TUFSource. It is
// intentionally one-shot: each selection obtains a fresh value so a network
// or carrier replacement cannot silently reuse an old cohort domain.
type FailureDomainSource interface {
	ResolveFailureDomain(context.Context, FailureDomainRequest) (string, error)
}

type FailureDomainSourceFunc func(context.Context, FailureDomainRequest) (string, error)

func (f FailureDomainSourceFunc) ResolveFailureDomain(ctx context.Context, request FailureDomainRequest) (string, error) {
	if f == nil {
		return "", ErrFailureDomainUnavailable
	}
	return f(ctx, request)
}

// DeferralSource reads the single local deferral record, if one exists. The
// source is not allowed to alter the signed plan or rollout state.
type DeferralSource interface {
	CurrentDeferral(context.Context) (releasepolicy.Deferral, bool, error)
}

type DeferralSourceFunc func(context.Context) (releasepolicy.Deferral, bool, error)

func (f DeferralSourceFunc) CurrentDeferral(ctx context.Context) (releasepolicy.Deferral, bool, error) {
	if f == nil {
		return releasepolicy.Deferral{}, false, ErrDeferralUnavailable
	}
	return f(ctx)
}

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
	FailureDomain FailureDomainSource
	Deferral      DeferralSource
}

func (s TUFSource) Resolve(ctx context.Context) (Release, bool, error) {
	return s.resolve(ctx, false, false)
}

// ResolveManual bypasses only the signed cohort delay. It still verifies TUF,
// revocations, compatibility metadata, and every artifact hash.
func (s TUFSource) ResolveManual(ctx context.Context) (Release, bool, error) {
	return s.resolve(ctx, true, false)
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
	eligible, err := s.eligible(ctx, index, now, bypassCohort)
	if err != nil {
		return Release{}, false, err
	}
	if !eligible {
		return Release{}, false, nil
	}
	release, ok := releaseFromIndex(index)
	if !ok {
		return Release{}, false, ErrInvalidRelease
	}
	return release, true, nil
}

func (s TUFSource) resolve(ctx context.Context, bypassCohort, supervisor bool) (Release, bool, error) {
	now := s.now()
	index, err := bootstrap.FetchVerifiedReleaseIndex(ctx, s.RepositoryURL, filepath.Join(s.StateRoot, "index"), s.HTTP, now)
	if err != nil {
		return Release{}, false, err
	}
	if index.SupervisorMaintenance && !supervisor {
		return Release{}, false, nil
	}
	eligible, err := s.eligible(ctx, index, now, bypassCohort)
	if err != nil {
		return Release{}, false, err
	}
	if !eligible {
		return Release{}, false, nil
	}
	release, ok := releaseFromIndex(index)
	if !ok {
		return Release{}, false, ErrInvalidRelease
	}
	return release, true, nil
}

func (s TUFSource) eligible(ctx context.Context, index releaseindex.Index, now time.Time, bypassCohort bool) (bool, error) {
	if index.Validate(now) != nil || !releasepolicy.IsIdentifier(s.MachineID) {
		return false, ErrInvalidRelease
	}
	if index.Revoked || index.MinimumVersion != "" && compareVersion(index.Version, index.MinimumVersion) < 0 || index.DeploymentPlan == nil || index.DeploymentPlan.RolloutState != releasepolicy.RolloutStateActive {
		return false, nil
	}
	if now.Before(index.CreatedAt) {
		return false, nil
	}
	if s.Deferral == nil {
		return false, ErrDeferralUnavailable
	}
	deferral, present, err := s.Deferral.CurrentDeferral(ctx)
	if err != nil {
		return false, errors.Join(ErrDeferralUnavailable, err)
	}
	if present {
		active, err := index.DeploymentPlan.DeferralActive(deferral, now)
		if err != nil {
			return false, errors.Join(ErrDeferralUnavailable, err)
		}
		if active {
			return false, nil
		}
	}
	if s.FailureDomain == nil {
		return false, ErrFailureDomainUnavailable
	}
	planDigest, err := index.DeploymentPlan.PlanSHA256()
	if err != nil {
		return false, errors.Join(ErrInvalidRelease, err)
	}
	domain, err := s.FailureDomain.ResolveFailureDomain(ctx, FailureDomainRequest{ReleaseID: index.ReleaseID, Version: index.Version, ManifestSHA256: index.ManifestSHA256, PlanSHA256: planDigest, MachineID: s.MachineID, Platform: index.Platform, Architecture: index.Architecture})
	if err != nil || !releasepolicy.IsIdentifier(domain) {
		return false, errors.Join(ErrFailureDomainUnavailable, err)
	}
	return index.EligibleFor(releaseindex.EligibilityInput{MachineID: s.MachineID, Platform: index.Platform, Architecture: index.Architecture, FailureDomain: domain, Now: now, BypassCohort: bypassCohort}), nil
}

// Active resolves signed metadata for the runtime already selected by the
// stable launcher. A current release that has since been revoked remains
// identifiable so the resident updater can start and replace it; Resolve and
// FetchComponent continue to reject it for new activation. An updater never
// invents metadata for an older or unknown local executable.
func (s TUFSource) Active(ctx context.Context, version string) (Release, error) {
	now := s.now()
	index, err := bootstrap.FetchVerifiedReleaseIndex(ctx, s.RepositoryURL, filepath.Join(s.StateRoot, "index"), s.HTTP, now)
	if err != nil {
		return Release{}, err
	}
	release, ok := releaseFromIndex(index)
	if !ok || release.Version != version {
		if !activeVersionPermitted(index, version) {
			return Release{}, ErrReleaseRevoked
		}
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
	if !ok || !activeVersionPermitted(index, release.Version) || !sameReleaseTargets(selected, release) {
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
		ManifestSHA256: index.ManifestSHA256,
		CanaryPath:     index.DeploymentPlan.Canary.Path, CanaryStatus: index.DeploymentPlan.Canary.ExpectedStatus, CanarySamples: index.DeploymentPlan.Canary.Samples,
		CanaryTimeout:     time.Duration(index.DeploymentPlan.Canary.TimeoutSeconds) * time.Second,
		DrainTimeout:      time.Duration(index.DeploymentPlan.Activation.DrainTimeoutSeconds) * time.Second,
		StabilityWindow:   time.Duration(index.DeploymentPlan.Activation.StabilityWindowSeconds) * time.Second,
		StabilityInterval: time.Duration(index.DeploymentPlan.Activation.StabilityProbeIntervalSeconds) * time.Second,
		RollbackTimeout:   time.Duration(index.DeploymentPlan.Activation.RollbackTimeoutSeconds) * time.Second,
		CLISHA256:         target.SHA256, CLILength: target.Length, CLIPlatform: target.Platform, CLIArchitecture: target.Architecture,
		Hostd: component, Updater: component, Launcher: component,
		HostdAPIMin: index.HostdAPIMin, HostdAPIMax: index.HostdAPIMax, RuntimeAPIMin: index.RuntimeAPIMin, RuntimeAPIMax: index.RuntimeAPIMax,
		SupervisorMaintenance: index.SupervisorMaintenance,
	}, true
}

func sameReleaseTargets(a, b Release) bool {
	return a.Version == b.Version && a.SHA256 == b.SHA256 && a.Length == b.Length && a.Platform == b.Platform && a.Architecture == b.Architecture &&
		a.ManifestSHA256 == b.ManifestSHA256 && a.CanaryPath == b.CanaryPath && a.CanaryStatus == b.CanaryStatus && a.CanarySamples == b.CanarySamples && a.CanaryTimeout == b.CanaryTimeout && a.DrainTimeout == b.DrainTimeout && a.StabilityWindow == b.StabilityWindow && a.StabilityInterval == b.StabilityInterval && a.RollbackTimeout == b.RollbackTimeout &&
		a.HostdAPIMin == b.HostdAPIMin && a.HostdAPIMax == b.HostdAPIMax && a.RuntimeAPIMin == b.RuntimeAPIMin && a.RuntimeAPIMax == b.RuntimeAPIMax && a.SupervisorMaintenance == b.SupervisorMaintenance
}

func openReadOnly(path string) (io.ReadCloser, error) { return os.Open(path) }
