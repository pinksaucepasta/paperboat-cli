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

func (s TUFSource) Fetch(ctx context.Context, release Release) (io.ReadCloser, error) {
	now := s.now()
	index, err := bootstrap.FetchVerifiedReleaseIndex(ctx, s.RepositoryURL, filepath.Join(s.StateRoot, "index"), s.HTTP, now)
	if err != nil {
		return nil, err
	}
	selected, ok := releaseFromIndex(index)
	if !ok || selected.Version != release.Version || selected.SHA256 != release.SHA256 || selected.Length != release.Length {
		return nil, ErrInvalidRelease
	}
	path, err := bootstrap.FetchVerifiedReleaseComponent(ctx, s.RepositoryURL, filepath.Join(s.StateRoot, "targets"), index, "runtime", s.HTTP, now)
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
	target, ok := index.Component("runtime")
	if !ok {
		return Release{}, false
	}
	return Release{Version: index.Version, SHA256: target.SHA256, Length: target.Length, Platform: target.Platform, Architecture: target.Architecture, HostdAPIMin: index.HostdAPIMin, HostdAPIMax: index.HostdAPIMax, RuntimeAPIMin: index.RuntimeAPIMin, RuntimeAPIMax: index.RuntimeAPIMax}, true
}

func openReadOnly(path string) (io.ReadCloser, error) { return os.Open(path) }
