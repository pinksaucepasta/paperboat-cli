//go:build trk28_local_acceptance

package workerupdate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releasepolicy"
)

// TestLocalPublishedTUFSource serves a publisher-created repository through a
// TLS test origin and exercises the same TUFSource path used by production.
// It is opt-in so ordinary tests never depend on a release workstation or
// local publication artifacts.
func TestLocalPublishedTUFSource(t *testing.T) {
	repository := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_TUF_REPOSITORY_DIR"))
	if repository == "" {
		t.Skip("PAPERBOAT_TEST_TUF_REPOSITORY_DIR is not set")
	}
	if info, err := os.Lstat(repository); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("invalid repository=%q err=%v", repository, err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		path, err := publishedPath(repository, request.URL)
		if err != nil {
			http.NotFound(writer, request)
			return
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			http.NotFound(writer, request)
			return
		}
		http.ServeFile(writer, request, path)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	source := TUFSource{
		RepositoryURL: server.URL,
		StateRoot:     filepath.Join(t.TempDir(), "tuf-state"),
		MachineID:     "machine_trk28",
		HTTP:          server.Client(),
		Deferral: DeferralSourceFunc(func(context.Context) (releasepolicy.Deferral, bool, error) {
			return releasepolicy.Deferral{}, false, nil
		}),
		FailureDomain: FailureDomainSourceFunc(func(_ context.Context, request FailureDomainRequest) (string, error) {
			if request.MachineID != "machine_trk28" || request.Platform == "" || request.Architecture == "" {
				return "", ErrFailureDomainUnavailable
			}
			return "iad-1", nil
		}),
	}
	release, found, err := source.ResolveManual(ctx)
	if err != nil {
		t.Fatalf("resolve publisher output through TUFSource: %v", err)
	}
	if !found || release.Version == "" || release.SHA256 == "" || release.ManifestSHA256 == "" || release.CanaryPath != "/healthz" || release.CanaryStatus != http.StatusOK {
		t.Fatalf("release=%+v found=%v", release, found)
	}
	if expected := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_TUF_VERSION")); expected != "" && release.Version != expected {
		t.Fatalf("version=%q want=%q", release.Version, expected)
	}
}

func publishedPath(repository string, requestURL *url.URL) (string, error) {
	if requestURL == nil || requestURL.RawQuery != "" || requestURL.Fragment != "" {
		return "", os.ErrInvalid
	}
	relative, err := url.PathUnescape(strings.TrimPrefix(requestURL.Path, "/"))
	if err != nil || relative == "" || strings.ContainsRune(relative, '\x00') {
		return "", os.ErrInvalid
	}
	clean := filepath.Clean(filepath.FromSlash(relative))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", os.ErrInvalid
	}
	root, err := filepath.Abs(repository)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", os.ErrInvalid
	}
	return path, nil
}
