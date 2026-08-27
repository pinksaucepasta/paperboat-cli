//go:build darwin || linux

package updated

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

func TestHTTPHealthRejectsCandidateWithoutFreshHeartbeat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"live":true}`)) }))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://127.0.0.1" + parsed.Path + "/healthz"
	// httptest uses a loopback IP but may not preserve it in URL on all hosts.
	endpoint = strings.Replace(server.URL, parsed.Hostname(), "127.0.0.1", 1) + "/healthz"
	health := HTTPHealth{Endpoint: endpoint}
	stale := hostdproto.Status{State: hostdproto.StateActive, WorkerID: "runtime", APIVersion: 1, Epoch: 1, LastHeartbeatUnixMilli: time.Now().Add(-16 * time.Second).UnixMilli()}
	if err := health.Check(context.Background(), stale, workerupdate.Release{}); err == nil {
		t.Fatal("stale worker heartbeat passed health")
	}
	fresh := stale
	fresh.LastHeartbeatUnixMilli = time.Now().UnixMilli()
	if err := health.Check(context.Background(), fresh, workerupdate.Release{}); err != nil {
		t.Fatalf("fresh heartbeat health=%v", err)
	}
}

func TestValidUnixWorkerIdentitySupportsOnlyExactPairs(t *testing.T) {
	for _, test := range []struct {
		uid, gid int
		want     bool
	}{
		{uid: 1000, gid: 1000, want: true},
		{uid: 0, gid: 0, want: true},
		{uid: 0, gid: 1000},
		{uid: 1000, gid: 0},
		{uid: -1, gid: -1},
	} {
		if got := validUnixWorkerIdentity(test.uid, test.gid); got != test.want {
			t.Fatalf("validUnixWorkerIdentity(%d, %d)=%v want %v", test.uid, test.gid, got, test.want)
		}
	}
}

func TestResolveReleaseDoesNotActivateOrWaitForMonitor(t *testing.T) {
	called := false
	result, err := resolveRelease(context.Background(), "2026.08.27.46", func(context.Context) (workerupdate.Release, bool, error) {
		called = true
		return workerupdate.Release{Version: "2026.08.27.47"}, true, nil
	})
	if err != nil {
		t.Fatalf("resolveRelease error = %v", err)
	}
	if !called {
		t.Fatal("resolver was not called")
	}
	if result.Version != "2026.08.27.47" || result.Updated {
		t.Fatalf("result = %+v, want version-only result", result)
	}
}

func TestResolveReleaseKeepsActiveVersionWhenNoRelease(t *testing.T) {
	result, err := resolveRelease(context.Background(), "2026.08.27.46", func(context.Context) (workerupdate.Release, bool, error) {
		return workerupdate.Release{}, false, nil
	})
	if err != nil {
		t.Fatalf("resolveRelease error = %v", err)
	}
	if result.Version != "2026.08.27.46" || result.Updated {
		t.Fatalf("result = %+v, want active version", result)
	}
}
