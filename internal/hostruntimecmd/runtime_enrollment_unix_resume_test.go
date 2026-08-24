//go:build darwin || linux

package hostruntimecmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/enrollment"
)

type countingRuntimeEnrollmentClient struct {
	inner enrollmentClient
	calls int
}

func (c *countingRuntimeEnrollmentClient) Enroll(ctx context.Context, config enrollment.Config) (enrollment.RuntimeIdentity, error) {
	c.calls++
	return c.inner.Enroll(ctx, config)
}

func TestUnixRuntimeEnrollmentResumesCrashBeforeCheckpointWithoutCredentialReplay(t *testing.T) {
	now := time.Now().UTC()
	root := t.TempDir()
	enrollmentRequests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		enrollmentRequests++
		_ = json.NewEncoder(w).Encode(map[string]any{"data": enrollment.RuntimeIdentity{
			HelperID: "helper_client", MachineID: "mch_client", EnvironmentID: "env_client",
			Credential: "identity-0123456789012345678901234567890123456789", ExpiresAt: now.Add(time.Hour),
		}})
	}))
	defer server.Close()
	client, err := enrollment.NewClient(server.Client().Transport, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	counting := &countingRuntimeEnrollmentClient{inner: client}
	material := testClientBootstrapMaterial(server.URL, now.Add(time.Hour))
	publicKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	record := bootstrap.NewResumeRecord(server.URL, publicKey, "token", "Laptop", "client", "verifier-012345678901234567890123456789", now.Add(time.Hour))
	record.PairingStarted, record.Material = true, &material
	if err := bootstrap.SaveResume(root, record); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(t.TempDir(), "pb")
	if err := os.WriteFile(artifactPath, []byte("verified"), 0o700); err != nil {
		t.Fatal(err)
	}
	previousFetcher := fetchBootstrapArtifact
	fetchBootstrapArtifact = func(context.Context, bootstrap.ArtifactTarget, string, *http.Client) (string, error) {
		return artifactPath, nil
	}
	defer func() { fetchBootstrapArtifact = previousFetcher }()
	crash := errors.New("simulated crash before runtime checkpoint")
	_, err = prepareUnixBootstrapRuntime(context.Background(), &material, root, server.Client(), counting, false, func() error {
		record.RuntimeEnrolled = true
		return crash
	})
	var checkpointErr *runtimeEnrollmentCheckpointError
	if !errors.As(err, &checkpointErr) || !errors.Is(err, crash) {
		t.Fatalf("checkpoint error = %v", err)
	}
	reloaded, err := bootstrap.LoadResume(root, server.URL, publicKey, "", "Laptop", "client", now)
	if err != nil || reloaded.RuntimeEnrolled {
		t.Fatalf("journal after crash = %#v, err=%v", reloaded, err)
	}
	retryMaterial := testClientBootstrapMaterial(server.URL, now.Add(time.Hour))
	path, err := prepareUnixBootstrapRuntime(context.Background(), &retryMaterial, root, server.Client(), counting, false, func() error {
		reloaded.RuntimeEnrolled = true
		return bootstrap.SaveResume(root, reloaded)
	})
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err = bootstrap.LoadResume(root, server.URL, publicKey, "", "Laptop", "client", now)
	if err != nil || !reloaded.RuntimeEnrolled || path != artifactPath || counting.calls != 1 || enrollmentRequests != 1 {
		t.Fatalf("journal=%#v path=%q client_calls=%d requests=%d err=%v", reloaded, path, counting.calls, enrollmentRequests, err)
	}
}
