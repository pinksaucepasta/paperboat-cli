package workerupdate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releaseindex"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/releasepolicy"
)

type failureDomainClient struct {
	request hostdproto.UpdateGateRequest
	result  hostdproto.UpdateGateResponse
	err     error
}

func (c *failureDomainClient) UpdateGate(_ context.Context, request hostdproto.UpdateGateRequest) (hostdproto.UpdateGateResponse, error) {
	c.request = request
	return c.result, c.err
}

func validFailureDomainTarget(machineID, domain string) hostdproto.UpdateGateTargetBinding {
	return hostdproto.UpdateGateTargetBinding{MachineID: machineID, AccountID: "account_1", HostID: "host_1", TunnelID: "tunnel_1", ConnectorID: "connector_1", EdgeNodeID: "edge_1", ProcessEpoch: 2, SessionGeneration: 3, ConfigGeneration: 4, RouteGeneration: 5, FailureDomain: domain}
}

func TestActiveVersionPermittedEnforcesSignedRevocations(t *testing.T) {
	index := releaseindex.Index{Version: "2026.08.27.56"}
	if !activeVersionPermitted(index, "2026.08.27.55") {
		t.Fatal("unrevoked previous release was rejected")
	}
	index.RevokedVersions = []string{"2026.08.27.55"}
	if activeVersionPermitted(index, "2026.08.27.55") {
		t.Fatal("explicitly revoked release was accepted")
	}
	index.RevokedVersions = nil
	index.MinimumVersion = "2026.08.27.56"
	if activeVersionPermitted(index, "2026.08.27.55") {
		t.Fatal("release below signed minimum was accepted")
	}
	index.MinimumVersion = ""
	index.Revoked = true
	if activeVersionPermitted(index, index.Version) {
		t.Fatal("revoked current release was accepted")
	}
}

func TestCurrentRevokedReleaseRemainsIdentifiableButNotActivatable(t *testing.T) {
	plan, err := releasepolicy.Default("2026.08.27.56", strings.Repeat("b", 64), 1, "security", "revoked-test", []releasepolicy.PlatformTarget{{Platform: "linux", Architecture: "amd64"}})
	if err != nil {
		t.Fatal(err)
	}
	index := releaseindex.Index{
		Version: "2026.08.27.56", Revoked: true, ManifestSHA256: strings.Repeat("b", 64),
		DeploymentPlan: &plan,
		Targets:        []releaseindex.Target{{Component: "pb", SHA256: strings.Repeat("a", 64), Length: 10, Platform: "linux", Architecture: "amd64"}},
		HostdAPIMin:    1, HostdAPIMax: 1, RuntimeAPIMin: 1, RuntimeAPIMax: 1,
	}
	release, ok := releaseFromIndex(index)
	if !ok || release.Version != index.Version {
		t.Fatalf("release=%+v ok=%v", release, ok)
	}
	if activeVersionPermitted(index, release.Version) {
		t.Fatal("revoked current release was activatable")
	}
}

func TestReleaseFromIndexProjectsSignedActivationPolicy(t *testing.T) {
	manifest := strings.Repeat("b", 64)
	plan, err := releasepolicy.Default("2026.08.31.1", manifest, 7, "security", "signed-seed", []releasepolicy.PlatformTarget{{Platform: "linux", Architecture: "amd64"}})
	if err != nil {
		t.Fatal(err)
	}
	index := releaseindex.Index{Version: plan.Version, ManifestSHA256: manifest, DeploymentPlan: &plan, Targets: []releaseindex.Target{{Component: "pb", SHA256: strings.Repeat("a", 64), Length: 10, Platform: "linux", Architecture: "amd64"}}, HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2}
	release, ok := releaseFromIndex(index)
	if !ok || release.ManifestSHA256 != manifest || release.CanaryPath != plan.Canary.Path || release.CanaryStatus != plan.Canary.ExpectedStatus || release.CanarySamples != plan.Canary.Samples || release.CanaryTimeout != time.Duration(plan.Canary.TimeoutSeconds)*time.Second || release.DrainTimeout != time.Duration(plan.Activation.DrainTimeoutSeconds)*time.Second || release.StabilityWindow != time.Duration(plan.Activation.StabilityWindowSeconds)*time.Second || release.StabilityInterval != time.Duration(plan.Activation.StabilityProbeIntervalSeconds)*time.Second || release.RollbackTimeout != time.Duration(plan.Activation.RollbackTimeoutSeconds)*time.Second {
		t.Fatalf("release=%+v ok=%v", release, ok)
	}
	changed := release
	changed.StabilityWindow++
	if sameReleaseTargets(release, changed) {
		t.Fatal("signed policy mutation was not bound to release identity")
	}
}

func TestHostdFailureDomainSourceBindsFreshSignedInputs(t *testing.T) {
	client := &failureDomainClient{result: hostdproto.UpdateGateResponse{Target: validFailureDomainTarget("machine_1", "iad-1")}}
	source := HostdFailureDomainSource{Client: client, MachineID: "machine_1"}
	request := FailureDomainRequest{ReleaseID: "rel_1", Version: "2026.08.31.1", ManifestSHA256: strings.Repeat("a", 64), PlanSHA256: strings.Repeat("b", 64), MachineID: "machine_1", Platform: "linux", Architecture: "amd64"}
	domain, err := source.ResolveFailureDomain(context.Background(), request)
	if err != nil || domain != "iad-1" {
		t.Fatalf("domain=%q err=%v", domain, err)
	}
	if client.request.Operation != hostdproto.UpdateGateTarget || client.request.Version != request.Version || client.request.ManifestSHA256 != request.ManifestSHA256 || client.request.TransactionID != eligibilityTransactionID(request) {
		t.Fatalf("request=%+v", client.request)
	}
	changed := request
	changed.PlanSHA256 = strings.Repeat("c", 64)
	if _, err := source.ResolveFailureDomain(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	if client.request.TransactionID == eligibilityTransactionID(request) {
		t.Fatal("plan digest did not change binding transaction")
	}
}

func TestHostdFailureDomainSourceRejectsMissingStaleOrWrongBinding(t *testing.T) {
	request := FailureDomainRequest{ReleaseID: "rel_1", Version: "2026.08.31.1", ManifestSHA256: strings.Repeat("a", 64), PlanSHA256: strings.Repeat("b", 64), MachineID: "machine_1", Platform: "linux", Architecture: "amd64"}
	for name, source := range map[string]HostdFailureDomainSource{
		"missing client": {MachineID: "machine_1"},
		"wrong machine":  {MachineID: "machine_2", Client: &failureDomainClient{result: hostdproto.UpdateGateResponse{Target: validFailureDomainTarget("machine_2", "iad-1")}}},
		"invalid domain": {MachineID: "machine_1", Client: &failureDomainClient{result: hostdproto.UpdateGateResponse{Target: validFailureDomainTarget("machine_1", "*")}}},
		"client error":   {MachineID: "machine_1", Client: &failureDomainClient{err: errors.New("offline")}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := source.ResolveFailureDomain(context.Background(), request); !errors.Is(err, ErrFailureDomainUnavailable) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if _, err := (HostdFailureDomainSource{Client: &failureDomainClient{result: hostdproto.UpdateGateResponse{Target: validFailureDomainTarget("machine_1", "iad-1")}}, MachineID: "machine_1"}).ResolveFailureDomain(context.Background(), FailureDomainRequest{ReleaseID: request.ReleaseID, Version: request.Version, ManifestSHA256: request.ManifestSHA256, PlanSHA256: request.PlanSHA256, MachineID: request.MachineID, Platform: "linux", Architecture: "386"}); !errors.Is(err, ErrFailureDomainUnavailable) {
		t.Fatalf("unsupported platform err=%v", err)
	}
}

func TestTUFSourceRequiresDurableDeferralAndFreshFailureDomain(t *testing.T) {
	index, now := validEligibilityIndex(t)
	source := TUFSource{
		MachineID: "machine_1",
		FailureDomain: FailureDomainSourceFunc(func(context.Context, FailureDomainRequest) (string, error) {
			return "iad-1", nil
		}),
	}
	if _, err := source.eligible(context.Background(), index, now, true); !errors.Is(err, ErrDeferralUnavailable) {
		t.Fatalf("missing durable deferral err=%v", err)
	}
	source.Deferral = DeferralSourceFunc(func(context.Context) (releasepolicy.Deferral, bool, error) {
		return releasepolicy.Deferral{}, false, nil
	})
	source.FailureDomain = nil
	if _, err := source.eligible(context.Background(), index, now, true); !errors.Is(err, ErrFailureDomainUnavailable) {
		t.Fatalf("missing live failure domain err=%v", err)
	}
	source.FailureDomain = FailureDomainSourceFunc(func(context.Context, FailureDomainRequest) (string, error) {
		return "*", nil
	})
	if _, err := source.eligible(context.Background(), index, now, true); !errors.Is(err, ErrFailureDomainUnavailable) {
		t.Fatalf("wildcard failure domain err=%v", err)
	}
}

func validEligibilityIndex(t *testing.T) (releaseindex.Index, time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 31, 15, 0, 0, 0, time.UTC)
	manifest := strings.Repeat("a", 64)
	plan, err := releasepolicy.Default("2026.08.31.1", manifest, 1, "routine", "worker-test-seed", []releasepolicy.PlatformTarget{{Platform: "linux", Architecture: "amd64"}})
	if err != nil {
		t.Fatal(err)
	}
	planDigest, err := plan.PlanSHA256()
	if err != nil {
		t.Fatal(err)
	}
	asset := releaseindex.AssetName("linux", "amd64")
	return releaseindex.Index{
		Schema: releaseindex.SchemaV1, ReleaseID: "rel_worker_test", Version: plan.Version, Channel: "stable", Severity: "routine",
		CreatedAt: now.Add(-3 * time.Hour), Platform: "linux", Architecture: "amd64", BinaryFormat: "elf",
		Targets:     []releaseindex.Target{{Component: "pb", TargetPath: asset, AssetName: asset, Repository: "example/paperboat-cli", DownloadURL: "https://github.com/example/paperboat-cli/releases/download/" + plan.Version + "/" + asset, SHA256: strings.Repeat("b", 64), Length: 1, Platform: "linux", Architecture: "amd64", BinaryFormat: "elf"}},
		HostdAPIMin: 1, HostdAPIMax: 2, RuntimeAPIMin: 1, RuntimeAPIMax: 2, RolloutPolicyRevision: plan.PolicyRevision,
		ManifestSHA256: manifest, DeploymentPlanSHA256: planDigest, DeploymentPlan: &plan,
	}, now
}
