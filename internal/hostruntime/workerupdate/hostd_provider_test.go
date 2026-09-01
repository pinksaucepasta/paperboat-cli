package workerupdate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/hostdproto"
)

type recordingHostdGateClient struct {
	requests []hostdproto.UpdateGateRequest
	target   hostdproto.UpdateGateTargetBinding
}

func (c *recordingHostdGateClient) UpdateGate(_ context.Context, request hostdproto.UpdateGateRequest) (hostdproto.UpdateGateResponse, error) {
	c.requests = append(c.requests, request)
	return hostdproto.UpdateGateResponse{Target: c.target}, nil
}

func TestHostdDeploymentProviderCarriesExactSignedPolicyAndTargetFence(t *testing.T) {
	target := hostdproto.UpdateGateTargetBinding{MachineID: "machine_01", AccountID: "account_01", HostID: "host_01", TunnelID: "tunnel_01", ConnectorID: "connector_01", EdgeNodeID: "edge_01", ProcessEpoch: 2, SessionGeneration: 3, ConfigGeneration: 4, RouteGeneration: 5, FailureDomain: "hel1-a"}
	client := &recordingHostdGateClient{target: target}
	provider := HostdDeploymentProvider{Client: client}
	resolved, err := provider.CurrentTarget(context.Background(), TargetRequest{TransactionID: "transaction_01", Version: "2026.08.31.1", ManifestSHA256: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	err = provider.ObserveStability(context.Background(), StabilityRequest{TransactionID: "transaction_01", Candidate: "2026.08.31.1", ManifestSHA256: strings.Repeat("a", 64), Path: "/signed-canary", ExpectedStatus: 207, Samples: 4, Target: resolved, Window: 10 * time.Second, Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	request := client.requests[1]
	if request.Operation != hostdproto.UpdateGateStability || request.ManifestSHA256 != strings.Repeat("a", 64) || request.Path != "/signed-canary" || request.ExpectedStatus != 207 || request.Samples != 4 || request.ExpectedTarget == nil || *request.ExpectedTarget != target {
		t.Fatalf("request=%+v", request)
	}
	if err := provider.Commit(context.Background(), CommitRequest{TransactionID: "transaction_01", Version: "2026.08.31.1", ManifestSHA256: strings.Repeat("a", 64), Target: resolved}); err != nil {
		t.Fatal(err)
	}
	commit := client.requests[2]
	if commit.Operation != hostdproto.UpdateGateCommit || commit.Version != "2026.08.31.1" || commit.ManifestSHA256 != strings.Repeat("a", 64) || commit.ExpectedTarget == nil || *commit.ExpectedTarget != target {
		t.Fatalf("commit=%+v", commit)
	}
}
