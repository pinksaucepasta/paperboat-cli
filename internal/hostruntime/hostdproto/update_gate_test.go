package hostdproto

import (
	"bytes"
	"strings"
	"testing"
)

func updateGateTargetFixture() UpdateGateTargetBinding {
	return UpdateGateTargetBinding{Scope: UpdateGateScopeTunnel, MachineID: "machine_01", AccountID: "account_01", HostID: "host_01", TunnelID: "tunnel_01", ConnectorID: "connector_01", EdgeNodeID: "edge_01", ProcessEpoch: 2, SessionGeneration: 3, ConfigGeneration: 4, RouteGeneration: 5, FailureDomain: "hel1-a"}
}

func TestUpdateGateFrameBindsSignedPolicyAndLiveTarget(t *testing.T) {
	target := updateGateTargetFixture()
	request := UpdateGateRequest{Operation: UpdateGateStability, TransactionID: "transaction_01", Version: "2026.08.31.1", ManifestSHA256: strings.Repeat("a", 64), Path: "/_paperboat/canary?phase=update", ExpectedStatus: 204, Samples: 3, WindowMillis: 10_000, IntervalMillis: 1_000, ExpectedTarget: &target}
	var wire bytes.Buffer
	if err := WriteFrame(&wire, request); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadFrame(&wire)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := decoded.(*UpdateGateRequest)
	if !ok || got.ManifestSHA256 != request.ManifestSHA256 || got.Path != request.Path || got.ExpectedStatus != 204 || got.ExpectedTarget == nil || *got.ExpectedTarget != target {
		t.Fatalf("decoded=%#v", decoded)
	}
}

func TestUpdateGateFrameRejectsUnsignedOrUnboundActions(t *testing.T) {
	target := updateGateTargetFixture()
	valid := UpdateGateRequest{Operation: UpdateGateCandidate, TransactionID: "transaction_01", Version: "2026.08.31.1", ManifestSHA256: strings.Repeat("a", 64), Path: "/canary", ExpectedStatus: 204, Samples: 3, TimeoutMillis: 1_000, ExpectedTarget: &target}
	mutations := []func(*UpdateGateRequest){
		func(v *UpdateGateRequest) { v.ManifestSHA256 = "" },
		func(v *UpdateGateRequest) { v.ExpectedTarget = nil },
		func(v *UpdateGateRequest) { v.Path = "https://attacker.test" },
		func(v *UpdateGateRequest) { v.ExpectedStatus = 302 },
	}
	for index, mutate := range mutations {
		candidate := valid
		copyTarget := target
		candidate.ExpectedTarget = &copyTarget
		mutate(&candidate)
		if _, err := Encode(candidate); err == nil {
			t.Fatalf("case %d accepted", index)
		}
	}
}

func TestUpdateGateCommitRequiresExactTargetAndNoProbeFields(t *testing.T) {
	target := updateGateTargetFixture()
	valid := UpdateGateRequest{
		Operation:      UpdateGateCommit,
		TransactionID:  "transaction_01",
		Version:        "2026.08.31.1",
		ManifestSHA256: strings.Repeat("a", 64),
		ExpectedTarget: &target,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid commit rejected: %v", err)
	}
	mutations := []func(*UpdateGateRequest){
		func(v *UpdateGateRequest) { v.ExpectedTarget = nil },
		func(v *UpdateGateRequest) { v.Path = "/canary" },
		func(v *UpdateGateRequest) { v.PreviousVersion = "2026.08.30.1" },
		func(v *UpdateGateRequest) { v.TimeoutMillis = 1_000 },
	}
	for index, mutate := range mutations {
		candidate := valid
		copyTarget := target
		candidate.ExpectedTarget = &copyTarget
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatalf("case %d accepted", index)
		}
	}
}

func TestUpdateGateStandaloneTargetRejectsFabricatedTunnelState(t *testing.T) {
	target := UpdateGateTargetBinding{Scope: UpdateGateScopeStandalone, MachineID: "machine_01", FailureDomain: "standalone"}
	if err := target.Validate(); err != nil {
		t.Fatalf("valid standalone target rejected: %v", err)
	}
	target.TunnelID = "tunnel_fake"
	if err := target.Validate(); err == nil {
		t.Fatal("standalone target accepted fabricated tunnel identity")
	}
}
