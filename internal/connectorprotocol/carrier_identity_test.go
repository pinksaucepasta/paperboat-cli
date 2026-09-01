package connectorprotocol

import (
	"errors"
	"net/url"
	"testing"
)

func TestCarrierIdentityURNBindsEverySessionDimension(t *testing.T) {
	binding := CarrierIdentityBinding{
		AccountID: "account_1", HostID: "host_1", TunnelID: "tunnel_1",
		ConnectorID: "connector_1", SessionID: "session_1",
		ProcessGeneration: 7, ConfigGeneration: 3, EdgeProcessEpoch: "edge_epoch_1",
	}
	uri, err := CarrierIdentityURN(binding)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := uri.String(), "urn:paperboat:connector-v1:carrier:pO5EmR605mPtJSr_1M4fWhtrxYAyrLEd_WCU6Y0mvqY"; got != want {
		t.Fatalf("carrier identity URN = %q, want %q", got, want)
	}
	if err := MatchCarrierIdentityURN([]*url.URL{uri}, binding); err != nil {
		t.Fatalf("exact identity did not match: %v", err)
	}
	changes := []func(*CarrierIdentityBinding){
		func(value *CarrierIdentityBinding) { value.AccountID = "account_2" },
		func(value *CarrierIdentityBinding) { value.HostID = "host_2" },
		func(value *CarrierIdentityBinding) { value.TunnelID = "tunnel_2" },
		func(value *CarrierIdentityBinding) { value.ConnectorID = "connector_2" },
		func(value *CarrierIdentityBinding) { value.SessionID = "session_2" },
		func(value *CarrierIdentityBinding) { value.ProcessGeneration++ },
		func(value *CarrierIdentityBinding) { value.ConfigGeneration++ },
		func(value *CarrierIdentityBinding) { value.EdgeProcessEpoch = "edge_epoch_2" },
	}
	for index, change := range changes {
		changed := binding
		change(&changed)
		if err := MatchCarrierIdentityURN([]*url.URL{uri}, changed); !errors.Is(err, ErrCarrierIdentityBinding) {
			t.Fatalf("change %d matched stale identity: %v", index, err)
		}
	}
}

func TestCarrierIdentityURNRejectsAmbiguousOrInvalidCertificates(t *testing.T) {
	binding := CarrierIdentityBinding{AccountID: "account_1", HostID: "host_1", TunnelID: "tunnel_1", ConnectorID: "connector_1", SessionID: "session_1", ProcessGeneration: 1, ConfigGeneration: 1, EdgeProcessEpoch: "edge_epoch_1"}
	uri, err := CarrierIdentityURN(binding)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := url.Parse("urn:paperboat:connector-v1:carrier:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	for _, uris := range [][]*url.URL{nil, {uri, uri}, {other}, {nil}} {
		if err := MatchCarrierIdentityURN(uris, binding); !errors.Is(err, ErrCarrierIdentityBinding) {
			t.Fatalf("URIs %#v error = %v", uris, err)
		}
	}
	invalid := binding
	invalid.ProcessGeneration = 0
	if _, err := CarrierIdentityURN(invalid); !errors.Is(err, ErrCarrierIdentityBinding) {
		t.Fatalf("invalid binding error = %v", err)
	}
}

func TestValidateOpaqueEpochAcceptsRawBase64URLPrefixes(t *testing.T) {
	for _, value := range []string{"_bcdefgh", "-bcdefgh", "Abcdefgh0123_-"} {
		if err := ValidateOpaqueEpoch(value); err != nil {
			t.Fatalf("valid opaque epoch %q: %v", value, err)
		}
	}
	for _, value := range []string{"short", " epoch_1", "epoch.123", "epoch:123", "epoch/123"} {
		if err := ValidateOpaqueEpoch(value); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid opaque epoch %q error = %v", value, err)
		}
	}
}
