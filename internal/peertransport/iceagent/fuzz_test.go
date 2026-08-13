package iceagent

import (
	"net"
	"testing"

	"github.com/pion/ice/v4"
)

func FuzzValidateCandidateString(f *testing.F) {
	f.Add("candidate:1 1 UDP 2130706431 192.0.2.1 5000 typ host")
	f.Add("candidate:2 1 TCP 1 192.0.2.1 9 typ host tcptype passive")
	f.Add("candidate:3 1 UDP 1 host.local 9999 typ host")
	f.Add("")

	f.Fuzz(func(t *testing.T, raw string) {
		if err := ValidateCandidateString(raw); err != nil {
			return
		}
		if len(raw) == 0 || len(raw) > MaximumCandidateBytes {
			t.Fatal("accepted candidate violates wire length bound")
		}
		candidate, err := ice.UnmarshalCandidate(raw)
		if err != nil || candidate == nil {
			t.Fatalf("accepted candidate cannot be parsed: %v", err)
		}
		if err := ValidateCandidate(candidate); err != nil {
			t.Fatalf("accepted candidate violates policy: %v", err)
		}
		if candidate.NetworkType() != ice.NetworkTypeUDP4 && candidate.NetworkType() != ice.NetworkTypeUDP6 {
			t.Fatalf("accepted network type=%s", candidate.NetworkType())
		}
		if candidate.Type() != ice.CandidateTypeHost && candidate.Type() != ice.CandidateTypeServerReflexive && candidate.Type() != ice.CandidateTypePeerReflexive {
			t.Fatalf("accepted candidate type=%s", candidate.Type())
		}
		if net.ParseIP(candidate.Address()) == nil {
			t.Fatalf("accepted non-IP candidate address=%q", candidate.Address())
		}
		if normalized := candidate.Marshal(); ValidateCandidateString(normalized) != nil {
			t.Fatalf("normalized accepted candidate was rejected: %q", normalized)
		}
	})
}
