package windowsopenssh

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFirewallOwnershipPlanOnlyClaimsNewOpenSSHPublicInboundRule(t *testing.T) {
	admin := FirewallRule{Name: "Admin-OpenSSH", DisplayName: "OpenSSH SSH Server", Direction: "Inbound", Action: "Allow", Enabled: true, Profiles: "Public", Program: `C:\Windows\System32\OpenSSH\sshd.exe`}
	created := FirewallRule{Name: "OpenSSH-Server-In-TCP", DisplayName: "OpenSSH SSH Server", Direction: "Inbound", Action: "Allow", Enabled: true, Profiles: "Public", Program: `C:\Program Files\OpenSSH\sshd.exe`}
	unsafe := FirewallRule{Name: "Other-Server", Direction: "Inbound", Action: "Allow", Enabled: true, Profiles: "Public", Program: `C:\Program Files\Other\server.exe`}
	before := FirewallSnapshot{CapturedAt: time.Now().UTC(), OpenSSHInbound: []FirewallRule{admin}}
	after := FirewallSnapshot{CapturedAt: time.Now().UTC(), OpenSSHInbound: []FirewallRule{admin, created, unsafe}}
	owned := firewallOwnershipPlan(before, after)
	if len(owned) != 1 || owned[0].Rule.Name != created.Name {
		t.Fatalf("owned=%+v", owned)
	}
}

func TestFirewallOwnershipPlanNeverClaimsRulesWhenSystemSSHDPredatesWinGet(t *testing.T) {
	rule := FirewallRule{Name: "OpenSSH-Server-In-TCP", DisplayName: "OpenSSH SSH Server", Direction: "Inbound", Action: "Allow", Enabled: true, Profiles: "Public", Program: `C:\Program Files\OpenSSH\sshd.exe`}
	owned := firewallOwnershipPlan(FirewallSnapshot{CapturedAt: time.Now().UTC(), SystemSSHD: true}, FirewallSnapshot{CapturedAt: time.Now().UTC(), SystemSSHD: true, OpenSSHInbound: []FirewallRule{rule}})
	if len(owned) != 0 {
		t.Fatalf("system sshd ownership plan = %+v", owned)
	}
}

func TestFirewallStateRoundTripRejectsUnsafeOwnership(t *testing.T) {
	config := Config{Platform: "windows", InstallRoot: filepath.Join(t.TempDir(), "OpenSSH"), StateRoot: filepath.Join(t.TempDir(), "state"), ApprovedVersion: ApprovedVersion, ExpectedPublisher: "Microsoft", Port: 38222, Runner: &fakeRunner{}}
	rule := FirewallRule{Name: "OpenSSH-Server-In-TCP", DisplayName: "OpenSSH SSH Server", Direction: "Inbound", Action: "Allow", Enabled: true, Profiles: "Public", Program: `C:\Program Files\OpenSSH\sshd.exe`}
	state := FirewallState{Schema: firewallStateSchema, Before: FirewallSnapshot{CapturedAt: time.Now().UTC()}, After: FirewallSnapshot{CapturedAt: time.Now().UTC(), OpenSSHInbound: []FirewallRule{rule}}, Owned: []OwnedFirewallRule{{Rule: rule}}}
	if err := writeFirewallState(config, state); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := readFirewallState(config)
	if err != nil || !exists || len(loaded.Owned) != 1 {
		t.Fatalf("state=%+v exists=%t err=%v", loaded, exists, err)
	}
	loaded.Owned[0].Rule.Program = `C:\Other\server.exe`
	if err := validateFirewallState(loaded); err == nil {
		t.Fatal("unsafe firewall ownership was accepted")
	}
}

func TestPaperboatEndpointFirewallRuleMatchesOnlyEnabledInboundEndpoint(t *testing.T) {
	base := FirewallRule{Name: "Paperboat", Direction: "Inbound", Action: "Allow", Enabled: true, LocalPort: "22,38222"}
	if !paperboatEndpointFirewallRule(base, 38222) {
		t.Fatal("Paperboat endpoint port was not detected")
	}
	base.LocalPort = "Any"
	base.Service = ServiceName
	if !paperboatEndpointFirewallRule(base, 38222) {
		t.Fatal("Paperboat service rule was not detected")
	}
	for _, mutate := range []func(*FirewallRule){func(r *FirewallRule) { r.Enabled = false }, func(r *FirewallRule) { r.Direction = "Outbound" }, func(r *FirewallRule) { r.Action = "Block" }} {
		candidate := base
		mutate(&candidate)
		if paperboatEndpointFirewallRule(candidate, 38222) {
			t.Fatalf("non-exposing rule was rejected: %+v", candidate)
		}
	}
}
