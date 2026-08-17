package managedssh

import (
	"errors"
	"testing"
)

func TestAliasHostRoundTrip(t *testing.T) {
	host, err := AliasHost("Build-01", "PPRBT")
	if err != nil || host != "build-01.pprbt" {
		t.Fatalf("AliasHost() = %q, %v", host, err)
	}
	alias, err := ParseAliasHost(host, "pprbt")
	if err != nil || alias != "build-01" {
		t.Fatalf("ParseAliasHost() = %q, %v", alias, err)
	}
}

func TestParseMachineTarget(t *testing.T) {
	for input, want := range map[string][2]string{
		"build-01":        {"build-01", ""},
		"root@build-01":   {"build-01", "root"},
		"Deploy@BUILD-01": {"BUILD-01", "Deploy"},
		"root@machine_01": {"machine_01", "root"},
	} {
		alias, username, err := ParseMachineTarget(input)
		if err != nil || alias != want[0] || username != want[1] {
			t.Fatalf("ParseMachineTarget(%q) = %q, %q, %v", input, alias, username, err)
		}
	}
	for _, input := range []string{"", "@build", "root@", "root@user@build", "-root@build", "root@bad\nmachine"} {
		if _, _, err := ParseMachineTarget(input); err == nil {
			t.Fatalf("ParseMachineTarget(%q) succeeded", input)
		}
	}
}

func TestAliasHostRejectsNonCanonicalDestinations(t *testing.T) {
	for _, host := range []string{"pprbt", "a.b.pprbt", "-bad.pprbt", "bad-.pprbt", "machine.pprbt.dev", "bad.other.dev", "127.0.0.1"} {
		if _, err := ParseAliasHost(host, "pprbt"); !errors.Is(err, ErrSSHAliasInvalid) {
			t.Fatalf("ParseAliasHost(%q) error = %v", host, err)
		}
	}
	for _, alias := range []string{"", "-bad", "bad-", "bad.name", "bad/name"} {
		if _, err := AliasHost(alias, "pprbt"); !errors.Is(err, ErrSSHAliasInvalid) {
			t.Fatalf("AliasHost(%q) error = %v", alias, err)
		}
	}
}

func TestResolveUsernamePrecedence(t *testing.T) {
	tests := []struct {
		name          string
		requested     string
		openSSH       string
		registered    string
		local         string
		hasRegistered bool
		want          string
	}{
		{name: "requested", requested: "deploy", openSSH: "deploy", registered: "hosted", local: "local", hasRegistered: true, want: "deploy"},
		{name: "openssh", openSSH: "configured", registered: "hosted", local: "local", hasRegistered: true, want: "configured"},
		{name: "registered", registered: "hosted", local: "local", hasRegistered: true, want: "hosted"},
		{name: "local only without registered user", local: "local", want: "local"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ResolveUsername(test.requested, test.openSSH, test.registered, test.local, test.hasRegistered)
			if err != nil || got != test.want {
				t.Fatalf("ResolveUsername() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestResolveUsernameRejectsConflictAndUnsafeValues(t *testing.T) {
	if _, err := ResolveUsername("root", "deploy", "", "", false); !errors.Is(err, ErrSSHUsernameConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	if _, err := ResolveUsername("", "", "", "local", true); !errors.Is(err, ErrSSHUsernameMissing) {
		t.Fatalf("registered-user absence error = %v", err)
	}
	for _, value := range []string{"-oProxyCommand=x", "user@host", "bad user", "bad\nuser", ""} {
		_, err := ResolveUsername(value, "", "", "", false)
		if value == "" {
			if !errors.Is(err, ErrSSHUsernameMissing) {
				t.Fatalf("ResolveUsername(%q) error = %v", value, err)
			}
		} else if !errors.Is(err, ErrSSHUsernameInvalid) {
			t.Fatalf("ResolveUsername(%q) error = %v", value, err)
		}
	}
}

func TestResolveDestinationFencesPort(t *testing.T) {
	input := DestinationInput{Alias: "build", AliasSuffix: "pprbt", RegisteredPort: 2222, RequestedPort: 2222, RegisteredUser: "deploy", HasRegisteredUser: true}
	got, err := ResolveDestination(input)
	if err != nil || got.Host != "build.pprbt" || got.Port != 2222 || got.User != "deploy" {
		t.Fatalf("ResolveDestination() = %#v, %v", got, err)
	}
	input.RequestedPort = 22
	if _, err := ResolveDestination(input); !errors.Is(err, ErrSSHPortConflict) {
		t.Fatalf("port conflict error = %v", err)
	}
	if _, err := ValidateDestinationPort("2222", 2222); err != nil {
		t.Fatalf("ValidateDestinationPort() error = %v", err)
	}
	if _, err := ValidateDestinationPort("22", 2222); !errors.Is(err, ErrSSHPortConflict) {
		t.Fatalf("ValidateDestinationPort conflict error = %v", err)
	}
}
