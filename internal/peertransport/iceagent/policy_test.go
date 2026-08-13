package iceagent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pion/ice/v4"
)

func TestValidateSTUNURLsAllowsOnlySTUN(t *testing.T) {
	urls, err := ValidateSTUNURLs([]string{"stun:stun.example.test:3478", "stun:[2001:db8::1]:3478"})
	if err != nil || len(urls) != 2 {
		t.Fatalf("urls=%v err=%v", urls, err)
	}
}

func TestConnectReturnsWhenICEChecklistFails(t *testing.T) {
	agent, err := newAgentWithOptions(Config{LocalUfrag: "ufrag-123456789", LocalPwd: "password-123456789012345678901234"}, []ice.AgentOption{
		ice.WithDisconnectedTimeout(10 * time.Millisecond),
		ice.WithFailedTimeout(10 * time.Millisecond),
		ice.WithCheckInterval(time.Millisecond),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	_, err = agent.Connect(ctx, RoleControlling, "remote-ufrag", "remote-password-123456789012345678901234")
	if !errors.Is(err, ErrConnectionFailed) {
		t.Fatalf("err=%v, want ErrConnectionFailed", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("failed checklist remained blocked for %s", elapsed)
	}
}

func TestValidateSTUNURLsRejectsTURNAndTCP(t *testing.T) {
	for _, test := range []struct {
		name string
		url  string
		want error
	}{
		{name: "turn", url: "turn:relay.example.test:3478", want: ErrTURNNotAllowed},
		{name: "turns", url: "turns:relay.example.test:5349", want: ErrTURNNotAllowed},
		{name: "stuns", url: "stuns:stun.example.test:5349", want: ErrTCPNotAllowed},
		{name: "tcp", url: "stun:stun.example.test:3478?transport=tcp", want: ErrTCPNotAllowed},
		{name: "http", url: "https://stun.example.test", want: ErrInvalidSTUNURL},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ValidateSTUNURLs([]string{test.url})
			if !errors.Is(err, test.want) {
				t.Fatalf("err=%v, want %v", err, test.want)
			}
		})
	}
}

func TestNewDisablesTCPAndMDNS(t *testing.T) {
	agent, err := New(Config{STUNURLs: []string{"stun:stun.example.test:3478"}, LocalUfrag: "ufrag-123456789", LocalPwd: "password-123456789012345678901234"})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCandidatePolicyRejectsRelayAndTCP(t *testing.T) {
	for _, raw := range []string{
		"candidate:1 1 TCP 123 192.0.2.1 9 typ host tcptype passive",
		"candidate:1 1 UDP 123 192.0.2.1 3478 typ relay raddr 198.51.100.1 rport 3478",
	} {
		candidate, err := ice.UnmarshalCandidate(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateCandidate(candidate); err == nil {
			t.Fatalf("candidate accepted: %s", raw)
		}
	}
}

func TestAddRemoteCandidateRejectsForbiddenCandidateBeforePion(t *testing.T) {
	agent, err := New(Config{LocalUfrag: "ufrag-123456789", LocalPwd: "password-123456789012345678901234"})
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	if err := agent.AddRemoteCandidate("candidate:1 1 UDP 123 192.0.2.1 3478 typ relay raddr 198.51.100.1 rport 3478"); !errors.Is(err, ErrCandidateTypeNotAllowed) {
		t.Fatalf("err=%v", err)
	}
}

func TestConnectRejectsInvalidRoleAndCredentials(t *testing.T) {
	agent, err := New(Config{LocalUfrag: "ufrag-123456789", LocalPwd: "password-123456789012345678901234"})
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	if _, err := agent.Connect(context.Background(), Role(99), "remote", "password"); err == nil {
		t.Fatal("invalid role accepted")
	}
	if _, err := agent.Connect(context.Background(), RoleControlling, "", ""); err == nil {
		t.Fatal("empty credentials accepted")
	}
}
