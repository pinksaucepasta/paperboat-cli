package doctor

import (
	"context"
	"testing"
	"time"
)

func TestRunIsConcurrentBoundedAndDeterministic(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	started := make(chan string, 3)
	release := make(chan struct{})
	probe := func(code, status string) Probe {
		return Probe{Code: code, Run: func(ctx context.Context) Check {
			started <- code
			select {
			case <-release:
			case <-ctx.Done():
			}
			check := Check{Category: "network", Code: code, Status: status, Summary: "Safe result."}
			if status == StatusWarning {
				check.Recovery = "Retry on another network."
			}
			return check
		}}
	}
	done := make(chan Report, 1)
	go func() {
		report, _ := Run(context.Background(), Config{Timeout: time.Second, ProbeTimeout: time.Second, Clock: func() time.Time { return now }, Correlation: func() (string, error) { return "pb-doctor-0123456789abcdef", nil }}, &Machine{ID: "machine_1", Alias: "Studio"}, []Probe{probe("z_check", StatusPass), probe("a_check", StatusWarning), probe("m_check", StatusPass)})
		done <- report
	}()
	for range 3 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("probes did not start concurrently")
		}
	}
	close(release)
	report := <-done
	if report.Overall != "degraded" || report.Checks[0].Code != "a_check" || report.Checks[1].Code != "m_check" || report.Checks[2].Code != "z_check" {
		t.Fatalf("report=%#v", report)
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRunConvertsDeadlineAndInvalidIdentityToSafeResults(t *testing.T) {
	report, err := Run(context.Background(), Config{Timeout: 100 * time.Millisecond, ProbeTimeout: 10 * time.Millisecond, Clock: time.Now, Correlation: func() (string, error) { return "pb-doctor-fedcba9876543210", nil }}, nil, []Probe{
		{Code: "slow_check", Run: func(ctx context.Context) Check { <-ctx.Done(); return Check{} }},
		{Code: "identity_check", Run: func(context.Context) Check {
			return Check{Category: "local", Code: "wrong", Status: StatusPass, Summary: "Unsafe."}
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Overall != "unhealthy" || report.Checks[0].Code != "identity_check" || report.Checks[0].Status != StatusFail || report.Checks[1].Status != StatusUnavailable {
		t.Fatalf("report=%#v", report)
	}
}

func TestValidationRejectsDuplicateAndUnsafeChecks(t *testing.T) {
	if _, err := normalize([]Check{{Category: "network", Code: "same", Status: StatusPass, Summary: "One."}, {Category: "network", Code: "same", Status: StatusPass, Summary: "Two."}}); err == nil {
		t.Fatal("duplicate checks accepted")
	}
	if err := (Check{Category: "network", Code: "bad", Status: StatusFail, Summary: "token\nsecret", Recovery: "Retry."}).Validate(); err == nil {
		t.Fatal("multiline summary accepted")
	}
}
