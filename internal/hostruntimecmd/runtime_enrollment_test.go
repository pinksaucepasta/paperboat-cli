package hostruntimecmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/enrollment"
)

func TestPlanRuntimeEnrollment(t *testing.T) {
	material := bootstrap.Material{UserMachineID: "machine-new", EnvironmentID: "environment-new", HelperID: "helper-new"}
	matching := enrollment.RuntimeIdentity{MachineID: material.UserMachineID, EnvironmentID: material.EnvironmentID, HelperID: material.HelperID}
	mismatched := enrollment.RuntimeIdentity{MachineID: "machine-old", EnvironmentID: "environment-old", HelperID: "helper-old"}
	expired := errors.New("expired")

	tests := []struct {
		name           string
		current        enrollment.RuntimeIdentity
		loadErr        error
		renewable      enrollment.RuntimeIdentity
		renewalLoadErr error
		reuse          bool
		want           runtimeEnrollmentAction
		wantErr        bool
	}{
		{name: "matching valid identity is reused", current: matching, renewable: matching, want: runtimeEnrollmentReuse},
		{name: "matching valid reusable identity uses renewing source safety window", current: matching, renewable: matching, reuse: true, want: runtimeEnrollmentRenew},
		{name: "matching expired reusable identity is renewed", loadErr: expired, renewable: matching, reuse: true, want: runtimeEnrollmentRenew},
		{name: "matching expired identity with fresh enrollment material is enrolled", loadErr: expired, renewable: matching, want: runtimeEnrollmentEnroll},
		{name: "mismatched reusable identity is rejected", current: mismatched, renewable: mismatched, reuse: true, wantErr: true},
		{name: "expired mismatched reusable identity is rejected", loadErr: expired, renewable: mismatched, reuse: true, wantErr: true},
		{name: "expired mismatched identity with fresh enrollment material is enrolled", loadErr: expired, renewable: mismatched, want: runtimeEnrollmentEnroll},
		{name: "missing reusable identity is rejected", loadErr: errors.New("missing"), renewalLoadErr: errors.New("missing"), reuse: true, wantErr: true},
		{name: "missing identity with fresh enrollment material is enrolled", loadErr: errors.New("missing"), renewalLoadErr: errors.New("missing"), want: runtimeEnrollmentEnroll},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := material
			candidate.ReuseIdentity = test.reuse
			got, err := planRuntimeEnrollment(test.current, test.loadErr, test.renewable, test.renewalLoadErr, candidate)
			if test.wantErr {
				if err == nil {
					t.Fatalf("action=%v without error", got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("action=%v err=%v want=%v", got, err, test.want)
			}
		})
	}
}

func TestPrepareWindowsBootstrapRuntimeRenewsCompletedResumeBeforeArtifact(t *testing.T) {
	material := bootstrap.Material{UserMachineID: "machine-new", EnvironmentID: "environment-new", HelperID: "helper-new", ReuseIdentity: true}
	expiredIdentity := enrollment.RuntimeIdentity{MachineID: material.UserMachineID, EnvironmentID: material.EnvironmentID, HelperID: material.HelperID}
	events := make([]string, 0, 3)
	metadataErr := errors.New("timestamp metadata is expired")
	path, err := prepareWindowsBootstrapRuntime(context.Background(), true, true, func(context.Context) error {
		action, err := planRuntimeEnrollment(enrollment.RuntimeIdentity{}, errors.New("expired"), expiredIdentity, nil, material)
		if err != nil {
			return err
		}
		if action != runtimeEnrollmentRenew {
			return errors.New("expired identity was not renewed")
		}
		events = append(events, "renew")
		return nil
	}, func() error {
		events = append(events, "record")
		return nil
	}, func(context.Context) error {
		events = append(events, "machine-control")
		return nil
	}, func(context.Context) (string, error) {
		events = append(events, "artifact")
		return "", metadataErr
	})
	if !errors.Is(err, metadataErr) || path != "" {
		t.Fatalf("path=%q err=%v", path, err)
	}
	if got := strings.Join(events, ","); got != "renew,machine-control,artifact" {
		t.Fatalf("events=%q", got)
	}
}

func TestPrepareWindowsBootstrapRuntimeVerifiesArtifactBeforeFreshEnrollment(t *testing.T) {
	events := make([]string, 0, 4)
	path, err := prepareWindowsBootstrapRuntime(context.Background(), false, false, func(context.Context) error {
		events = append(events, "enroll")
		return nil
	}, func() error {
		events = append(events, "record")
		return nil
	}, func(context.Context) error {
		events = append(events, "machine-control")
		return nil
	}, func(context.Context) (string, error) {
		events = append(events, "artifact")
		return "verified-artifact", nil
	})
	if err != nil || path != "verified-artifact" {
		t.Fatalf("path=%q err=%v", path, err)
	}
	if got := strings.Join(events, ","); got != "artifact,enroll,record,machine-control" {
		t.Fatalf("events=%q", got)
	}
}

func TestPrepareWindowsBootstrapRuntimeDoesNotEnrollWhenFreshArtifactFails(t *testing.T) {
	events := make([]string, 0, 1)
	artifactErr := errors.New("artifact verification failed")
	_, err := prepareWindowsBootstrapRuntime(context.Background(), false, false, func(context.Context) error {
		events = append(events, "enroll")
		return nil
	}, func() error {
		events = append(events, "record")
		return nil
	}, func(context.Context) error {
		events = append(events, "machine-control")
		return nil
	}, func(context.Context) (string, error) {
		events = append(events, "artifact")
		return "", artifactErr
	})
	if !errors.Is(err, artifactErr) {
		t.Fatalf("err=%v", err)
	}
	if got := strings.Join(events, ","); got != "artifact" {
		t.Fatalf("events=%q", got)
	}
}

func TestReconcileRuntimeEnrollmentRecordsFirstCompletion(t *testing.T) {
	ensureCalls := 0
	recordCalls := 0
	err := reconcileRuntimeEnrollment(context.Background(), false, func(context.Context) error {
		ensureCalls++
		return nil
	}, func() error {
		recordCalls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if ensureCalls != 1 || recordCalls != 1 {
		t.Fatalf("ensure calls=%d record calls=%d", ensureCalls, recordCalls)
	}
}
