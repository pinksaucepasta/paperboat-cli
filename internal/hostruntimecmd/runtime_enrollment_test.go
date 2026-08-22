package hostruntimecmd

import (
	"errors"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/enrollment"
)

func TestRuntimeEnrollmentReplacesOnlyStaleNonReusableIdentity(t *testing.T) {
	material := bootstrap.Material{UserMachineID: "machine-new", EnvironmentID: "environment-new", HelperID: "helper-new"}
	matching := enrollment.RuntimeIdentity{MachineID: material.UserMachineID, EnvironmentID: material.EnvironmentID, HelperID: material.HelperID}
	if required, err := runtimeEnrollmentRequired(matching, nil, material); err != nil || required {
		t.Fatalf("matching identity required=%v err=%v", required, err)
	}

	stale := enrollment.RuntimeIdentity{MachineID: "machine-old", EnvironmentID: "environment-old", HelperID: "helper-old"}
	if required, err := runtimeEnrollmentRequired(stale, nil, material); err != nil || !required {
		t.Fatalf("stale replaceable identity required=%v err=%v", required, err)
	}

	material.ReuseIdentity = true
	if required, err := runtimeEnrollmentRequired(stale, nil, material); required || err == nil {
		t.Fatalf("mismatched reusable identity required=%v err=%v", required, err)
	}
	if required, err := runtimeEnrollmentRequired(enrollment.RuntimeIdentity{}, errors.New("missing"), material); required || err == nil {
		t.Fatalf("missing reusable identity required=%v err=%v", required, err)
	}
}
