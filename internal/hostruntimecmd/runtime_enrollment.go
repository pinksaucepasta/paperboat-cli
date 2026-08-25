package hostruntimecmd

import (
	"context"
	"errors"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/enrollment"
)

type runtimeEnrollmentAction uint8

const (
	runtimeEnrollmentReuse runtimeEnrollmentAction = iota + 1
	runtimeEnrollmentRenew
	runtimeEnrollmentEnroll
)

func planRuntimeEnrollment(current enrollment.RuntimeIdentity, loadErr error, renewable enrollment.RuntimeIdentity, renewalLoadErr error, material bootstrap.Material) (runtimeEnrollmentAction, error) {
	if loadErr == nil {
		if runtimeIdentityMatches(current, material) {
			if material.ReuseIdentity {
				return runtimeEnrollmentRenew, nil
			}
			return runtimeEnrollmentReuse, nil
		}
		if material.ReuseIdentity {
			return 0, errors.New("server attempted to reuse an unavailable or mismatched runtime identity")
		}
		return runtimeEnrollmentEnroll, nil
	}
	if renewalLoadErr == nil && runtimeIdentityMatches(renewable, material) {
		if material.ReuseIdentity {
			return runtimeEnrollmentRenew, nil
		}
		return runtimeEnrollmentEnroll, nil
	}
	if material.ReuseIdentity {
		return 0, errors.New("server attempted to reuse an unavailable or mismatched runtime identity")
	}
	return runtimeEnrollmentEnroll, nil
}

func runtimeIdentityMatches(current enrollment.RuntimeIdentity, material bootstrap.Material) bool {
	return current.HelperID == material.HelperID && current.EnvironmentID == material.EnvironmentID && current.MachineID == material.UserMachineID
}

// reconcileRuntimeEnrollment always revalidates local runtime identity state.
// RuntimeEnrolled records durable progress, not that the credential is still
// current, so a resumed bootstrap must not use it to skip renewal.
func reconcileRuntimeEnrollment(ctx context.Context, runtimeEnrolled bool, ensure func(context.Context) error, record func() error) error {
	if ensure == nil || record == nil {
		return errors.New("runtime enrollment reconciliation is invalid")
	}
	if err := ensure(ctx); err != nil {
		return err
	}
	if runtimeEnrolled {
		return nil
	}
	return record()
}

func prepareWindowsBootstrapRuntime(ctx context.Context, reuseIdentity, runtimeEnrolled bool, ensureRuntime func(context.Context) error, recordRuntime func() error, ensureMachineControl func(context.Context) error, fetchArtifact func(context.Context) (string, error)) (string, error) {
	if ensureMachineControl == nil || fetchArtifact == nil {
		return "", errors.New("Windows bootstrap runtime preparation is invalid")
	}
	artifactPath := ""
	if !reuseIdentity {
		var err error
		artifactPath, err = fetchArtifact(ctx)
		if err != nil {
			return "", err
		}
	}
	if err := reconcileRuntimeEnrollment(ctx, runtimeEnrolled, ensureRuntime, recordRuntime); err != nil {
		return "", err
	}
	if err := ensureMachineControl(ctx); err != nil {
		return "", err
	}
	if reuseIdentity {
		return fetchArtifact(ctx)
	}
	return artifactPath, nil
}
