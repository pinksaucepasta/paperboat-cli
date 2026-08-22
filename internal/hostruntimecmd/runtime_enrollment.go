package hostruntimecmd

import (
	"errors"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/bootstrap"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/enrollment"
)

func runtimeEnrollmentRequired(current enrollment.RuntimeIdentity, loadErr error, material bootstrap.Material) (bool, error) {
	if loadErr == nil && current.HelperID == material.HelperID && current.EnvironmentID == material.EnvironmentID && current.MachineID == material.UserMachineID {
		return false, nil
	}
	if material.ReuseIdentity {
		return false, errors.New("server attempted to reuse an unavailable or mismatched runtime identity")
	}
	return true, nil
}
