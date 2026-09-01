//go:build !linux

package environmentkey

import (
	"context"
	"io"
)

type ProvisionConfig struct {
	CiphertextPath string
	MachineID      string
	Generation     uint64
	Random         io.Reader
	Runner         CredentialRunner
}

type CredentialRunner interface {
	Run(context.Context, []string, []byte, int64) ([]byte, error)
}

type ExecCredentialRunner struct{}

func (ExecCredentialRunner) Run(context.Context, []string, []byte, int64) ([]byte, error) {
	return nil, ErrUnavailable
}

func EnsureSystemdCredential(context.Context, ProvisionConfig) (bool, error) {
	return false, ErrUnavailable
}
