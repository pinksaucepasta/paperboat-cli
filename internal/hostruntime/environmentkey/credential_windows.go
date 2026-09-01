//go:build windows

package environmentkey

import "context"

type SystemdCredentialSource struct {
	Generation uint64
	MachineID  string
}

func (SystemdCredentialSource) Load(context.Context) (Material, error) {
	return Material{}, ErrUnavailable
}
