//go:build !darwin && !linux

package managedssh

import (
	"context"
	"time"
)

func ProbeAgentIdentity(context.Context, string, [32]byte, time.Duration) error {
	return ErrAgentDenied
}
