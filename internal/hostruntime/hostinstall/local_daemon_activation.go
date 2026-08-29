package hostinstall

import (
	"context"
)

type localDaemonActivation struct {
	Installed bool
	Start     func(context.Context) error
	Install   func(context.Context) error
	WaitReady func(context.Context) error
}

func activateLocalDaemon(ctx context.Context, activation localDaemonActivation) error {
	if ctx == nil || activation.Start == nil || activation.Install == nil || activation.WaitReady == nil {
		return ErrInvalidRequest
	}
	var err error
	if activation.Installed {
		err = activation.Start(ctx)
	} else {
		err = activation.Install(ctx)
	}
	if err != nil {
		return err
	}
	return activation.WaitReady(ctx)
}
