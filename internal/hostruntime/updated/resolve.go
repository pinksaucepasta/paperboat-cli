package updated

import (
	"context"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/workerupdate"
)

// resolveRelease verifies signed release metadata without staging or
// activating anything. Both platform control services use this for `pb update
// check`; activation is reserved for the explicit update operation or the
// automatic scheduler.
func resolveRelease(ctx context.Context, activeVersion string, resolve workerupdate.Resolver) (workerupdate.Result, error) {
	if resolve == nil {
		return workerupdate.Result{}, workerupdate.ErrInvalidRelease
	}
	release, found, err := resolve(ctx)
	if err != nil || !found {
		return workerupdate.Result{Version: activeVersion}, err
	}
	return workerupdate.Result{Version: release.Version}, nil
}
