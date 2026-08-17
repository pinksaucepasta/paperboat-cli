package workerupdate

import (
	"context"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/autoupdate"
)

// MandatoryScheduler creates the only supported background scheduler for an
// ordinary runtime update. Its callback enters Manager.Check, which stages and
// cuts over a fenced worker; it has no path to the legacy restart updater.
func (m *Manager) MandatoryScheduler(resolve Resolver, observe func(autoupdate.Observation)) (*autoupdate.Scheduler, error) {
	if resolve == nil {
		return nil, ErrInvalidConfig
	}
	return autoupdate.New(autoupdate.Config{
		Check: func(ctx context.Context) (autoupdate.Result, error) {
			result, err := m.Check(ctx, resolve)
			return autoupdate.Result{Version: result.Version, Updated: result.Updated}, err
		},
		Observe: observe,
	})
}
