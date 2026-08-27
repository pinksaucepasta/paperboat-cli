package updated

import "errors"

// ErrUnavailable means the local updater control endpoint could not be
// reached. Callers may use the signed direct update path only for this
// transport-level failure; updater-declared validation or activation errors
// must remain authoritative.
var ErrUnavailable = errors.New("paperboat updater is unavailable")
