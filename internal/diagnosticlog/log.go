// Package diagnosticlog provides best-effort structured diagnostics that never
// block the operation being observed.
package diagnosticlog

import (
	"log/slog"
	"sync"
)

const queueDepth = 256

type record struct {
	message string
	args    []any
}

var (
	start sync.Once
	queue = make(chan record, queueDepth)
)

// TryInfo enqueues one record without waiting for the logging backend.
func TryInfo(message string, args ...any) {
	start.Do(func() {
		go func() {
			for item := range queue {
				slog.Info(item.message, item.args...)
			}
		}()
	})
	item := record{message: message, args: append([]any(nil), args...)}
	select {
	case queue <- item:
	default:
	}
}
