//go:build windows

package diagnostics

import (
	"path/filepath"
	"time"
)

const (
	BundleSchemaV1     = "paperboat.diagnostic-bundle/v1"
	MaximumBundleBytes = 25 << 20
)

// Bundle is kept available on Windows so the shared bugreport and local API
// contracts remain type-safe. Windows local-diagnostics persistence is not
// wired into the current service entry yet; callers must receive a concrete
// unsupported error rather than a fabricated archive.
type Bundle struct {
	Schema      string    `json:"schema"`
	Correlation string    `json:"correlation"`
	CreatedAt   time.Time `json:"created_at"`
	Path        string    `json:"path"`
	Bytes       int64     `json:"bytes"`
	Categories  []string  `json:"categories"`
}

func (b Bundle) Validate() error {
	if b.Schema != BundleSchemaV1 || len(b.Correlation) != 35 || b.Correlation[:3] != "pb-" || !safeBundleHex(b.Correlation[3:]) || b.CreatedAt.IsZero() || b.CreatedAt.Location() != time.UTC || !filepath.IsAbs(b.Path) || filepath.Clean(b.Path) != b.Path || b.Bytes <= 0 || b.Bytes > MaximumBundleBytes || len(b.Categories) != 4 {
		return ErrInvalid
	}
	want := [...]string{"manifest", "recent_events", "redacted_events", "status"}
	for index, category := range want {
		if b.Categories[index] != category {
			return ErrInvalid
		}
	}
	return nil
}

func safeBundleHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
