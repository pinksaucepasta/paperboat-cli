package networkcheck

import (
	"errors"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/networkadaptation"
)

const maximumReports = 256

type Cache struct {
	mu      sync.Mutex
	reports map[networkadaptation.Fingerprint]Report
}

func NewCache() *Cache {
	return &Cache{reports: make(map[networkadaptation.Fingerprint]Report)}
}

func (c *Cache) Store(fingerprint networkadaptation.Fingerprint, report Report, now time.Time) error {
	if c == nil || !fingerprint.Valid() || report.Validate() != nil || now.IsZero() || report.ExpiresAt.Before(now) {
		return errors.New("invalid network check cache entry")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)
	if _, exists := c.reports[fingerprint]; !exists && len(c.reports) >= maximumReports {
		var oldest networkadaptation.Fingerprint
		var oldestAt time.Time
		for key, current := range c.reports {
			if oldestAt.IsZero() || current.ObservedAt.Before(oldestAt) {
				oldest, oldestAt = key, current.ObservedAt
			}
		}
		delete(c.reports, oldest)
	}
	c.reports[fingerprint] = report
	return nil
}

func (c *Cache) Load(fingerprint networkadaptation.Fingerprint, now time.Time) (Report, bool) {
	if c == nil || !fingerprint.Valid() || now.IsZero() {
		return Report{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(now)
	report, found := c.reports[fingerprint]
	return report, found
}

func (c *Cache) Invalidate() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	count := len(c.reports)
	c.reports = make(map[networkadaptation.Fingerprint]Report)
	c.mu.Unlock()
	return count
}

func (c *Cache) expireLocked(now time.Time) {
	for key, report := range c.reports {
		if !report.ExpiresAt.After(now) {
			delete(c.reports, key)
		}
	}
}
