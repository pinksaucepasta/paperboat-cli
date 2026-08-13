package clientauthority

import (
	"context"
	"crypto/ed25519"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/config"
)

type cacheKey struct {
	account, client, machine string
	generation               uint64
}

// Cache retains endpoint authority metadata for the daemon lifetime. It never
// owns a carrier; machine-specific transport state is created only by an
// active consumer.
type Cache struct {
	mu      sync.Mutex
	entries map[cacheKey]Authority
}

func NewCache() *Cache { return &Cache{entries: make(map[cacheKey]Authority)} }

func (c *Cache) Resolve(ctx context.Context, request Request) (Authority, error) {
	if c == nil {
		return Resolve(ctx, request)
	}
	key := cacheKey{account: request.AccountID, client: request.CLIClientSessionID, machine: request.MachineID, generation: request.MachineGeneration}
	now := request.Now.UTC()
	c.mu.Lock()
	if cached, ok := c.entries[key]; ok && cached.MachineCertificate.Claims.ExpiresAt.After(now.Add(time.Second)) {
		clone := cloneAuthority(cached)
		c.mu.Unlock()
		return clone, nil
	}
	c.mu.Unlock()
	resolved, err := Resolve(ctx, request)
	if err != nil {
		return Authority{}, err
	}
	c.mu.Lock()
	if previous, ok := c.entries[key]; ok {
		previous.Clear()
	}
	c.entries[key] = cloneAuthority(resolved)
	c.mu.Unlock()
	return resolved, nil
}

func (c *Cache) InvalidateMachine(machineID string) {
	if c == nil || machineID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, authority := range c.entries {
		if key.machine == machineID {
			authority.Clear()
			delete(c.entries, key)
		}
	}
}

func (c *Cache) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, authority := range c.entries {
		authority.Clear()
		delete(c.entries, key)
	}
}

func cloneAuthority(value Authority) Authority {
	return Authority{
		RootPublic:            append(ed25519.PublicKey(nil), value.RootPublic...),
		LocalKeys:             cloneKeys(value.LocalKeys),
		LocalCertificate:      value.LocalCertificate,
		LocalCertificateRaw:   append([]byte(nil), value.LocalCertificateRaw...),
		MachineCertificate:    value.MachineCertificate,
		MachineCertificateRaw: append([]byte(nil), value.MachineCertificateRaw...),
	}
}

func cloneKeys(value config.PeerIdentityKeys) config.PeerIdentityKeys {
	value.RootPrivate = append([]byte(nil), value.RootPrivate...)
	value.QUICPrivate = append([]byte(nil), value.QUICPrivate...)
	return value
}
