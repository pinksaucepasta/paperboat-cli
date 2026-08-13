package clientauthority

import (
	"crypto/ed25519"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/config"
)

func TestCacheCloneAndTargetedInvalidation(t *testing.T) {
	cache := NewCache()
	authority := Authority{RootPublic: ed25519.PublicKey{1}, LocalKeys: config.PeerIdentityKeys{RootPrivate: ed25519.PrivateKey{2}, QUICPrivate: ed25519.PrivateKey{3}}, LocalCertificateRaw: []byte{4}, MachineCertificateRaw: []byte{5}}
	firstKey := cacheKey{account: "account", client: "client", machine: "machine_1", generation: 1}
	secondKey := cacheKey{account: "account", client: "client", machine: "machine_2", generation: 1}
	cache.entries[firstKey] = cloneAuthority(authority)
	cache.entries[secondKey] = cloneAuthority(authority)
	copy := cloneAuthority(cache.entries[firstKey])
	copy.RootPublic[0] = 9
	if cache.entries[firstKey].RootPublic[0] != 1 {
		t.Fatal("authority clone shared key storage")
	}
	cache.InvalidateMachine("machine_1")
	if _, ok := cache.entries[firstKey]; ok {
		t.Fatal("target machine authority remained cached")
	}
	if _, ok := cache.entries[secondKey]; !ok {
		t.Fatal("unrelated machine authority was invalidated")
	}
	cache.Close()
	if len(cache.entries) != 0 {
		t.Fatal("cache close retained authority")
	}
}
