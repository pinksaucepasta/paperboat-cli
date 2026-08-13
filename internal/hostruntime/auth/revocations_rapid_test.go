package auth

import (
	"sync/atomic"
	"testing"

	"pgregory.net/rapid"
)

func TestRevocationCacheRapidStateMachine(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		operations := rapid.SliceOfN(rapid.Uint8(), 1, 256).Draw(t, "operations")
		cache := NewRevocationCache()
		type watched struct {
			jti     string
			flag    *atomic.Bool
			signal  <-chan struct{}
			release func()
			revoked bool
		}
		var watchers []*watched
		current := make(map[string]bool)
		jtis := []string{"jti_0", "jti_1", "jti_2", "jti_3"}
		for _, operation := range operations {
			switch operation % 3 {
			case 0:
				next := make(map[string]bool)
				var snapshot []string
				for index, jti := range jtis {
					if operation&(1<<uint(index+2)) != 0 {
						next[jti] = true
						snapshot = append(snapshot, jti)
					}
				}
				if err := cache.Replace(snapshot); err != nil {
					t.Fatal(err)
				}
				current = next
				for _, watcher := range watchers {
					watcher.revoked = watcher.revoked || current[watcher.jti]
				}
			case 1:
				jti := jtis[int(operation/3)%len(jtis)]
				flag, signal, release, err := cache.Watch(jti)
				if err != nil {
					t.Fatal(err)
				}
				watchers = append(watchers, &watched{jti: jti, flag: flag, signal: signal, release: release, revoked: current[jti]})
			case 2:
				if len(watchers) > 0 {
					index := int(operation/3) % len(watchers)
					watchers[index].release()
					watchers[index].release()
					watchers = append(watchers[:index], watchers[index+1:]...)
				}
			}
			for _, jti := range jtis {
				if got := cache.Revoked(Claims{JTI: jti}); got != current[jti] {
					t.Fatalf("jti=%q revoked=%v want=%v", jti, got, current[jti])
				}
			}
			for _, watcher := range watchers {
				if watcher.flag.Load() != watcher.revoked {
					t.Fatalf("watcher jti=%q flag=%v want=%v", watcher.jti, watcher.flag.Load(), watcher.revoked)
				}
				select {
				case <-watcher.signal:
					if !watcher.revoked {
						t.Fatalf("unrevoked watcher %q was signaled", watcher.jti)
					}
				default:
					if watcher.revoked {
						t.Fatalf("revoked watcher %q was not signaled", watcher.jti)
					}
				}
			}
		}
		for _, watcher := range watchers {
			watcher.release()
		}
		cache.mu.RLock()
		remaining := len(cache.watchers)
		cache.mu.RUnlock()
		if remaining != 0 {
			t.Fatalf("watchers leaked=%d", remaining)
		}
	})
}
