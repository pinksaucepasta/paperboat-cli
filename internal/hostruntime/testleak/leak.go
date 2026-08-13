// Package testleak provides bounded process-resource checks for integration tests.
package testleak

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"go.uber.org/goleak"
)

type Snapshot struct {
	Goroutines       int
	Descriptors      int
	ignoreGoroutines goleak.Option
}

func Take() (Snapshot, error) {
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Goroutines: runtime.NumGoroutine(), Descriptors: len(entries), ignoreGoroutines: goleak.IgnoreCurrent()}, nil
}

func WaitForBaseline(baseline Snapshot, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		runtime.GC()
		runtime.Gosched()
		current, err := Take()
		if err != nil {
			return err
		}
		if current.Goroutines <= baseline.Goroutines && current.Descriptors <= baseline.Descriptors {
			if err := goleak.Find(baseline.ignoreGoroutines); err == nil {
				return nil
			}
		}
		if time.Now().After(deadline) {
			buffer := make([]byte, 1<<20)
			n := runtime.Stack(buffer, true)
			return fmt.Errorf("resource leak: baseline_goroutines=%d current_goroutines=%d baseline_descriptors=%d current_descriptors=%d\n%s", baseline.Goroutines, current.Goroutines, baseline.Descriptors, current.Descriptors, buffer[:n])
		}
		//paperboat:allow-source-policy sleep owner=test-infrastructure reason=bounded-resource-quiescence-probe
		time.Sleep(10 * time.Millisecond)
	}
}
