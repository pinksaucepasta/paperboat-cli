//go:build windows

package hostservice

import (
	"context"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPowerRequestIsIdempotentAndReleased(t *testing.T) {
	var creates, sets, clears, closes int
	lid := &testLidPolicy{}
	applier := &platformApplier{
		lid:    lid,
		create: func() (windows.Handle, error) { creates++; return windows.Handle(42), nil },
		set:    func(windows.Handle) error { sets++; return nil },
		clear:  func(windows.Handle) error { clears++; return nil },
		close:  func(windows.Handle) error { closes++; return nil },
	}
	if err := applier.Apply(context.Background(), KeepAwake); err != nil {
		t.Fatal(err)
	}
	if err := applier.Apply(context.Background(), KeepAwake); err != nil {
		t.Fatal(err)
	}
	if creates != 1 || sets != 1 || lid.keeps != 2 {
		t.Fatalf("repeated keep-awake created=%d set=%d lid-keeps=%d", creates, sets, lid.keeps)
	}
	if err := applier.Apply(context.Background(), AllowSleep); err != nil {
		t.Fatal(err)
	}
	if err := applier.Apply(context.Background(), AllowSleep); err != nil {
		t.Fatal(err)
	}
	if clears != 1 || closes != 1 || lid.restores != 2 || applier.active || applier.handle != 0 {
		t.Fatalf("release clear=%d close=%d lid-restores=%d active=%v handle=%v", clears, closes, lid.restores, applier.active, applier.handle)
	}
}

type testLidPolicy struct{ keeps, restores int }

func (p *testLidPolicy) KeepAwake() error { p.keeps++; return nil }
func (p *testLidPolicy) Restore() error   { p.restores++; return nil }

type testPowerScheme struct {
	scheme windows.GUID
	ac, dc uint32
	writes int
}

func (p *testPowerScheme) Current() (windows.GUID, error)            { return p.scheme, nil }
func (p *testPowerScheme) Read(windows.GUID) (uint32, uint32, error) { return p.ac, p.dc, nil }
func (p *testPowerScheme) Write(_ windows.GUID, ac, dc uint32) error {
	p.ac, p.dc, p.writes = ac, dc, p.writes+1
	return nil
}

func TestWindowsLidPolicyCapturesAndRestoresBaseline(t *testing.T) {
	scheme, err := windows.GUIDFromString("{381b4222-f694-41f0-9685-ff5bb260df2e}")
	if err != nil {
		t.Fatal(err)
	}
	power := &testPowerScheme{scheme: scheme, ac: 1, dc: 2}
	policy := &windowsLidPolicy{baselinePath: filepath.Join(t.TempDir(), "power-baseline.json"), power: power}
	if err := policy.KeepAwake(); err != nil {
		t.Fatal(err)
	}
	if power.ac != 0 || power.dc != 0 || power.writes != 1 {
		t.Fatalf("keep-awake state ac=%d dc=%d writes=%d", power.ac, power.dc, power.writes)
	}
	if err := policy.KeepAwake(); err != nil {
		t.Fatal(err)
	}
	if err := policy.Restore(); err != nil {
		t.Fatal(err)
	}
	if power.ac != 1 || power.dc != 2 || power.writes != 3 {
		t.Fatalf("restored state ac=%d dc=%d writes=%d", power.ac, power.dc, power.writes)
	}
}
