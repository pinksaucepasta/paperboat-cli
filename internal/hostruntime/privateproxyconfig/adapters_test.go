package privateproxyconfig

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

type call struct {
	name string
	args []string
}
type scriptedRunner struct {
	outputs [][]byte
	errs    []error
	calls   []call
}

func (s *scriptedRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	s.calls = append(s.calls, call{name, append([]string(nil), args...)})
	i := len(s.calls) - 1
	var out []byte
	var err error
	if i < len(s.outputs) {
		out = s.outputs[i]
	}
	if i < len(s.errs) {
		err = s.errs[i]
	}
	return out, err
}

func TestMacSnapshotUsesExactArgvAndSkipsDisabled(t *testing.T) {
	r := &scriptedRunner{outputs: [][]byte{[]byte("An asterisk denotes disabled services.\nWi-Fi\n*VPN\nEthernet\n"), []byte("URL: http://old/p.pac\nEnabled: Yes\n"), []byte("URL: (null)\nEnabled: No\n")}}
	a := NewMacOSAdapter(r)
	raw, err := a.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got macState
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Services) != 2 || got.Services[0].URL != "http://old/p.pac" || got.Services[1].URL != "" || got.Services[1].Enabled {
		t.Fatalf("state=%+v", got)
	}
	want := call{networksetup, []string{"-getautoproxyurl", "Wi-Fi"}}
	if !reflect.DeepEqual(r.calls[1], want) {
		t.Fatalf("call=%+v", r.calls[1])
	}
}

func TestMacMatchesIgnoresRetainedURLOnlyWhenProxyIsDisabled(t *testing.T) {
	want, _ := json.Marshal(macState{Services: []macService{{Name: "Wi-Fi", Enabled: false}}})
	r := &scriptedRunner{outputs: [][]byte{[]byte("Wi-Fi\n"), []byte("URL: http://127.0.0.1:56837/proxy.pac\nEnabled: No\n")}}
	matched, err := NewMacOSAdapter(r).Matches(context.Background(), want)
	if err != nil || !matched {
		t.Fatalf("matched=%v err=%v", matched, err)
	}

	want, _ = json.Marshal(macState{Services: []macService{{Name: "Wi-Fi", URL: "http://127.0.0.1:1/proxy.pac", Enabled: true}}})
	r = &scriptedRunner{outputs: [][]byte{[]byte("Wi-Fi\n"), []byte("URL: http://127.0.0.1:2/proxy.pac\nEnabled: Yes\n")}}
	matched, err = NewMacOSAdapter(r).Matches(context.Background(), want)
	if err != nil || matched {
		t.Fatalf("matched=%v err=%v", matched, err)
	}
}

func TestLinuxRequiresExplicitGNOMESession(t *testing.T) {
	r := &scriptedRunner{}
	a := NewLinuxAdapter(r, func(string) string { return "" })
	if _, err := a.Snapshot(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err=%v", err)
	}
	if len(r.calls) != 0 {
		t.Fatal("mutated without supported session")
	}
}

type fakeRegistry struct {
	interactive bool
	value       RegistryValue
	broadcasts  int
}

func (r *fakeRegistry) InteractiveUser(context.Context) (bool, error)           { return r.interactive, nil }
func (r *fakeRegistry) GetAutoConfigURL(context.Context) (RegistryValue, error) { return r.value, nil }
func (r *fakeRegistry) SetAutoConfigURL(_ context.Context, v RegistryValue) error {
	r.value = v
	return nil
}
func (r *fakeRegistry) BroadcastInternetSettingsChanged(context.Context) error {
	r.broadcasts++
	return nil
}
func TestWindowsPreservesMissingValueAndRejectsSystem(t *testing.T) {
	r := &fakeRegistry{interactive: true}
	a := NewWindowsAdapter(r)
	raw, err := a.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Install(context.Background(), "http://127.0.0.1:1/a.pac"); err != nil {
		t.Fatal(err)
	}
	if err := a.Restore(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	if r.value.Exists || r.broadcasts != 2 {
		t.Fatalf("registry=%+v broadcasts=%d", r.value, r.broadcasts)
	}
	r.interactive = false
	if _, err := a.Snapshot(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err=%v", err)
	}
}
