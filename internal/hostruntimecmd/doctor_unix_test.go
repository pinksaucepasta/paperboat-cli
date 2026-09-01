//go:build darwin || linux

package hostruntimecmd

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSystemServiceScopeUsesCurrentLinuxUnits(t *testing.T) {
	tests := []struct {
		name      string
		hostMode  bool
		active    map[string]bool
		wantErr   bool
		wantCalls []string
	}{
		{
			name:     "host current units",
			hostMode: true,
			active: map[string]bool{
				"paperboat-hostd.service":              true,
				"paperboat-runtime-privileged.service": true,
			},
			wantCalls: []string{
				"/usr/bin/systemctl is-active paperboat-hostd.service",
				"/usr/bin/systemctl is-active paperboat-runtime-privileged.service",
			},
		},
		{
			name:      "client hostd only",
			active:    map[string]bool{"paperboat-hostd.service": true},
			wantCalls: []string{"/usr/bin/systemctl is-active paperboat-hostd.service"},
		},
		{
			name:      "missing hostd",
			hostMode:  true,
			active:    map[string]bool{"paperboat-runtime-privileged.service": true},
			wantErr:   true,
			wantCalls: []string{"/usr/bin/systemctl is-active paperboat-hostd.service"},
		},
		{
			name:     "degraded privileged service",
			hostMode: true,
			active:   map[string]bool{"paperboat-hostd.service": true},
			wantErr:  true,
			wantCalls: []string{
				"/usr/bin/systemctl is-active paperboat-hostd.service",
				"/usr/bin/systemctl is-active paperboat-runtime-privileged.service",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			run := func(_ context.Context, name string, args ...string) ([]byte, error) {
				call := strings.TrimSpace(name + " " + strings.Join(args, " "))
				calls = append(calls, call)
				unit := args[len(args)-1]
				if !test.active[unit] {
					return nil, errors.New("inactive")
				}
				return []byte("active\n"), nil
			}
			scope, err := systemServiceScopeWithRunner(context.Background(), "linux", test.hostMode, run)
			if (err != nil) != test.wantErr {
				t.Fatalf("error=%v, wantErr=%t", err, test.wantErr)
			}
			if scope != "system" {
				t.Fatalf("scope=%q", scope)
			}
			if !reflect.DeepEqual(calls, test.wantCalls) {
				t.Fatalf("calls=%v, want=%v", calls, test.wantCalls)
			}
		})
	}
}

func TestSystemServiceScopeRejectsLegacyOnlyAndMissingPlatformServices(t *testing.T) {
	legacyOnly := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[len(args)-1] == "paperboat-runtime-host.service" {
			return []byte("active\n"), nil
		}
		return nil, errors.New("unit missing")
	}
	if _, err := systemServiceScopeWithRunner(context.Background(), "linux", true, legacyOnly); err == nil {
		t.Fatal("legacy runtime-host service satisfied host readiness")
	}
	if _, err := systemServiceScopeWithRunner(context.Background(), "linux", true, func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("unit missing")
	}); err == nil {
		t.Fatal("missing current unit satisfied host readiness")
	}
}
