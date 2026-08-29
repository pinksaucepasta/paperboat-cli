//go:build darwin || linux

package updated

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestFixedUpdaterReexecPreservesJobAndUsesOnlyUpdaterRole(t *testing.T) {
	wantErr := errors.New("exec stopped for test")
	var path string
	var arguments, environment []string
	restarter := &FixedUpdaterReexec{
		binary: "/fixed/paperboat/pb",
		exec: func(gotPath string, gotArguments, gotEnvironment []string) error {
			path = gotPath
			arguments = append([]string(nil), gotArguments...)
			environment = append([]string(nil), gotEnvironment...)
			return wantErr
		},
	}
	if err := restarter.Restart(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("Restart() error = %v, want %v", err, wantErr)
	}
	if path != restarter.binary || !reflect.DeepEqual(arguments, []string{restarter.binary, "__runtime-updated"}) {
		t.Fatalf("exec path=%q arguments=%q", path, arguments)
	}
	if len(environment) == 0 {
		t.Fatal("reexec dropped the root-owned service environment")
	}
}

func TestFixedUpdaterReexecHonorsCanceledContext(t *testing.T) {
	called := false
	restarter := &FixedUpdaterReexec{binary: "/fixed/paperboat/pb", exec: func(string, []string, []string) error {
		called = true
		return nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := restarter.Restart(ctx); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("Restart() error=%v called=%v", err, called)
	}
}
