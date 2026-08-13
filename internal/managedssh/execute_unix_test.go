//go:build darwin || linux

package managedssh

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenSSHExecutorPreservesArgumentsAndEnvironment(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "ssh")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var gotPath string
	var gotArguments, gotEnvironment []string
	sentinel := errors.New("exec reached")
	executor := OpenSSHExecutor{Exec: func(path string, arguments, environment []string) error {
		gotPath, gotArguments, gotEnvironment = path, append([]string(nil), arguments...), append([]string(nil), environment...)
		return sentinel
	}}
	arguments := []string{"-vv", "deploy@build.pprbt.dev", "printf", "%s", "hello world"}
	environment := []string{"PATH=/usr/bin:/bin", "SSH_AUTH_SOCK=/tmp/agent.sock"}
	if err := executor.Execute(executable, arguments, environment); !errors.Is(err, sentinel) {
		t.Fatalf("Execute() error=%v", err)
	}
	if gotPath != executable || len(gotArguments) != len(arguments)+1 || gotArguments[0] != executable {
		t.Fatalf("path=%q arguments=%q", gotPath, gotArguments)
	}
	for index := range arguments {
		if gotArguments[index+1] != arguments[index] {
			t.Fatalf("argument %d=%q want %q", index, gotArguments[index+1], arguments[index])
		}
	}
	if len(gotEnvironment) != len(environment) || gotEnvironment[1] != environment[1] {
		t.Fatalf("environment=%q", gotEnvironment)
	}
}

func TestOpenSSHExecutorRejectsInvalidInputs(t *testing.T) {
	executor := OpenSSHExecutor{Exec: func(string, []string, []string) error { t.Fatal("exec called"); return nil }}
	for _, test := range []struct {
		arguments   []string
		environment []string
	}{
		{arguments: nil},
		{arguments: []string{"host\x00bad"}},
		{arguments: []string{"host"}, environment: []string{"MISSING_VALUE"}},
		{arguments: []string{"host"}, environment: []string{"=value"}},
	} {
		if err := executor.Execute("/bin/sh", test.arguments, test.environment); !errors.Is(err, ErrOpenSSHExecution) {
			t.Fatalf("Execute(%q, %q) error=%v", test.arguments, test.environment, err)
		}
	}
	if err := executor.Execute(filepath.Join(t.TempDir(), "missing"), []string{"host"}, nil); !errors.Is(err, ErrOpenSSHExecution) {
		t.Fatalf("missing executable error=%v", err)
	}
}
