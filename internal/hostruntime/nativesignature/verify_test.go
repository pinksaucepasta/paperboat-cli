package nativesignature

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type call struct {
	name string
	args []string
}

type fakeRunner struct {
	calls  []call
	output []byte
	err    error
}

func (r *fakeRunner) Run(_ context.Context, name string, arguments ...string) ([]byte, error) {
	r.calls = append(r.calls, call{name: name, args: append([]string(nil), arguments...)})
	return r.output, r.err
}

func TestVerifierAcceptsLinuxWithoutNativeTool(t *testing.T) {
	runner := &fakeRunner{}
	if err := New(runner).Verify(context.Background(), "/release/pb", "linux", "amd64"); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("called native verifier for linux: %#v", runner.calls)
	}
}

func TestVerifierRequiresDarwinCodeSignAndGatekeeper(t *testing.T) {
	runner := &fakeRunner{}
	if err := New(runner).Verify(context.Background(), "/release/pb", "darwin", "arm64"); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 || runner.calls[0].name != "codesign" || runner.calls[1].name != "spctl" {
		t.Fatalf("native calls = %#v", runner.calls)
	}
	if got := strings.Join(runner.calls[0].args, " "); got != "--verify --deep --strict --verbose=2 /release/pb" {
		t.Fatalf("codesign args = %q", got)
	}
	if got := strings.Join(runner.calls[1].args, " "); got != "--assess --type execute --verbose=4 /release/pb" {
		t.Fatalf("spctl args = %q", got)
	}
}

func TestVerifierUsesInstallerChecksForDarwinPackage(t *testing.T) {
	runner := &fakeRunner{}
	if err := New(runner).Verify(context.Background(), "/release/pb-darwin-arm64.dmg", "darwin", "arm64"); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || runner.calls[0].name != "/usr/bin/hdiutil" {
		t.Fatalf("native calls = %#v", runner.calls)
	}
	if got := strings.Join(runner.calls[0].args, " "); got != "imageinfo /release/pb-darwin-arm64.dmg" {
		t.Fatalf("hdiutil args = %q", got)
	}
}

func TestVerifierRejectsFailedDarwinAssessment(t *testing.T) {
	runner := &fakeRunner{err: errors.New("rejected")}
	if err := New(runner).Verify(context.Background(), "/release/pb", "darwin", "amd64"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifierAllowsUnsignedWindowsPEWhenTUFAndPEChecksAreUsed(t *testing.T) {
	runner := &fakeRunner{}
	if err := New(runner).Verify(context.Background(), "C:\\Program Files\\Paperboat\\pb.exe", "windows", "amd64"); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unexpected native calls = %#v", runner.calls)
	}
}

func TestVerifierRejectsInvalidAuthenticodeAndUnsupportedPlatforms(t *testing.T) {
	for name, test := range map[string]struct {
		output       []byte
		platform     string
		architecture string
	}{
		"unsupported platform":     {platform: "plan9", architecture: "amd64"},
		"unsupported architecture": {platform: "linux", architecture: "386"},
	} {
		t.Run(name, func(t *testing.T) {
			err := New(&fakeRunner{output: test.output}).Verify(context.Background(), "/release/pb", test.platform, test.architecture)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
