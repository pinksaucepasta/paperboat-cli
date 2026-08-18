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

func TestVerifierRejectsFailedDarwinAssessment(t *testing.T) {
	runner := &fakeRunner{err: errors.New("rejected")}
	if err := New(runner).Verify(context.Background(), "/release/pb", "darwin", "amd64"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifierRequiresValidAuthenticode(t *testing.T) {
	runner := &fakeRunner{output: []byte("Valid")}
	if err := New(runner).Verify(context.Background(), "C:\\Program Files\\Paperboat\\pb.exe", "windows", "amd64"); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || runner.calls[0].name != "powershell.exe" {
		t.Fatalf("native calls = %#v", runner.calls)
	}
	if !strings.Contains(strings.Join(runner.calls[0].args, " "), "Get-AuthenticodeSignature -LiteralPath 'C:\\Program Files\\Paperboat\\pb.exe'") {
		t.Fatalf("Authenticode command = %#v", runner.calls[0])
	}
}

func TestVerifierRejectsInvalidAuthenticodeAndUnsupportedPlatforms(t *testing.T) {
	for name, test := range map[string]struct {
		output       []byte
		platform     string
		architecture string
	}{
		"invalid authenticode":     {output: []byte("NotSigned"), platform: "windows", architecture: "arm64"},
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
