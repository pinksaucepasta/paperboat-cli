package manifest

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCheckedInManifestIsLongPathAware(t *testing.T) {
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "packaging", "windows", "resources", "paperboat.manifest"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifest(data); err != nil {
		t.Fatal(err)
	}
}

func TestValidateManifestRejectsWrongNamespace(t *testing.T) {
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "packaging", "windows", "resources", "paperboat.manifest"))
	if err != nil {
		t.Fatal(err)
	}
	wrong := strings.Replace(string(data), longPathAwareNamespace, "urn:paperboat:test", 1)
	if err := ValidateManifest([]byte(wrong)); err == nil {
		t.Fatal("manifest with the wrong longPathAware namespace was accepted")
	}
}

func TestGoBuildEmbedsLongPathManifestForBothArchitectures(t *testing.T) {
	root := repositoryRoot(t)
	for _, test := range []struct {
		name   string
		goos   string
		goarch string
		pkg    string
	}{
		{name: "cli-amd64", goos: "windows", goarch: "amd64", pkg: "./cmd/pb"},
		{name: "cli-arm64", goos: "windows", goarch: "arm64", pkg: "./cmd/pb"},
		{name: "launcher-amd64", goos: "windows", goarch: "amd64", pkg: "./cmd/pb-launcher"},
		{name: "launcher-arm64", goos: "windows", goarch: "arm64", pkg: "./cmd/pb-launcher"},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), test.name+".exe")
			command := exec.Command("go", "build", "-trimpath", "-o", output, test.pkg)
			command.Dir = root
			command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+test.goos, "GOARCH="+test.goarch)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("go build %s: %v\n%s", test.pkg, err, output)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidatePE(data); err != nil {
				t.Fatalf("embedded long-path manifest: %v", err)
			}
		})
	}
}

func TestValidatePERejectsNonPEInput(t *testing.T) {
	if err := ValidatePE([]byte("not a Windows executable")); err == nil {
		t.Fatal("non-PE input was accepted")
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
}
