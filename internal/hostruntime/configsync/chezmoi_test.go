package configsync

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPlaintextRepositoryRejectsUnsafeChezmoiSource(t *testing.T) {
	for _, name := range []string{"run_once_bad", "encrypted_dot_config", "encrypted_literal_dot_config"} {
		t.Run(name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, name), []byte("unsafe"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ValidateConfigRepository(root); err == nil {
				t.Fatal("unsafe chezmoi source accepted")
			}
		})
	}
}

func TestPlaintextRepositoryAllowsExecutableChezmoiSource(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "executable_dot_script"), []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfigRepository(root); err != nil {
		t.Fatalf("executable source rejected: %v", err)
	}
}

func TestPlaintextRepositoryAllowsLiteralEncryptedFilename(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "literal_encrypted_dot_config"), []byte("plain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfigRepository(root); err != nil {
		t.Fatalf("literal filename rejected: %v", err)
	}
}

func TestChezmoiSourceConfiguresPlaintextAndAddWithoutEncryption(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell recorder fixture; native Windows chezmoi execution is qualified by runtime tests")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := filepath.Join(root, "runtime")
	sourceRoot := filepath.Join(root, "source")
	homeRoot := filepath.Join(root, "home")
	for _, path := range []string{runtimeRoot, sourceRoot, homeRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	argumentsPath := filepath.Join(root, "arguments")
	binary := filepath.Join(root, "chezmoi")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argumentsPath + "\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	source, err := NewChezmoiSource(ChezmoiSourceConfig{
		Binary: binary, RuntimeRoot: runtimeRoot, SourceRoot: sourceRoot, HomeRoot: homeRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Add(t.Context(), []string{"config.txt"}); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join(runtimeRoot, "chezmoi.toml"))
	if err != nil || strings.Contains(string(config), "encryption") || strings.Contains(string(config), "age") {
		t.Fatalf("chezmoi config = %q, %v", config, err)
	}
	arguments, err := os.ReadFile(argumentsPath)
	if err != nil || strings.Contains(string(arguments), "encrypt") {
		t.Fatalf("chezmoi arguments = %q, %v", arguments, err)
	}
}
