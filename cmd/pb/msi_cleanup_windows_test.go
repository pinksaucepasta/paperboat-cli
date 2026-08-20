//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMSIPreviewOwnershipRequiresExactPaperboatDeclaration(t *testing.T) {
	root := t.TempDir()
	paths := msiCleanupPaths{
		BinaryRoot:  filepath.Join(root, "bin"),
		StateRoot:   filepath.Join(root, "state"),
		ServiceRoot: filepath.Join(root, "state", "services"),
	}
	if err := os.MkdirAll(paths.ServiceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(paths.BinaryRoot, "pb.exe")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("MZ"), 0o700); err != nil {
		t.Fatal(err)
	}
	name := "PaperboatPreview-0123456789abcdef"
	definitionPath := filepath.Join(paths.ServiceRoot, name+".json")
	definition := msiWindowsServiceDefinition{
		Schema:     msiPaperboatServiceSchema,
		Name:       name,
		Executable: executable,
		Arguments: []string{
			msiPaperboatPreviewCommand,
			"--state-root", filepath.Join(paths.StateRoot, "runtime"),
			"--service-definition", definitionPath,
		},
		Account: "SYSTEM",
	}
	body, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(definitionPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := readMSIServiceDefinition(definitionPath)
	if err != nil || !exists || !ownedPaperboatPreviewDefinition(definitionPath, loaded, name, paths) {
		t.Fatalf("owned definition exists=%t err=%v definition=%+v", exists, err, loaded)
	}

	loaded.Arguments[loadedArgumentIndex(loaded.Arguments, "--service-definition")+1] = filepath.Join(paths.ServiceRoot, "PaperboatPreview-ffffffffffffffff.json")
	if ownedPaperboatPreviewDefinition(definitionPath, loaded, name, paths) {
		t.Fatal("definition with a different service declaration path was accepted")
	}
}

func TestMSIPreviewOwnershipRejectsLookalikeNamesAndExecutables(t *testing.T) {
	for _, name := range []string{"PaperboatPreview-0123456789abcde", "PaperboatPreview-0123456789abcdef0", "PaperboatPreview-0123456789ABCDEf"} {
		if isPaperboatPreviewServiceName(name) {
			t.Fatalf("lookalike service name accepted: %s", name)
		}
	}
	paths := msiCleanupPaths{BinaryRoot: `C:\Program Files\Paperboat\bin`, StateRoot: `C:\ProgramData\Paperboat`, ServiceRoot: `C:\ProgramData\Paperboat\services`}
	if allowedPaperboatServiceExecutable(`C:\Program Files\PaperboatEvil\bin\pb.exe`, paths) {
		t.Fatal("lookalike executable root accepted")
	}
}

func loadedArgumentIndex(args []string, value string) int {
	for index, arg := range args {
		if arg == value {
			return index
		}
	}
	return -1
}
