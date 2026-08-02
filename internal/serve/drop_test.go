package serve

import (
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseDroppedFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "report final.txt")
	mustWrite(t, file, "report")
	escaped := strings.ReplaceAll(file, " ", `\ `)
	fileURL := (&url.URL{Scheme: "file", Path: file}).String()
	want, err := ResolveSource(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{escaped, `"` + file + `"`, fileURL, bracketedPasteStart + escaped + bracketedPasteEnd} {
		source, consumed := ParseDroppedFile(input)
		if !consumed || source.Path != want.Path || source.Kind != SourceFile {
			t.Errorf("input %q: source=%#v consumed=%v", input, source, consumed)
		}
	}
}

func TestParseDroppedFilePreservesNonFileInput(t *testing.T) {
	file := filepath.Join(t.TempDir(), "report.txt")
	mustWrite(t, file, "report")
	inputs := []string{"ordinary text", file + " " + file, filepath.Dir(file), "file://remotehost/tmp/file", "relative.txt", "'unterminated"}
	if runtime.GOOS != "windows" {
		inputs = append(inputs, "C:\\not-local-on-unix.txt")
	}
	for _, input := range inputs {
		if source, consumed := ParseDroppedFile(input); consumed {
			t.Errorf("input %q consumed as %#v", input, source)
		}
	}
}
