//go:build windows

package windowsenvironment

import (
	"slices"
	"testing"
)

func TestAppendPathEntryIsCaseInsensitiveAndIdempotent(t *testing.T) {
	const directory = `C:\Program Files\Paperboat\bin`
	for _, current := range []string{
		`C:\Windows\System32;C:\Program Files\Paperboat\bin`,
		`C:\Windows\System32;"c:\program files\paperboat\bin"`,
	} {
		updated, changed := appendPathEntry(current, directory)
		if changed || updated != current {
			t.Fatalf("appendPathEntry(%q) = %q, changed=%v", current, updated, changed)
		}
	}
	updated, changed := appendPathEntry(`C:\Windows\System32`, directory)
	if !changed || updated != `C:\Windows\System32;C:\Program Files\Paperboat\bin` {
		t.Fatalf("appendPathEntry new entry = %q, changed=%v", updated, changed)
	}
}

func TestRemovePathEntryPreservesUnrelatedEntries(t *testing.T) {
	updated, changed := removePathEntry(`C:\Windows\System32;C:\Program Files\Paperboat\bin;C:\Tools`, `c:\program files\paperboat\bin`)
	if !changed || updated != `C:\Windows\System32;C:\Tools` {
		t.Fatalf("removePathEntry = %q, changed=%v", updated, changed)
	}
}

func TestWithCommandDirectoryUpdatesExistingPathWithoutDroppingEnvironment(t *testing.T) {
	input := []string{"Path=C:\\Windows\\System32", "USER=pujan"}
	got := WithCommandDirectory(input, `C:\Program Files\Paperboat\bin`)
	want := []string{"Path=C:\\Windows\\System32;C:\\Program Files\\Paperboat\\bin", "USER=pujan"}
	if !slices.Equal(got, want) {
		t.Fatalf("WithCommandDirectory = %#v, want %#v", got, want)
	}
	if !slices.Equal(input, []string{"Path=C:\\Windows\\System32", "USER=pujan"}) {
		t.Fatalf("WithCommandDirectory mutated input: %#v", input)
	}
}

func TestWithCommandDirectoryAddsMissingPath(t *testing.T) {
	got := WithCommandDirectory([]string{"USER=pujan"}, `C:\Program Files\Paperboat\bin`)
	want := []string{"USER=pujan", `Path=C:\Program Files\Paperboat\bin`}
	if !slices.Equal(got, want) {
		t.Fatalf("WithCommandDirectory = %#v, want %#v", got, want)
	}
}
