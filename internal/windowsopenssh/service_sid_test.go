package windowsopenssh

import "testing"

func TestDeriveServiceSIDMatchesWindowsSCM(t *testing.T) {
	const expected = "S-1-5-80-1125057845-2852617304-131425828-4126041352-434254831"
	for _, serviceName := range []string{"PaperboatHostd", "paperboathostd"} {
		if got := deriveServiceSID(serviceName); got != expected {
			t.Fatalf("deriveServiceSID(%q) = %q, want %q", serviceName, got, expected)
		}
	}
}
