//go:build windows

package windowsopenssh

import "testing"

func TestParseWingetPackageListCurrentTable(t *testing.T) {
	output := "Name    Id                        Version\r\n" +
		"------------------------------------------\r\n" +
		"OpenSSH Microsoft.OpenSSH.Preview 10.0.0.0\r\n"
	registered, version := parseWingetPackageList(output)
	if !registered || version != ApprovedVersion {
		t.Fatalf("registered=%t version=%q", registered, version)
	}
}

func TestNoInstalledWingetPackageRequiresAuthoritativeMessage(t *testing.T) {
	if !noInstalledWingetPackage("No installed package found matching input criteria.") {
		t.Fatal("authoritative package-absent response was not recognized")
	}
	for _, output := range []string{"", "source unavailable", "operation timed out"} {
		if noInstalledWingetPackage(output) {
			t.Fatalf("probe failure %q was treated as package absence", output)
		}
	}
}
