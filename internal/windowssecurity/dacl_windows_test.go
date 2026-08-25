//go:build windows

package windowssecurity

import "testing"

func TestDACLMatchesLocalAdministratorAliasAfterOwnerRemoval(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-500"
	expected := dacl("O:" + sid + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + sid + ")")
	actual := "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LA)"
	if !daclMatchesLocalAdministratorAlias(actual, expected, sid) {
		t.Fatal("RID-500 trustee alias did not match after the owner field was removed")
	}
}

func TestDACLMatchesLocalAdministratorAliasRejectsDifferentACLs(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-500"
	expected := dacl("O:" + sid + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + sid + ")")
	tests := []struct {
		name    string
		actual  string
		userSID string
	}{
		{name: "non RID-500 user", actual: "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LA)", userSID: "S-1-5-21-1-2-3-1001"},
		{name: "extra ACE", actual: "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LA)(A;;FR;;;WD)", userSID: sid},
		{name: "different order", actual: "D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;LA)", userSID: sid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if daclMatchesLocalAdministratorAlias(test.actual, expected, test.userSID) {
				t.Fatal("different ACL matched the RID-500 alias fallback")
			}
		})
	}
}
