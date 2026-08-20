package machinename

import "testing"

func TestValidatePortableHostnameLabel(t *testing.T) {
	for _, value := range []string{"Victus-Windows-E2E-Fresh", "macbook", "host-01", "A"} {
		if err := Validate(value); err != nil {
			t.Errorf("Validate(%q) = %v", value, err)
		}
	}
	for _, value := range []string{"", " --setup-mode=host", "--setup-mode=host", "host/name", "host name", "host=prod", ".", "host.", "-host", "host-", "a_b", "東京"} {
		if err := Validate(value); err == nil {
			t.Errorf("Validate(%q) unexpectedly succeeded", value)
		}
	}
}
