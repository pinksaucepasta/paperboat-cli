package hostruntimecmd

import "testing"

func TestBootstrapSSHFieldsOnlyForHost(t *testing.T) {
	if user, port := bootstrapSSHFields("receive", " pujan ", 22); user != "" || port != 0 {
		t.Fatalf("receive SSH fields = %q/%d, want empty/0", user, port)
	}
	if user, port := bootstrapSSHFields("host", " pujan ", 22); user != "pujan" || port != 22 {
		t.Fatalf("host SSH fields = %q/%d, want pujan/22", user, port)
	}
}
