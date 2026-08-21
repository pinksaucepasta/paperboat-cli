//go:build windows

package hostruntimecmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestReadWindowsHostdTokenAcceptsExactTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hostd.token")
	want := bytes.Repeat([]byte{0x5a}, 32)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsHostdTokenACL(path); err != nil {
		t.Fatal(err)
	}
	got, err := readWindowsHostdToken(path)
	if err != nil {
		descriptor, descriptorErr := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if descriptorErr != nil || descriptor == nil {
			t.Fatal(err)
		}
		user, userErr := windows.GetCurrentProcessToken().GetTokenUser()
		if userErr != nil || user == nil || user.User.Sid == nil {
			t.Fatalf("%v (dacl %q; current SID unavailable: %v)", err, windowsHostdTokenDACL(descriptor.String()), userErr)
		}
		control, _, controlErr := descriptor.Control()
		expected := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")"
		t.Fatalf("%v (sid %q; control %#x err %v; dacl %q; expected %q)", err, user.User.Sid.String(), control, controlErr, descriptor.String(), expected)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("token = %x, want %x", got, want)
	}
}

func setWindowsHostdTokenACL(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return err
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	absolute, err := descriptor.ToAbsolute()
	if err != nil {
		return err
	}
	dacl, _, err := absolute.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func TestReadWindowsHostdTokenRejectsRelativePath(t *testing.T) {
	if _, err := readWindowsHostdToken("hostd.token"); err == nil || !strings.Contains(err.Error(), "path is invalid") {
		t.Fatalf("err = %v, want invalid token path", err)
	}
}

func TestProductionRunDoesNotClaimReadinessWithoutHostdCredentials(t *testing.T) {
	t.Setenv("PAPERBOAT_HOSTD_TOKEN_FILE", "")
	var output bytes.Buffer
	err := runProduction(context.Background(), &output)
	if err == nil || !strings.Contains(err.Error(), "token path is invalid") {
		t.Fatalf("err = %v, want invalid token path", err)
	}
	if output.Len() != 0 {
		t.Fatalf("output = %q, must not claim readiness", output.String())
	}
}
