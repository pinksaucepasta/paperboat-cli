//go:build windows

package supportbundle

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pinksaucepasta/paperboat/internal/windowssecurity"
	"golang.org/x/sys/windows"
)

func TestWriteUsesProtectedWindowsOwnerACL(t *testing.T) {
	builder := mustBuilder(t)
	preview, err := builder.Preview(context.Background())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	output := filepath.Join(realTempDir(t), "support-bundle.json")
	if _, err := builder.Write(context.Background(), preview, output); err != nil {
		t.Fatalf("Write: %v", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	sid := user.User.Sid.String()
	descriptor := "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if sid != "S-1-5-18" {
		descriptor += "(A;;FA;;;" + sid + ")"
	}
	if !windowssecurity.OwnerMatchesSID(output, user.User.Sid) {
		t.Fatal("support bundle owner does not match the current user")
	}
	if !windowssecurity.ProtectedDACLMatches(output, descriptor) {
		t.Fatal("support bundle does not have the protected private DACL")
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatalf("Stat: %v", err)
	}
}
