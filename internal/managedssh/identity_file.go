package managedssh

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ManagedIdentityPublicKeyFilename is intentionally public-only. The matching
// private key never leaves the OS credential store; OpenSSH uses this file to
// select the matching key from the Paperboat-owned agent when IdentitiesOnly is
// enabled.
const ManagedIdentityPublicKeyFilename = "paperboat-managed-ssh.pub"

var ErrManagedIdentityFileConflict = errors.New("managed SSH public identity file conflicts with existing state")

const managedIdentityPublicKeyComment = "paperboat-managed-ssh-v1"

func ManagedIdentityPublicKeyPath(home string) string {
	if !filepath.IsAbs(home) {
		return ""
	}
	return filepath.Join(filepath.Clean(home), ".ssh", ManagedIdentityPublicKeyFilename)
}

func managedIdentityPublicKeyContent(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return nil, ErrManagedIdentityFileConflict
	}
	public, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(value))
	if err != nil || public.Type() != ssh.KeyAlgoED25519 || len(options) != 0 || strings.TrimSpace(string(rest)) != "" || comment != "" {
		return nil, ErrManagedIdentityFileConflict
	}
	canonical := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
	if canonical != value {
		return nil, ErrManagedIdentityFileConflict
	}
	return []byte(canonical + " " + managedIdentityPublicKeyComment + "\n"), nil
}

func isManagedIdentityPublicKey(value []byte, publicKey string) bool {
	public, comment, options, rest, err := ssh.ParseAuthorizedKey(value)
	if err != nil || comment != managedIdentityPublicKeyComment || len(options) != 0 || strings.TrimSpace(string(rest)) != "" || public.Type() != ssh.KeyAlgoED25519 {
		return false
	}
	if strings.TrimSpace(publicKey) == "" {
		return true
	}
	expected, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(publicKey)))
	return err == nil && len(options) == 0 && strings.TrimSpace(string(rest)) == "" && bytes.Equal(public.Marshal(), expected.Marshal())
}
