package windowsopenssh

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pinksaucepasta/paperboat/internal/atomicfile"
	"golang.org/x/crypto/ssh"
)

// ReconcileAuthorizedKeys atomically replaces only PaperboatSshd's dedicated
// authorization file. It never reads or writes a user's .ssh directory.
func ReconcileAuthorizedKeys(stateRoot string, publicKeys []string) (bool, error) {
	return ReconcileAuthorizedKeysContext(context.Background(), stateRoot, publicKeys)
}

func ReconcileAuthorizedKeysContext(ctx context.Context, stateRoot string, publicKeys []string) (bool, error) {
	if ctx == nil || !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot || len(publicKeys) > 256 {
		return false, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	unlock, err := lockAuthorizedKeys(ctx, stateRoot)
	if err != nil {
		return false, err
	}
	defer unlock()
	lines := make([]string, 0, len(publicKeys))
	seen := make(map[string]bool, len(publicKeys))
	for _, value := range publicKeys {
		key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(value)))
		if err != nil || key == nil || key.Type() != ssh.KeyAlgoED25519 || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 || strings.ContainsAny(comment, "\x00\r\n") {
			return false, ErrQualificationEnrollment
		}
		line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		if seen[line] {
			continue
		}
		seen[line] = true
		lines = append(lines, line)
	}
	slices.Sort(lines)
	body := []byte(nil)
	if len(lines) > 0 {
		body = []byte(strings.Join(lines, "\n") + "\n")
	}
	directory := filepath.Join(stateRoot, "authorized_keys")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return false, err
	}
	path := filepath.Join(directory, "paperboat")
	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if bytes.Equal(existing, body) {
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := atomicfile.Write(path, body, atomicfile.Options{Mode: 0o600, OwnerUID: -1, OwnerGID: -1}); err != nil {
		return false, err
	}
	return true, nil
}
