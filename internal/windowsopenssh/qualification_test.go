package windowsopenssh

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testAuthorizedKey(t *testing.T) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}

func TestEphemeralAuthorizedKeyEnrollmentRestoresExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	original := append([]byte("# administrator-owned test state\n"), testAuthorizedKey(t)...)
	original = append(original, '\n')
	if err := os.WriteFile(path, original, 0o640); err != nil {
		t.Fatal(err)
	}
	enrolledKey := testAuthorizedKey(t)
	enrollment, err := enrollEphemeralAuthorizedKey(path, enrolledKey)
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(current, append(append([]byte(nil), enrolledKey...), '\n')) {
		t.Fatalf("enrolled key missing from authorized_keys: %q", current)
	}
	if err := enrollment.Restore(); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, original) {
		t.Fatalf("restored authorized_keys = %q, want %q", restored, original)
	}
	if err := enrollment.Restore(); err != nil {
		t.Fatalf("second restore should be idempotent: %v", err)
	}
}

func TestEphemeralAuthorizedKeyEnrollmentRestoresMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	enrollment, err := enrollEphemeralAuthorizedKey(path, testAuthorizedKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if err := enrollment.Restore(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("authorized_keys after restore error = %v, want not exists", err)
	}
}

func TestEphemeralAuthorizedKeyEnrollmentFailsClosedOnConcurrentMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	enrollment, err := enrollEphemeralAuthorizedKey(path, testAuthorizedKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("administrator changed this file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restoreErr := enrollment.Restore()
	if !errors.Is(restoreErr, ErrQualificationRestoreConflict) {
		t.Fatalf("restore error = %v, want conflict", restoreErr)
	}
	current, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(current) != "administrator changed this file\n" {
		t.Fatalf("concurrent file was overwritten: %q", current)
	}
}

func TestQualificationErrorIsTypedBoundedAndRedacted(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "private-key")
	output := []byte(strings.Repeat(secretPath+" secret-output\n", 400))
	err := qualificationFailureWithCode(QualificationStageSCPUpload, errors.New("native command failed"), 255, output, secretPath)
	var qualificationErr *QualificationError
	if !errors.As(err, &qualificationErr) {
		t.Fatalf("error type = %T, want QualificationError", err)
	}
	if !errors.Is(err, ErrQualificationSCP) || qualificationErr.Stage != QualificationStageSCPUpload || qualificationErr.ExitCode != 255 {
		t.Fatalf("qualification error = %#v", qualificationErr)
	}
	if strings.Contains(qualificationErr.Error(), secretPath) || strings.Contains(qualificationErr.Detail, secretPath) {
		t.Fatalf("qualification error leaked secret path: %v", qualificationErr)
	}
	if len(qualificationErr.Detail) > qualificationMaximumDetail+len("…") {
		t.Fatalf("qualification detail length = %d, want bounded", len(qualificationErr.Detail))
	}
}

func TestQualificationRemoteNamesAndSFTPQuoting(t *testing.T) {
	for value, want := range map[string]bool{
		"paperboat-qualification-scp-0123456789abcdef":  true,
		"paperboat-qualification-sftp-0123456789abcdef": true,
		"paperboat-qualification-../../escape":          false,
		"paperboat-qualification-XYZ":                   false,
		"paperboat-qualification-":                      false,
	} {
		if got := validQualificationRemoteName(value); got != want {
			t.Fatalf("validQualificationRemoteName(%q) = %t, want %t", value, got, want)
		}
	}
	quoted := quoteSFTPPath(filepath.FromSlash("C:/Users/Test User/file.txt"))
	if quoted != `"C:/Users/Test User/file.txt"` {
		t.Fatalf("quoteSFTPPath = %q", quoted)
	}
}

func TestQualificationReportJSONContainsOnlySafeEvidence(t *testing.T) {
	report := QualificationReport{Identity: "DOMAIN\\user", Port: 38222, Authenticated: true, Exec: true, ExitStatus: true, PTY: true, SCPUpload: true, SCPDownload: true, SFTPUpload: true, SFTPDownload: true, Restored: true, TemporaryStateRemoved: true}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("private")) || bytes.Contains(body, []byte("secret")) {
		t.Fatalf("unsafe qualification evidence: %s", body)
	}
}
