package serve

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCopyFileToInboxPublishesVerifiedCopyWithoutOverwrite(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "source", "report.txt")
	mustWrite(t, sourcePath, "paperboat")
	source, _ := ResolveSource(sourcePath)
	inbox := filepath.Join(root, "Paperboat Inbox")
	planned, err := PlanInboxCopy(source, inbox)
	if err != nil || planned != filepath.Join(inbox, "serve", "report.txt") {
		t.Fatalf("planned=%q err=%v", planned, err)
	}
	first, err := CopyFileToInbox(context.Background(), source, inbox)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CopyFileToInbox(context.Background(), source, inbox)
	if err != nil {
		t.Fatal(err)
	}
	if first.Path != filepath.Join(inbox, "serve", "report.txt") || second.Path != filepath.Join(inbox, "serve", "report-1.txt") {
		t.Fatalf("paths = %q, %q", first.Path, second.Path)
	}
	wantHash := sha256.Sum256([]byte("paperboat"))
	if first.Size != 9 || first.SHA256 != wantHash {
		t.Fatalf("copy = %#v", first)
	}
	data, err := os.ReadFile(first.Path)
	if err != nil || string(data) != "paperboat" {
		t.Fatalf("data=%q err=%v", data, err)
	}
	entries, _ := os.ReadDir(filepath.Join(inbox, "serve"))
	for _, entry := range entries {
		if entry.Name()[0] == '.' {
			t.Errorf("incomplete copy remains: %s", entry.Name())
		}
	}
}

func TestCopyFileToInboxCancellationCreatesNoFile(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "large.bin")
	if err := os.WriteFile(sourcePath, make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	source, _ := ResolveSource(sourcePath)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := CopyFileToInbox(ctx, source, filepath.Join(root, "Inbox"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	entries, readErr := os.ReadDir(filepath.Join(root, "Inbox", "serve"))
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("entries=%v err=%v", entries, readErr)
	}
}

func TestCopyFileToInboxChecksumFailureCreatesNoFile(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "report.txt")
	mustWrite(t, sourcePath, "paperboat")
	source, _ := ResolveSource(sourcePath)
	inbox := filepath.Join(root, "Inbox")
	_, err := copyFileToInbox(context.Background(), source, inbox, func(string) (int64, [sha256.Size]byte, error) {
		return int64(len("paperboat")), sha256.Sum256([]byte("corrupt")), nil
	})
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("error = %v", err)
	}
	entries, readErr := os.ReadDir(filepath.Join(inbox, "serve"))
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("entries=%v err=%v", entries, readErr)
	}
}

func TestCopyFileToInboxRejectsDirectory(t *testing.T) {
	source, _ := ResolveSource(t.TempDir())
	_, err := CopyFileToInbox(context.Background(), source, filepath.Join(t.TempDir(), "Inbox"))
	if !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("error = %v", err)
	}
}
