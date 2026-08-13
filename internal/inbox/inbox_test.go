package inbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/filetransfer"
)

type fakeClient struct {
	data         []byte
	contentCalls int
	offsets      []int64
}

func (f *fakeClient) Pending(context.Context, string, int) ([]filetransfer.Manifest, error) {
	return nil, nil
}
func (f *fakeClient) Receipt(context.Context, string, string, string) error { return nil }
func (f *fakeClient) Content(_ context.Context, _ filetransfer.Manifest, offset int64) (*http.Response, error) {
	f.contentCalls++
	f.offsets = append(f.offsets, offset)
	status := http.StatusOK
	if offset > 0 {
		status = http.StatusPartialContent
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(f.data[offset:])), Header: make(http.Header)}, nil
}

func manifest(id, name string, data []byte) filetransfer.Manifest {
	digest := sha256.Sum256(data)
	return filetransfer.Manifest{TransferID: id, BatchID: "batch_1", SourceMachineID: "machine_host", DestinationMachineID: "machine_local", InitiatingUserID: "user_1", SessionID: "session_1", Basename: name, Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:]), State: "pending"}
}

func TestDeliverResumesPartialAcrossPBRestartAndReturnsDurableRelativePath(t *testing.T) {
	downloads := t.TempDir()
	data := []byte("exact transfer bytes")
	client := &fakeClient{data: data}
	_, err := New(Config{Client: client, MachineID: "machine_local", SessionID: "session_1", Path: filepath.Join(downloads, "Paperboat Inbox")})
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(downloads, "Paperboat Inbox")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".paperboat-transfer-ft_resume.part"), data[:6], 0o600); err != nil {
		t.Fatal(err)
	}
	// A new Inbox has no process-local state from the instance that wrote the partial.
	receiver, err := New(Config{Client: client, MachineID: "machine_local", SessionID: "session_1", Path: filepath.Join(downloads, "Paperboat Inbox")})
	if err != nil {
		t.Fatal(err)
	}
	path, err := receiver.Deliver(context.Background(), manifest("ft_resume", "result.bin", data))
	if err != nil {
		t.Fatal(err)
	}
	if path != "Paperboat Inbox/result.bin" || len(client.offsets) != 1 || client.offsets[0] != 6 {
		t.Fatalf("path=%q offsets=%v", path, client.offsets)
	}
	stored, err := os.ReadFile(filepath.Join(downloads, filepath.FromSlash(path)))
	if err != nil || !bytes.Equal(stored, data) {
		t.Fatalf("stored=%q err=%v", stored, err)
	}
}

func TestDeliverUsesCollisionNameAndDeduplicatesTransfer(t *testing.T) {
	downloads := t.TempDir()
	root := filepath.Join(downloads, "Paperboat Inbox")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "report.txt"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := []byte("new")
	client := &fakeClient{data: data}
	receiver, _ := New(Config{Client: client, MachineID: "machine_local", SessionID: "session_1", Path: filepath.Join(downloads, "Paperboat Inbox")})
	item := manifest("ft_duplicate", "report.txt", data)
	first, err := receiver.Deliver(context.Background(), item)
	if err != nil {
		t.Fatal(err)
	}
	second, err := receiver.Deliver(context.Background(), item)
	if err != nil {
		t.Fatal(err)
	}
	if first != "Paperboat Inbox/report (2).txt" || second != first || client.contentCalls != 1 {
		t.Fatalf("first=%q second=%q calls=%d", first, second, client.contentCalls)
	}
}

func TestDeliverMixedTenFileBatchPreservesExactBytesWithoutDuplicates(t *testing.T) {
	downloads := t.TempDir()
	contents := [][]byte{
		nil,
		[]byte("plain text\nwith newline"),
		{0x00, 0xff, 0x01, 0x80},
		[]byte("{\"json\":true}"),
		[]byte("no extension"),
		[]byte("unicode contents"),
		bytes.Repeat([]byte{0xa5}, 32<<10),
		[]byte("collision one"),
		[]byte("collision two"),
		[]byte("final file"),
	}
	names := []string{"empty", "notes.txt", "opaque.bin", "data.json", "README", "résumé 最終.txt", "chunk.dat", "duplicate.txt", "duplicate.txt", "archive.tar.gz"}
	paths := make([]string, len(contents))
	for index, content := range contents {
		client := &fakeClient{data: content}
		receiver, err := New(Config{Client: client, MachineID: "machine_local", SessionID: "session_1", Path: filepath.Join(downloads, "Paperboat Inbox")})
		if err != nil {
			t.Fatal(err)
		}
		item := manifest(fmt.Sprintf("ft_mixed_%d", index), names[index], content)
		paths[index], err = receiver.Deliver(context.Background(), item)
		if err != nil {
			t.Fatalf("deliver %d: %v", index, err)
		}
		again, err := receiver.Deliver(context.Background(), item)
		if err != nil || again != paths[index] {
			t.Fatalf("replay %d path=%q err=%v", index, again, err)
		}
		stored, err := os.ReadFile(filepath.Join(downloads, filepath.FromSlash(paths[index])))
		if err != nil || !bytes.Equal(stored, content) {
			t.Fatalf("stored %d differs: size=%d err=%v", index, len(stored), err)
		}
	}
	if paths[7] != "Paperboat Inbox/duplicate.txt" || paths[8] != "Paperboat Inbox/duplicate (2).txt" {
		t.Fatalf("collision paths=%q, %q", paths[7], paths[8])
	}
	entries, err := os.ReadDir(filepath.Join(downloads, "Paperboat Inbox"))
	if err != nil {
		t.Fatal(err)
	}
	visible := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".") {
			visible++
		}
	}
	if visible != len(contents) {
		t.Fatalf("visible files=%d want=%d", visible, len(contents))
	}
}

func TestDeliverRejectsAlteredJournaledFile(t *testing.T) {
	downloads := t.TempDir()
	data := []byte("original")
	client := &fakeClient{data: data}
	receiver, _ := New(Config{Client: client, MachineID: "machine_local", SessionID: "session_1", Path: filepath.Join(downloads, "Paperboat Inbox")})
	item := manifest("ft_altered", "report.txt", data)
	path, err := receiver.Deliver(context.Background(), item)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(downloads, filepath.FromSlash(path)), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Deliver(context.Background(), item); err == nil || errorCode(err) != "digest_mismatch" {
		t.Fatalf("err=%v", err)
	}
	if client.contentCalls != 1 {
		t.Fatalf("content calls=%d", client.contentCalls)
	}
}

func TestDeliverRecoversJournalBeforeLinkCrash(t *testing.T) {
	downloads := t.TempDir()
	root := filepath.Join(downloads, "Paperboat Inbox")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte("recovered")
	item := manifest("ft_crash", "result.bin", data)
	receipts := journal{Version: 1, Entries: map[string]receipt{item.TransferID: {Digest: item.SHA256, Path: "Paperboat Inbox/result.bin", At: time.Now().UTC()}}}
	if err := saveJournal(root, receipts); err != nil {
		t.Fatal(err)
	}
	client := &fakeClient{data: data}
	receiver, _ := New(Config{Client: client, MachineID: "machine_local", SessionID: "session_1", Path: filepath.Join(downloads, "Paperboat Inbox")})
	path, err := receiver.Deliver(context.Background(), item)
	if err != nil {
		t.Fatal(err)
	}
	if path != "Paperboat Inbox/result.bin" {
		t.Fatalf("path=%q", path)
	}
	stored, err := os.ReadFile(filepath.Join(downloads, filepath.FromSlash(path)))
	if err != nil || !bytes.Equal(stored, data) {
		t.Fatalf("stored=%q err=%v", stored, err)
	}
}

func TestDeliverSupportsEmptyFileWithoutDownload(t *testing.T) {
	client := &fakeClient{}
	downloads := t.TempDir()
	receiver, _ := New(Config{Client: client, MachineID: "machine_local", SessionID: "session_1", Path: filepath.Join(downloads, "Paperboat Inbox")})
	path, err := receiver.Deliver(context.Background(), manifest("ft_empty", "empty", nil))
	if err != nil {
		t.Fatal(err)
	}
	if client.contentCalls != 0 || path != "Paperboat Inbox/empty" {
		t.Fatalf("calls=%d path=%q", client.contentCalls, path)
	}
	info, err := os.Stat(filepath.Join(downloads, filepath.FromSlash(path)))
	if err != nil || info.Size() != 0 {
		t.Fatalf("info=%v err=%v", info, err)
	}
}

func TestDeliverRejectsDigestMismatchAndRemovesPartial(t *testing.T) {
	downloads := t.TempDir()
	client := &fakeClient{data: []byte("wrong")}
	receiver, _ := New(Config{Client: client, MachineID: "machine_local", SessionID: "session_1", Path: filepath.Join(downloads, "Paperboat Inbox")})
	item := manifest("ft_bad", "bad.bin", []byte("right"))
	if _, err := receiver.Deliver(context.Background(), item); err == nil || errorCode(err) != "digest_mismatch" {
		t.Fatalf("err=%v", err)
	}
	partial := filepath.Join(downloads, "Paperboat Inbox", ".paperboat-transfer-ft_bad.part")
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Fatalf("partial remains: %v", err)
	}
}

func TestLocalBasenamePreservesUnicodeAndAdaptsWindowsReservedNames(t *testing.T) {
	if got := localBasename("résumé 最終.txt", "windows"); got != "résumé 最終.txt" {
		t.Fatalf("unicode name = %q", got)
	}
	for input, want := range map[string]string{
		"CON":              "_CON",
		"com1.log":         "_com1.log",
		"report:final.txt": "report_final.txt",
		"trailing. ":       "trailing",
	} {
		if got := localBasename(input, "windows"); got != want {
			t.Errorf("localBasename(%q) = %q, want %q", input, got, want)
		}
	}
	if got := localBasename("CON", "darwin"); got != "CON" {
		t.Fatalf("darwin name = %q", got)
	}
}
