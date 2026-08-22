package filetransfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/store"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

func newService(t *testing.T) (*Service, *store.Store, string) {
	t.Helper()
	root := t.TempDir()
	durable, err := store.Open(context.Background(), store.Config{Root: filepath.Join(root, "state")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = durable.Close() })
	content := filepath.Join(root, "transfers")
	service, err := New(Config{Root: content, LocalMachineID: "machine_local", Store: durable, Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	return service, durable, content
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func requestFor(data []byte) CreateRequest {
	return CreateRequest{BatchID: "fb_1", SourceMachineID: "machine_source", DestinationMachineID: "machine_local", InitiatingUserID: "user_1", SessionID: "ses_1", Files: []File{{Basename: "data.bin", Size: int64(len(data)), SHA256: digest(data)}}}
}

func relayRequest(data []byte) CreateRequest {
	request := requestFor(data)
	request.SourceMachineID = "machine_local"
	request.DestinationMachineID = "machine_destination"
	request.DeliveryClientID = "cli_1"
	return request
}

func TestResumableTransferPersistsExactCommittedOffsetAndPublishes(t *testing.T) {
	service, durable, root := newService(t)
	data := []byte("abcdefgh")
	created, err := service.Create(context.Background(), requestFor(data))
	if err != nil {
		t.Fatal(err)
	}
	id := created[0].ID
	if got, err := service.Append(context.Background(), id, 0, bytes.NewReader(data[:3])); err != nil || got.CommittedOffset != 3 {
		t.Fatalf("append=%#v err=%v", got, err)
	}
	// Simulate bytes written after the last durable offset but before its metadata commit.
	partial, err := os.OpenFile(filepath.Join(root, id+".part"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = partial.Write([]byte("uncommitted"))
	_ = partial.Close()
	if got, err := service.Append(context.Background(), id, 3, bytes.NewReader(data[3:])); err != nil || got.CommittedOffset != int64(len(data)) {
		t.Fatalf("resume=%#v err=%v", got, err)
	}
	completed, err := service.Complete(context.Background(), id)
	if err != nil || completed.State != "published" {
		t.Fatalf("complete=%#v err=%v", completed, err)
	}
	published, err := service.PublishedPath(context.Background(), id)
	if err != nil || filepath.Base(published) != id+"-data.bin" {
		t.Fatalf("published path=%q err=%v", published, err)
	}
	publishedBytes, err := os.ReadFile(published)
	if err != nil || !bytes.Equal(publishedBytes, data) {
		t.Fatalf("published content=%q err=%v", publishedBytes, err)
	}
	if repeated, err := service.PublishedPath(context.Background(), id); err != nil || repeated != published {
		t.Fatalf("repeated published path=%q err=%v", repeated, err)
	}
	file, manifest, err := service.OpenContent(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	got, _ := io.ReadAll(file)
	if !bytes.Equal(got, data) || manifest.SHA256 != digest(data) {
		t.Fatalf("content=%q manifest=%#v", got, manifest)
	}
	persisted, err := durable.FileTransfer(context.Background(), id)
	if err != nil || persisted.CommittedOffset != int64(len(data)) {
		t.Fatalf("persisted=%#v err=%v", persisted, err)
	}
}

func TestEmptyTransferCompletesWithoutPatch(t *testing.T) {
	service, _, _ := newService(t)
	created, err := service.Create(context.Background(), requestFor(nil))
	if err != nil {
		t.Fatal(err)
	}
	completed, err := service.Complete(context.Background(), created[0].ID)
	if err != nil || completed.State != "published" || completed.ExpiresAt.Sub(completed.CreatedAt) != Retention {
		t.Fatalf("completed=%#v err=%v", completed, err)
	}
}

func TestBatchCompletionPublishesEveryFileAtomically(t *testing.T) {
	service, durable, _ := newService(t)
	first, second := []byte("first"), []byte("second")
	request := CreateRequest{BatchID: "fb_atomic", SourceMachineID: "machine_source", DestinationMachineID: "machine_local", InitiatingUserID: "user_1", SessionID: "ses_1", Files: []File{
		{Basename: "first.bin", Size: int64(len(first)), SHA256: digest(first)},
		{Basename: "second.bin", Size: int64(len(second)), SHA256: digest(second)},
	}}
	created, err := service.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Append(context.Background(), created[0].ID, 0, bytes.NewReader(first)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Complete(context.Background(), created[0].ID); !hasCode(err, InvalidSize) {
		t.Fatalf("early completion err=%v", err)
	}
	manifest, err := durable.FileTransfer(context.Background(), created[0].ID)
	if err != nil || manifest.State == "published" {
		t.Fatalf("first manifest=%#v err=%v", manifest, err)
	}
	if _, err := service.Append(context.Background(), created[1].ID, 0, bytes.NewReader(second)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Complete(context.Background(), created[0].ID); err != nil {
		t.Fatal(err)
	}
	for _, transfer := range created {
		manifest, err := durable.FileTransfer(context.Background(), transfer.ID)
		if err != nil || manifest.State != "published" {
			t.Fatalf("manifest=%#v err=%v", manifest, err)
		}
	}
}

func TestPublishedPathUsesInboxAndResolvesCollisionsIdempotently(t *testing.T) {
	service, durable, root := newService(t)
	inbox := filepath.Join(root, "Paperboat Inbox")
	service.config.PublishRoot = inbox
	if err := os.MkdirAll(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inbox, "data.bin"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := []byte("new data")
	created, err := service.Create(context.Background(), CreateRequest{BatchID: "fb_inbox", SourceMachineID: "machine_source", DestinationMachineID: "machine_local", InitiatingUserID: "user_1", Files: []File{{Basename: "data.bin", Size: int64(len(data)), SHA256: digest(data)}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Append(context.Background(), created[0].ID, 0, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Complete(context.Background(), created[0].ID); err != nil {
		t.Fatal(err)
	}
	path, err := service.PublishedPath(context.Background(), created[0].ID)
	if err != nil || path != filepath.Join(inbox, "data (2).bin") {
		t.Fatalf("published path=%q err=%v", path, err)
	}
	if repeated, err := service.PublishedPath(context.Background(), created[0].ID); err != nil || repeated != path {
		t.Fatalf("repeated path=%q err=%v", repeated, err)
	}
	manifest, err := durable.FileTransfer(context.Background(), created[0].ID)
	if err != nil || manifest.State != "published" {
		t.Fatalf("manifest=%+v err=%v", manifest, err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("published=%q err=%v", got, err)
	}
}

func TestMixedTenFileBatchPreservesExactBytesForLocalAndRelayedDestinations(t *testing.T) {
	contents := [][]byte{
		nil,
		[]byte("plain text\nwith newline"),
		{0x00, 0xff, 0x01, 0x80},
		[]byte("{\"json\":true}"),
		[]byte("no extension"),
		[]byte("unicode contents"),
		bytes.Repeat([]byte{0xa5}, 32<<10),
		[]byte("same basename content one"),
		[]byte("same basename content two"),
		[]byte("final file"),
	}
	names := []string{"empty", "notes.txt", "opaque.bin", "data.json", "README", "résumé 最終.txt", "chunk.dat", "duplicate.txt", "duplicate.txt", "archive.tar.gz"}
	for _, destination := range []string{"machine_local", "machine_destination"} {
		t.Run(destination, func(t *testing.T) {
			service, durable, root := newService(t)
			files := make([]File, len(contents))
			for index, content := range contents {
				files[index] = File{Basename: names[index], Size: int64(len(content)), SHA256: digest(content)}
			}
			request := CreateRequest{BatchID: "mixed-ten-" + destination, SourceMachineID: "machine_source", DestinationMachineID: destination, InitiatingUserID: "user_1", SessionID: "ses", Files: files}
			if destination != "machine_local" {
				request.SourceMachineID, request.DeliveryClientID = "machine_local", "cli"
			}
			created, err := service.Create(context.Background(), request)
			if err != nil || len(created) != MaxBatchFiles {
				t.Fatalf("create count=%d err=%v", len(created), err)
			}
			for index, transfer := range created {
				if len(contents[index]) > 0 {
					if _, err := service.Append(context.Background(), transfer.ID, 0, bytes.NewReader(contents[index])); err != nil {
						t.Fatalf("append %d: %v", index, err)
					}
				}
			}
			if _, err := service.Complete(context.Background(), created[0].ID); err != nil {
				t.Fatal(err)
			}
			for index, transfer := range created {
				manifest, err := durable.FileTransfer(context.Background(), transfer.ID)
				wantState := "published"
				if destination != "machine_local" {
					wantState = "pending"
				}
				if err != nil || manifest.State != wantState || manifest.SHA256 != digest(contents[index]) {
					t.Fatalf("manifest %d=%#v err=%v", index, manifest, err)
				}
				stored, err := os.ReadFile(filepath.Join(root, transfer.ID+".content"))
				if err != nil || !bytes.Equal(stored, contents[index]) {
					t.Fatalf("content %d differs: size=%d err=%v", index, len(stored), err)
				}
			}
		})
	}
}

func TestBatchDigestFailureCancelsAndCleansEveryFile(t *testing.T) {
	service, durable, root := newService(t)
	good, expectedBad := []byte("good"), []byte("expected")
	request := CreateRequest{BatchID: "fb_bad", SourceMachineID: "machine_source", DestinationMachineID: "machine_local", InitiatingUserID: "user_1", SessionID: "ses_1", Files: []File{
		{Basename: "good.bin", Size: int64(len(good)), SHA256: digest(good)},
		{Basename: "bad.bin", Size: int64(len(expectedBad)), SHA256: digest(expectedBad)},
	}}
	created, err := service.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Append(context.Background(), created[0].ID, 0, bytes.NewReader(good)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Append(context.Background(), created[1].ID, 0, bytes.NewReader([]byte("corrupt!"))); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Complete(context.Background(), created[0].ID); !hasCode(err, DigestMismatch) {
		t.Fatalf("completion err=%v", err)
	}
	for _, transfer := range created {
		manifest, err := durable.FileTransfer(context.Background(), transfer.ID)
		if err != nil || manifest.State != "canceled" {
			t.Fatalf("manifest=%#v err=%v", manifest, err)
		}
		for _, suffix := range []string{".part", ".content"} {
			if _, err := os.Stat(filepath.Join(root, transfer.ID+suffix)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s remains: %v", transfer.ID+suffix, err)
			}
		}
	}
}

func TestPendingSpoolLimitRejectsWholeBatch(t *testing.T) {
	root := t.TempDir()
	durable, err := store.Open(context.Background(), store.Config{Root: filepath.Join(root, "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()
	policy := DefaultPolicy
	policy.MaxFileBytes, policy.MaxBatchBytes, policy.MaxPendingSpoolBytes = 5, 5, 5
	service, err := New(Config{Root: filepath.Join(root, "transfers"), LocalMachineID: "machine_local", Store: durable, Policy: NewPolicyStore(policy)})
	if err != nil {
		t.Fatal(err)
	}
	first := relayRequest([]byte("1234"))
	if _, err := service.Create(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := relayRequest([]byte("12"))
	second.BatchID = "fb_2"
	if _, err := service.Create(context.Background(), second); !hasCode(err, ResourceLimit) {
		t.Fatalf("second create err=%v", err)
	}
	transfers, err := durable.FileTransfersByBatch(context.Background(), "fb_2")
	if err == nil || len(transfers) != 0 {
		t.Fatalf("partial rejected batch=%v err=%v", transfers, err)
	}
}

func TestAcceptedPolicyUpdateChangesCreateEnforcement(t *testing.T) {
	root := t.TempDir()
	durable, err := store.Open(context.Background(), store.Config{Root: filepath.Join(root, "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()
	policies := NewPolicyStore(DefaultPolicy)
	service, err := New(Config{Root: filepath.Join(root, "transfers"), LocalMachineID: "machine_local", Store: durable, Policy: policies})
	if err != nil {
		t.Fatal(err)
	}
	updated := DefaultPolicy
	updated.Revision = "file-transfer-tight"
	updated.MaxFileBytes = 2
	if err := policies.Update(updated); err != nil {
		t.Fatal(err)
	}
	request := requestFor([]byte("123"))
	if _, err := service.Create(context.Background(), request); !hasCode(err, InvalidSize) {
		t.Fatalf("create err=%v", err)
	}
}

func TestOutboundDeliveryExpiryFailsRecordAndCleansContent(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	durable, err := store.Open(context.Background(), store.Config{Root: filepath.Join(root, "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()
	policy := DefaultPolicy
	policy.DeliveryTimeoutSeconds = 60
	service, err := New(Config{Root: filepath.Join(root, "transfers"), LocalMachineID: "machine_local", Store: durable, Now: func() time.Time { return now }, Policy: NewPolicyStore(policy)})
	if err != nil {
		t.Fatal(err)
	}
	request := relayRequest([]byte("data"))
	created, err := service.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Append(context.Background(), created[0].ID, 0, bytes.NewReader([]byte("data"))); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Complete(context.Background(), created[0].ID); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := service.CleanupExpired(context.Background()); err != nil {
		t.Fatal(err)
	}
	manifest, err := durable.FileTransfer(context.Background(), created[0].ID)
	if err != nil || manifest.State != "failed" || manifest.ResultCode != "delivery_timeout" {
		t.Fatalf("manifest=%#v err=%v", manifest, err)
	}
	if _, err := os.Stat(filepath.Join(root, "transfers", created[0].ID+".content")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("content remains: %v", err)
	}
}

func TestPublishedInboundFileSurvivesUntilSevenDayRetentionBoundary(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	durable, err := store.Open(context.Background(), store.Config{Root: filepath.Join(root, "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()
	service, err := New(Config{Root: filepath.Join(root, "transfers"), LocalMachineID: "machine_local", Store: durable, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(context.Background(), requestFor(nil))
	if err != nil {
		t.Fatal(err)
	}
	id := created[0].ID
	if _, err := service.Complete(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	now = now.Add(Retention - time.Nanosecond)
	if err := service.CleanupExpired(context.Background()); err != nil {
		t.Fatal(err)
	}
	if manifest, err := service.Get(context.Background(), id); err != nil || manifest.State != "published" {
		t.Fatalf("before boundary manifest=%#v err=%v", manifest, err)
	}
	now = now.Add(time.Nanosecond)
	if err := service.CleanupExpired(context.Background()); err != nil {
		t.Fatal(err)
	}
	manifest, err := service.Get(context.Background(), id)
	if err != nil || manifest.State != "canceled" || manifest.ResultCode != "canceled" {
		t.Fatalf("at boundary manifest=%#v err=%v", manifest, err)
	}
	if _, err := os.Stat(filepath.Join(root, "transfers", id+".content")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired content remains: %v", err)
	}
}

func TestEncryptedTransferExpiryErasesKeyBeforeCleanup(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	durable, err := store.Open(context.Background(), store.Config{Root: filepath.Join(root, "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()
	eraseErr := errors.New("vault unavailable")
	erased := 0
	service, err := New(Config{
		Root: filepath.Join(root, "transfers"), LocalMachineID: "machine_local", Store: durable,
		Now: func() time.Time { return now }, EraseTransferKey: func(id string) error {
			if id != "fb_encrypted" {
				t.Fatalf("key id=%q", id)
			}
			erased++
			return eraseErr
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := requestFor([]byte("private"))
	request.E2EETransferID, request.TransferGeneration = "fb_encrypted", 1
	request.Files[0].ID, request.Files[0].Ordinal = "fb_encrypted.0", 0
	created, err := service.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(Retention)
	if err := service.CleanupExpired(context.Background()); !hasCode(err, StorageUnavailable) {
		t.Fatalf("cleanup err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "transfers", created[0].ID+".part")); err != nil {
		t.Fatalf("failed erasure removed retry state: %v", err)
	}
	eraseErr = nil
	if err := service.CleanupExpired(context.Background()); err != nil {
		t.Fatal(err)
	}
	if erased != 2 {
		t.Fatalf("erase attempts=%d", erased)
	}
	if _, err := os.Stat(filepath.Join(root, "transfers", created[0].ID+".part")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired content remains: %v", err)
	}
}

func TestEncryptedChunkCommitRejectsReorderAndAlteredReplay(t *testing.T) {
	service, _, _ := newService(t)
	data := bytes.Repeat([]byte{7}, transfercrypto.ChunkSize+1)
	request := requestFor(data)
	request.E2EETransferID, request.TransferGeneration = "fb_encrypted", 1
	request.Files[0].ID, request.Files[0].Ordinal = "fb_encrypted.0", 0
	created, err := service.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest := sha256.Sum256([]byte("ciphertext-0"))
	secondDigest := sha256.Sum256([]byte("ciphertext-1"))
	if _, err := service.AppendEncrypted(context.Background(), created[0].ID, 1, secondDigest, 17, data[transfercrypto.ChunkSize:]); !hasCode(err, OffsetConflict) {
		t.Fatalf("reordered chunk err=%v", err)
	}
	if _, err := service.AppendEncrypted(context.Background(), created[0].ID, 0, firstDigest, 31, data[:transfercrypto.ChunkSize]); err != nil {
		t.Fatal(err)
	}
	if replayed, err := service.AppendEncrypted(context.Background(), created[0].ID, 0, firstDigest, 31, data[:transfercrypto.ChunkSize]); err != nil || replayed.CommittedChunks != 1 {
		t.Fatalf("exact replay transfer=%+v err=%v", replayed, err)
	}
	alteredDigest := sha256.Sum256([]byte("altered-ciphertext-0"))
	if _, err := service.AppendEncrypted(context.Background(), created[0].ID, 0, alteredDigest, 31, data[:transfercrypto.ChunkSize]); !hasCode(err, OffsetConflict) {
		t.Fatalf("altered replay err=%v", err)
	}
	current, err := service.Get(context.Background(), created[0].ID)
	if err != nil || current.CommittedChunks != 1 || current.CommittedOffset != transfercrypto.ChunkSize {
		t.Fatalf("current=%+v err=%v", current, err)
	}
}

func TestTransferResumesAcrossHelperRestart(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	contentRoot := filepath.Join(root, "transfers")
	data := []byte("resume-across-helper-restart")
	durable, err := store.Open(context.Background(), store.Config{Root: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{Root: contentRoot, LocalMachineID: "machine_local", Store: durable})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(context.Background(), requestFor(data))
	if err != nil {
		t.Fatal(err)
	}
	id := created[0].ID
	cut := int64(9)
	if _, err := service.Append(context.Background(), id, 0, bytes.NewReader(data[:cut])); err != nil {
		t.Fatal(err)
	}
	if err := durable.Close(); err != nil {
		t.Fatal(err)
	}

	durable, err = store.Open(context.Background(), store.Config{Root: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()
	service, err = New(Config{Root: contentRoot, LocalMachineID: "machine_local", Store: durable})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := service.Get(context.Background(), id)
	if err != nil || manifest.CommittedOffset != cut {
		t.Fatalf("recovered manifest=%#v err=%v", manifest, err)
	}
	if _, err := service.Append(context.Background(), id, cut, bytes.NewReader(data[cut:])); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Complete(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(contentRoot, id+".content"))
	if err != nil || !bytes.Equal(stored, data) {
		t.Fatalf("stored=%q err=%v", stored, err)
	}
}

func TestTransferRejectsOffsetOverflowDigestAndUnsafeBatch(t *testing.T) {
	service, _, _ := newService(t)
	data := []byte("data")
	created, err := service.Create(context.Background(), requestFor(data))
	if err != nil {
		t.Fatal(err)
	}
	id := created[0].ID
	if _, err := service.Append(context.Background(), id, 1, bytes.NewReader(data)); !hasCode(err, OffsetConflict) {
		t.Fatalf("offset err=%v", err)
	}
	if _, err := service.Append(context.Background(), id, 0, bytes.NewReader([]byte("overflow"))); !hasCode(err, InvalidSize) {
		t.Fatalf("overflow err=%v", err)
	}
	if _, err := service.Append(context.Background(), id, 0, bytes.NewReader([]byte("xxxx"))); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Complete(context.Background(), id); !hasCode(err, DigestMismatch) {
		t.Fatalf("digest err=%v", err)
	}
	for _, request := range []CreateRequest{
		{BatchID: "fb", SourceMachineID: "machine_source", DestinationMachineID: "machine_local", InitiatingUserID: "user_1", SessionID: "ses", Files: []File{{Basename: "../x", Size: 0, SHA256: digest(nil)}}},
		{BatchID: "fb", SourceMachineID: "machine_source", DestinationMachineID: "machine_local", InitiatingUserID: "user_1", SessionID: "ses", Files: make([]File, MaxBatchFiles+1)},
	} {
		if _, err := service.Create(context.Background(), request); err == nil {
			t.Fatalf("accepted %#v", request)
		}
	}
}

func TestCancelIsIdempotentAndRemovesPartial(t *testing.T) {
	service, _, root := newService(t)
	created, err := service.Create(context.Background(), requestFor([]byte("data")))
	if err != nil {
		t.Fatal(err)
	}
	id := created[0].ID
	if err := service.Cancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := service.Cancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, id+".part")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat err=%v", err)
	}
}

func TestCancelWaitsForActiveAppendBeforeRemovingPartial(t *testing.T) {
	service, _, root := newService(t)
	created, err := service.Create(context.Background(), requestFor([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	id := created[0].ID
	reader := &blockedUploadReader{started: make(chan struct{}), release: make(chan struct{})}
	appendDone := make(chan error, 1)
	go func() {
		_, appendErr := service.Append(context.Background(), id, 0, reader)
		appendDone <- appendErr
	}()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("append did not begin reading")
	}
	cancelDone := make(chan error, 1)
	go func() { cancelDone <- service.Cancel(context.Background(), id) }()
	select {
	case err := <-cancelDone:
		t.Fatalf("cancel returned before active append closed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(reader.release)
	select {
	case err := <-appendDone:
		if !hasCode(err, Canceled) {
			t.Fatalf("append err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("append did not stop after cancellation")
	}
	select {
	case err := <-cancelDone:
		if err != nil {
			t.Fatalf("cancel err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not finish after append closed")
	}
	if _, err := os.Stat(filepath.Join(root, id+".part")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial remains after cancellation: %v", err)
	}
}

func TestAppendDoesNotCommitWhenCancellationArrivesWithEOF(t *testing.T) {
	service, _, root := newService(t)
	created, err := service.Create(context.Background(), requestFor([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	id := created[0].ID
	if _, err := service.Append(context.Background(), id, 0, cancellationOnEOFReader{cancel: func() { service.signalCancel(id) }}); !hasCode(err, Canceled) {
		t.Fatalf("append err=%v", err)
	}
	transfer, err := service.Get(context.Background(), id)
	if err != nil || transfer.CommittedOffset != 0 || transfer.State != "created" {
		t.Fatalf("transfer=%#v err=%v", transfer, err)
	}
	info, err := os.Stat(filepath.Join(root, id+".part"))
	if err != nil || info.Size() != 0 {
		t.Fatalf("partial info=%#v err=%v", info, err)
	}
}

func TestCancelTimeoutRetainsFilesAndCancellationForRetry(t *testing.T) {
	service, _, root := newService(t)
	service.config.CancellationDrainTimeout = 25 * time.Millisecond
	created, err := service.Create(context.Background(), requestFor([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	id := created[0].ID
	reader := &blockedUploadReader{started: make(chan struct{}), release: make(chan struct{})}
	appendDone := make(chan error, 1)
	go func() {
		_, appendErr := service.Append(context.Background(), id, 0, reader)
		appendDone <- appendErr
	}()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("append did not begin reading")
	}
	if err := service.Cancel(context.Background(), id); !hasCode(err, StorageUnavailable) {
		t.Fatalf("cancel err=%v", err)
	}
	select {
	case <-service.CancellationSignal(id):
	default:
		t.Fatal("cancellation signal was not retained after drain timeout")
	}
	if _, err := os.Stat(filepath.Join(root, id+".part")); err != nil {
		t.Fatalf("drain timeout removed partial: %v", err)
	}
	close(reader.release)
	select {
	case err := <-appendDone:
		if !hasCode(err, Canceled) {
			t.Fatalf("append err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("append did not stop after cancellation")
	}
	if err := service.Cancel(context.Background(), id); err != nil {
		t.Fatalf("retry cancel err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, id+".part")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retry cancel retained partial: %v", err)
	}
}

func TestCancelAndAppendRegistrationRaceLeavesNoWriterOrPartial(t *testing.T) {
	for iteration := 0; iteration < 64; iteration++ {
		t.Run(fmt.Sprintf("iteration-%d", iteration), func(t *testing.T) {
			service, _, root := newService(t)
			created, err := service.Create(context.Background(), requestFor([]byte("x")))
			if err != nil {
				t.Fatal(err)
			}
			id := created[0].ID
			reader := &cancelSignalReader{started: make(chan struct{}), signal: service.CancellationSignal(id)}
			start := make(chan struct{})
			appendDone := make(chan error, 1)
			cancelDone := make(chan error, 1)
			go func() {
				<-start
				_, appendErr := service.Append(context.Background(), id, 0, reader)
				appendDone <- appendErr
			}()
			go func() {
				<-start
				cancelDone <- service.Cancel(context.Background(), id)
			}()
			close(start)
			select {
			case err := <-appendDone:
				if !hasCode(err, Canceled) {
					t.Fatalf("append err=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("append did not finish")
			}
			select {
			case err := <-cancelDone:
				if err != nil {
					t.Fatalf("cancel err=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancel did not finish")
			}
			if _, active := service.writes.Load(id); active {
				t.Fatal("active writer registration remains")
			}
			if _, err := os.Stat(filepath.Join(root, id+".part")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial remains after concurrent cancellation: %v", err)
			}
		})
	}
}

func TestCreateEnforcesExactFileAndBatchBoundaries(t *testing.T) {
	service, _, _ := newService(t)
	files := make([]File, MaxBatchFiles)
	for index := range files {
		files[index] = File{Basename: fmt.Sprintf("file-%d.bin", index), Size: MaxFileBytes, SHA256: digest(nil)}
	}
	files[0].Basename = "résumé 最終.bin"
	files[1].Basename = "CON"
	created, err := service.Create(context.Background(), CreateRequest{BatchID: "boundary-ok", SourceMachineID: "machine_source", DestinationMachineID: "machine_local", InitiatingUserID: "user_1", SessionID: "ses", Files: files})
	if err != nil || len(created) != MaxBatchFiles {
		t.Fatalf("exact boundary: transfers=%d err=%v", len(created), err)
	}
	tooMany := append(append([]File(nil), files...), File{Basename: "eleven.bin", Size: 0, SHA256: digest(nil)})
	if _, err := service.Create(context.Background(), CreateRequest{BatchID: "count-over", SourceMachineID: "machine_source", DestinationMachineID: "machine_local", InitiatingUserID: "user_1", SessionID: "ses", Files: tooMany}); !hasCode(err, BatchLimit) {
		t.Fatalf("eleven files err=%v", err)
	}
	if _, err := service.Create(context.Background(), CreateRequest{BatchID: "size-over", SourceMachineID: "machine_source", DestinationMachineID: "machine_local", InitiatingUserID: "user_1", SessionID: "ses", Files: []File{{Basename: "large.bin", Size: MaxFileBytes + 1, SHA256: digest(nil)}}}); !hasCode(err, InvalidSize) {
		t.Fatalf("oversized file err=%v", err)
	}
}

type diskFullReader struct{}

func (diskFullReader) Read([]byte) (int, error) { return 0, syscall.ENOSPC }

type blockedUploadReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *blockedUploadReader) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	return 0, io.EOF
}

type cancellationOnEOFReader struct{ cancel func() }

func (r cancellationOnEOFReader) Read([]byte) (int, error) {
	r.cancel()
	return 0, io.EOF
}

type cancelSignalReader struct {
	started chan struct{}
	signal  <-chan struct{}
	once    sync.Once
}

func (r *cancelSignalReader) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.signal
	return 0, io.EOF
}

func TestAppendReportsDiskFullWithoutCommittingOffset(t *testing.T) {
	service, _, _ := newService(t)
	created, err := service.Create(context.Background(), requestFor([]byte("data")))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := service.Append(context.Background(), created[0].ID, 0, diskFullReader{})
	if !hasCode(err, StorageUnavailable) || !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("disk full err=%v", err)
	}
	if updated.CommittedOffset != 0 {
		t.Fatalf("returned committed offset=%d", updated.CommittedOffset)
	}
	persisted, getErr := service.Get(context.Background(), created[0].ID)
	if getErr != nil || persisted.CommittedOffset != 0 {
		t.Fatalf("persisted=%#v err=%v", persisted, getErr)
	}
}

func TestCreateBoundsConcurrentEmptyBatches(t *testing.T) {
	service, _, _ := newService(t)
	request := requestFor(nil)
	for index := 0; index < DefaultPolicy.MaxConcurrentTransfers; index++ {
		request.BatchID = fmt.Sprintf("empty-%d", index)
		if _, err := service.Create(context.Background(), request); err != nil {
			t.Fatalf("batch %d: %v", index, err)
		}
	}
	request.BatchID = "empty-over-limit"
	if _, err := service.Create(context.Background(), request); !hasCode(err, ResourceLimit) {
		t.Fatalf("unbounded empty batch err=%v", err)
	}
}

func hasCode(err error, code Code) bool {
	var transferErr *Error
	return errors.As(err, &transferErr) && transferErr.Code == code
}
