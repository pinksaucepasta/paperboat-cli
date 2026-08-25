package filetransfer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/store"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

const (
	MaxFileBytes  = int64(50 << 20)
	MaxBatchBytes = int64(500 << 20)
	MaxBatchFiles = 10
	Retention     = 7 * 24 * time.Hour

	// cancellationDrainTimeout bounds a DELETE while an HTTP upload is
	// unwinding. We must not remove a partial file until its active writer has
	// closed it: Windows rejects removal of an open file.
	cancellationDrainTimeout = 5 * time.Second
)

type Policy struct {
	Revision               string `json:"revision"`
	MaxFileBytes           int64  `json:"max_file_bytes"`
	MaxBatchFiles          int    `json:"max_batch_files"`
	MaxBatchBytes          int64  `json:"max_batch_bytes"`
	MaxConcurrentTransfers int    `json:"max_concurrent_transfers"`
	RetentionSeconds       int64  `json:"retention_seconds"`
	DeliveryTimeoutSeconds int64  `json:"delivery_timeout_seconds"`
	MaxPendingSpoolBytes   int64  `json:"max_pending_spool_bytes"`
}

var DefaultPolicy = Policy{Revision: "file-transfer-v1", MaxFileBytes: MaxFileBytes, MaxBatchFiles: MaxBatchFiles, MaxBatchBytes: MaxBatchBytes, MaxConcurrentTransfers: 2, RetentionSeconds: int64(Retention / time.Second), DeliveryTimeoutSeconds: 600, MaxPendingSpoolBytes: 1 << 30}

var opaqueIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type PolicyStore struct {
	mu     sync.RWMutex
	policy Policy
}

func NewPolicyStore(policy Policy) *PolicyStore {
	if !policy.Valid() {
		policy = DefaultPolicy
	}
	return &PolicyStore{policy: policy}
}
func (s *PolicyStore) Current() Policy { s.mu.RLock(); defer s.mu.RUnlock(); return s.policy }
func (s *PolicyStore) Update(policy Policy) error {
	if !policy.Valid() {
		return &Error{Code: InvalidSize}
	}
	s.mu.Lock()
	s.policy = policy
	s.mu.Unlock()
	return nil
}
func (p Policy) Valid() bool {
	return p.Revision != "" && p.MaxFileBytes > 0 && p.MaxFileBytes <= MaxFileBytes && p.MaxBatchFiles > 0 && p.MaxBatchFiles <= MaxBatchFiles && p.MaxBatchBytes >= p.MaxFileBytes && p.MaxBatchBytes <= MaxBatchBytes && p.MaxConcurrentTransfers > 0 && p.MaxConcurrentTransfers <= 2 && p.RetentionSeconds > 0 && p.DeliveryTimeoutSeconds > 0 && p.MaxPendingSpoolBytes >= p.MaxBatchBytes
}

type Code string

const (
	InvalidPath        Code = "invalid_path"
	InvalidSize        Code = "invalid_size"
	BatchLimit         Code = "batch_limit"
	OffsetConflict     Code = "offset_conflict"
	DigestMismatch     Code = "digest_mismatch"
	StorageUnavailable Code = "storage_unavailable"
	ResourceLimit      Code = "resource_limit"
	Canceled           Code = "canceled"
	DeliveryTimeout    Code = "delivery_timeout"
)

type Error struct {
	Code  Code
	Cause error
}

func (e *Error) Error() string {
	if e.Cause == nil {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Cause.Error()
}
func (e *Error) Unwrap() error { return e.Cause }

type File struct {
	ID       string `json:"transfer_id,omitempty"`
	Basename string `json:"basename"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Ordinal  uint64 `json:"file_ordinal,omitempty"`
}
type CreateRequest struct {
	BatchID              string
	SourceMachineID      string
	DestinationMachineID string
	InitiatingUserID     string
	SessionID            string
	DeliveryClientID     string
	Files                []File
	E2EETransferID       string
	TransferGeneration   uint64
}

type Config struct {
	Root                     string
	PublishRoot              string
	LocalMachineID           string
	Store                    *store.Store
	EraseTransferKey         func(string) error
	Now                      func() time.Time
	Random                   io.Reader
	Policy                   *PolicyStore
	CancellationDrainTimeout time.Duration
}

type Service struct {
	config  Config
	slotMu  sync.Mutex
	active  int
	locks   sync.Map
	cancels sync.Map
	writes  sync.Map
}

type transferCancellation struct {
	once sync.Once
	done chan struct{}
}

type transferWrite struct{ done chan struct{} }

func New(config Config) (*Service, error) {
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.Policy == nil {
		config.Policy = NewPolicyStore(DefaultPolicy)
	}
	if !filepath.IsAbs(config.Root) || config.LocalMachineID == "" || config.Store == nil {
		return nil, &Error{Code: InvalidPath}
	}
	if err := os.MkdirAll(config.Root, 0o700); err != nil {
		return nil, &Error{Code: StorageUnavailable, Cause: err}
	}
	if err := os.Chmod(config.Root, 0o700); err != nil {
		return nil, &Error{Code: StorageUnavailable, Cause: err}
	}
	return &Service{config: config}, nil
}

func (s *Service) Create(ctx context.Context, request CreateRequest) ([]store.FileTransfer, error) {
	policy := s.config.Policy.Current()
	encrypted := request.E2EETransferID != "" || request.TransferGeneration != 0
	if request.BatchID == "" || request.SourceMachineID == "" || request.DestinationMachineID == "" || request.InitiatingUserID == "" || request.SourceMachineID == request.DestinationMachineID || request.DestinationMachineID != s.config.LocalMachineID && (request.SessionID == "" || request.DeliveryClientID == "") || encrypted != (opaqueIDPattern.MatchString(request.E2EETransferID) && request.TransferGeneration > 0) {
		return nil, &Error{Code: InvalidPath}
	}
	if len(request.Files) < 1 || len(request.Files) > policy.MaxBatchFiles {
		return nil, &Error{Code: BatchLimit}
	}
	now := s.config.Now()
	transfers := make([]store.FileTransfer, len(request.Files))
	var total int64
	for i, file := range request.Files {
		if encrypted && (!opaqueIDPattern.MatchString(file.ID) || file.Ordinal != uint64(i)) || !encrypted && (file.ID != "" || file.Ordinal != 0) {
			return nil, &Error{Code: InvalidPath}
		}
		if !validBasename(file.Basename) {
			return nil, &Error{Code: InvalidPath}
		}
		if file.Size < 0 || file.Size > policy.MaxFileBytes {
			return nil, &Error{Code: InvalidSize}
		}
		if !validDigest(file.SHA256) {
			return nil, &Error{Code: DigestMismatch}
		}
		total += file.Size
		if total > policy.MaxBatchBytes {
			return nil, &Error{Code: BatchLimit}
		}
		id := file.ID
		if id == "" {
			var err error
			id, err = s.newID("ft_")
			if err != nil {
				return nil, &Error{Code: StorageUnavailable, Cause: err}
			}
		}
		expiresAt := now.Add(time.Duration(policy.RetentionSeconds) * time.Second)
		if request.DestinationMachineID != s.config.LocalMachineID {
			expiresAt = now.Add(time.Duration(policy.DeliveryTimeoutSeconds) * time.Second)
		}
		transfers[i] = store.FileTransfer{ID: id, BatchID: request.BatchID, SourceMachineID: request.SourceMachineID, DestinationMachineID: request.DestinationMachineID, InitiatingUserID: request.InitiatingUserID, SessionID: request.SessionID, DeliveryClientID: request.DeliveryClientID, Basename: file.Basename, Size: file.Size, SHA256: file.SHA256, State: "created", CreatedAt: now, ExpiresAt: expiresAt, E2EETransferID: request.E2EETransferID, TransferGeneration: request.TransferGeneration, FileOrdinal: file.Ordinal}
	}
	if err := s.config.Store.CreateFileTransfersWithinLimits(ctx, transfers, policy.MaxPendingSpoolBytes, policy.MaxConcurrentTransfers); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, &Error{Code: ResourceLimit, Cause: err}
		}
		return nil, &Error{Code: StorageUnavailable, Cause: err}
	}
	for _, transfer := range transfers {
		s.cancelSignal(transfer.ID)
		file, err := os.OpenFile(s.partialPath(transfer.ID), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			_ = s.cancelBatch(context.Background(), transfers)
			return nil, &Error{Code: StorageUnavailable, Cause: err}
		}
		if err := file.Close(); err != nil {
			_ = s.cancelBatch(context.Background(), transfers)
			return nil, &Error{Code: StorageUnavailable, Cause: err}
		}
	}
	if err := syncDir(s.config.Root); err != nil {
		_ = s.cancelBatch(context.Background(), transfers)
		return nil, &Error{Code: StorageUnavailable, Cause: err}
	}
	return transfers, nil
}

// CleanupExpired removes transfer records and content after their independent retention deadline.
func (s *Service) CleanupExpired(ctx context.Context) error {
	transfers, err := s.config.Store.ExpiredFileTransfers(ctx, s.config.Now())
	if err != nil {
		return err
	}
	erased := make(map[string]struct{})
	for _, transfer := range transfers {
		if transfer.E2EETransferID == "" || s.config.EraseTransferKey == nil {
			continue
		}
		if _, ok := erased[transfer.E2EETransferID]; ok {
			continue
		}
		if err := s.config.EraseTransferKey(transfer.E2EETransferID); err != nil {
			return &Error{Code: StorageUnavailable, Cause: fmt.Errorf("erase expired transfer key: %w", err)}
		}
		erased[transfer.E2EETransferID] = struct{}{}
	}
	for _, transfer := range transfers {
		_ = os.Remove(s.partialPath(transfer.ID))
		_ = os.Remove(s.contentPath(transfer.ID))
		_ = os.Remove(s.publishedPath(transfer))
		s.cancels.Delete(transfer.ID)
	}
	return s.config.Store.ExpireFileTransfers(ctx, transfers)
}

type CleanupWorker struct {
	Service  *Service
	Interval time.Duration
	cancel   context.CancelFunc
	done     chan struct{}
}

func (w *CleanupWorker) Start(context.Context) error {
	interval := w.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel, w.done = cancel, make(chan struct{})
	go func() {
		defer close(w.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = w.Service.CleanupExpired(context.Background())
			}
		}
	}()
	return nil
}
func (w *CleanupWorker) Shutdown(ctx context.Context) error {
	if w.cancel == nil {
		return nil
	}
	w.cancel()
	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) Append(ctx context.Context, id string, offset int64, body io.Reader) (store.FileTransfer, error) {
	if err := s.acquire(ctx); err != nil {
		return store.FileTransfer{}, err
	}
	defer s.release()
	lock := s.lock(id)
	lock.Lock()
	defer lock.Unlock()
	finish := s.beginWrite(id)
	defer finish()
	transfer, err := s.config.Store.FileTransfer(ctx, id)
	if err != nil {
		return store.FileTransfer{}, &Error{Code: InvalidPath, Cause: err}
	}
	if transfer.State == "canceled" {
		return store.FileTransfer{}, &Error{Code: Canceled}
	}
	if offset != transfer.CommittedOffset {
		return transfer, &Error{Code: OffsetConflict}
	}
	file, err := os.OpenFile(s.partialPath(id), os.O_WRONLY, 0)
	if err != nil {
		return transfer, &Error{Code: StorageUnavailable, Cause: err}
	}
	defer file.Close()
	if err := file.Truncate(offset); err != nil {
		return transfer, &Error{Code: StorageUnavailable, Cause: err}
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return transfer, &Error{Code: StorageUnavailable, Cause: err}
	}
	remaining := transfer.Size - offset
	canceled := s.cancelSignal(id)
	written, err := io.Copy(file, io.LimitReader(&contextReader{ctx: ctx, reader: body, canceled: canceled}, remaining+1))
	if err != nil {
		if ctx.Err() != nil {
			return transfer, ctx.Err()
		}
		select {
		case <-canceled:
			return transfer, &Error{Code: Canceled}
		default:
		}
		return transfer, classifyIO(err)
	}
	select {
	case <-canceled:
		_ = file.Truncate(offset)
		return transfer, &Error{Code: Canceled}
	default:
	}
	if written > remaining {
		_ = file.Truncate(offset)
		return transfer, &Error{Code: InvalidSize}
	}
	if err := file.Sync(); err != nil {
		return transfer, &Error{Code: StorageUnavailable, Cause: err}
	}
	if err := s.config.Store.CommitFileTransferOffset(ctx, id, offset, offset+written); err != nil {
		return transfer, &Error{Code: OffsetConflict, Cause: err}
	}
	transfer.CommittedOffset += written
	transfer.State = "uploading"
	return transfer, nil
}

func (s *Service) AppendEncrypted(ctx context.Context, id string, ordinal uint64, ciphertextDigest [sha256.Size]byte, ciphertextLength int, plaintext []byte) (store.FileTransfer, error) {
	if err := s.acquire(ctx); err != nil {
		return store.FileTransfer{}, err
	}
	defer s.release()
	lock := s.lock(id)
	lock.Lock()
	defer lock.Unlock()
	finish := s.beginWrite(id)
	defer finish()
	transfer, err := s.config.Store.FileTransfer(ctx, id)
	if err != nil || transfer.E2EETransferID == "" || transfer.TransferGeneration == 0 {
		return store.FileTransfer{}, &Error{Code: InvalidPath, Cause: err}
	}
	if transfer.State == "canceled" {
		return store.FileTransfer{}, &Error{Code: Canceled}
	}
	if ordinal > uint64(^uint64(0)>>1)/uint64(transfercrypto.ChunkSize) {
		return transfer, &Error{Code: InvalidSize}
	}
	offset := int64(ordinal * uint64(transfercrypto.ChunkSize))
	want := transfer.Size - offset
	if want > int64(transfercrypto.ChunkSize) {
		want = int64(transfercrypto.ChunkSize)
	}
	if want < 0 || int64(len(plaintext)) != want {
		return transfer, &Error{Code: InvalidSize}
	}
	if ordinal < transfer.CommittedChunks {
		replayed, commitErr := s.config.Store.CommitFileTransferChunk(ctx, id, ordinal, offset, offset+int64(len(plaintext)), ciphertextDigest, ciphertextLength, len(plaintext))
		if commitErr != nil || !replayed {
			return transfer, &Error{Code: OffsetConflict, Cause: commitErr}
		}
		return transfer, nil
	}
	if ordinal != transfer.CommittedChunks || offset != transfer.CommittedOffset {
		return transfer, &Error{Code: OffsetConflict}
	}
	file, err := os.OpenFile(s.partialPath(id), os.O_WRONLY, 0)
	if err != nil {
		return transfer, &Error{Code: StorageUnavailable, Cause: err}
	}
	defer file.Close()
	if err := file.Truncate(offset); err != nil {
		return transfer, &Error{Code: StorageUnavailable, Cause: err}
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return transfer, &Error{Code: StorageUnavailable, Cause: err}
	}
	if written, err := file.Write(plaintext); err != nil || written != len(plaintext) {
		_ = file.Truncate(offset)
		return transfer, &Error{Code: StorageUnavailable, Cause: errors.Join(err, io.ErrShortWrite)}
	}
	if err := file.Sync(); err != nil {
		_ = file.Truncate(offset)
		return transfer, &Error{Code: StorageUnavailable, Cause: err}
	}
	if _, err := s.config.Store.CommitFileTransferChunk(ctx, id, ordinal, offset, offset+int64(len(plaintext)), ciphertextDigest, ciphertextLength, len(plaintext)); err != nil {
		_ = file.Truncate(offset)
		return transfer, &Error{Code: OffsetConflict, Cause: err}
	}
	transfer.CommittedOffset += int64(len(plaintext))
	transfer.CommittedChunks++
	transfer.State = "uploading"
	return transfer, nil
}

func (s *Service) acquire(ctx context.Context) error {
	for {
		s.slotMu.Lock()
		limit := s.config.Policy.Current().MaxConcurrentTransfers
		if s.active < limit {
			s.active++
			s.slotMu.Unlock()
			return nil
		}
		s.slotMu.Unlock()
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func (s *Service) release() { s.slotMu.Lock(); s.active--; s.slotMu.Unlock() }

func (s *Service) Complete(ctx context.Context, id string) (store.FileTransfer, error) {
	requested, err := s.config.Store.FileTransfer(ctx, id)
	if err != nil {
		return store.FileTransfer{}, &Error{Code: InvalidPath, Cause: err}
	}
	lock := s.lock("batch:" + requested.BatchID)
	lock.Lock()
	defer lock.Unlock()
	transfers, err := s.config.Store.FileTransfersByBatch(ctx, requested.BatchID)
	if err != nil {
		return store.FileTransfer{}, &Error{Code: InvalidPath, Cause: err}
	}
	allTerminal := true
	for _, transfer := range transfers {
		if transfer.State != "published" && transfer.State != "pending" && transfer.State != "delivered" {
			allTerminal = false
		}
	}
	if allTerminal {
		return s.config.Store.FileTransfer(ctx, id)
	}
	for _, transfer := range transfers {
		if transfer.CommittedOffset != transfer.Size || transfer.State != "created" && transfer.State != "uploading" {
			return requested, &Error{Code: InvalidSize}
		}
		contentPath := s.partialPath(transfer.ID)
		if _, statErr := os.Stat(contentPath); errors.Is(statErr, os.ErrNotExist) {
			contentPath = s.contentPath(transfer.ID)
		}
		file, openErr := os.Open(contentPath)
		if openErr != nil {
			return requested, &Error{Code: StorageUnavailable, Cause: openErr}
		}
		hash := sha256.New()
		written, copyErr := io.Copy(hash, &contextReader{ctx: ctx, reader: file, canceled: s.cancelSignal(transfer.ID)})
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return requested, classifyIO(errors.Join(copyErr, closeErr))
		}
		if written != transfer.Size || hex.EncodeToString(hash.Sum(nil)) != transfer.SHA256 {
			_ = s.cancelBatchLocked(context.Background(), transfers)
			return requested, &Error{Code: DigestMismatch}
		}
	}
	var renamed []store.FileTransfer
	for _, transfer := range transfers {
		if _, statErr := os.Stat(s.contentPath(transfer.ID)); statErr == nil {
			continue
		}
		//paperboat:allow-source-policy atomic-replacement owner=file-transfer reason=verified-content-commit
		if renameErr := os.Rename(s.partialPath(transfer.ID), s.contentPath(transfer.ID)); renameErr != nil {
			for index := len(renamed) - 1; index >= 0; index-- {
				//paperboat:allow-source-policy atomic-replacement owner=file-transfer reason=batch-commit-rollback
				_ = os.Rename(s.contentPath(renamed[index].ID), s.partialPath(renamed[index].ID))
			}
			return requested, &Error{Code: StorageUnavailable, Cause: renameErr}
		}
		renamed = append(renamed, transfer)
	}
	if err := syncDir(s.config.Root); err != nil {
		return requested, &Error{Code: StorageUnavailable, Cause: err}
	}
	if err := s.config.Store.CompleteFileTransferBatch(ctx, requested.BatchID, s.config.LocalMachineID); err != nil {
		return requested, &Error{Code: StorageUnavailable, Cause: err}
	}
	for _, transfer := range transfers {
		if transfer.DestinationMachineID == s.config.LocalMachineID {
			s.cancels.Delete(transfer.ID)
		}
	}
	return s.config.Store.FileTransfer(ctx, id)
}

func (s *Service) Get(ctx context.Context, id string) (store.FileTransfer, error) {
	return s.config.Store.FileTransfer(ctx, id)
}
func (s *Service) Batch(ctx context.Context, batchID string) ([]store.FileTransfer, error) {
	return s.config.Store.FileTransfersByBatch(ctx, batchID)
}
func (s *Service) List(ctx context.Context, sourceMachineID, userID, sessionID string, limit int) ([]store.FileTransfer, error) {
	return s.config.Store.FileTransfersForSource(ctx, sourceMachineID, userID, sessionID, limit)
}
func (s *Service) Pending(ctx context.Context, clientID, sessionID string, limit int) ([]store.FileTransfer, error) {
	return s.config.Store.PendingFileTransfers(ctx, clientID, sessionID, s.config.Now(), limit)
}
func (s *Service) Receipt(ctx context.Context, id, clientID, resultCode, receiptPath string) error {
	if err := s.config.Store.ReceiptFileTransfer(ctx, id, clientID, resultCode, receiptPath); err != nil {
		return err
	}
	if err := os.Remove(s.contentPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return &Error{Code: StorageUnavailable, Cause: err}
	}
	s.cancels.Delete(id)
	return syncDir(s.config.Root)
}

func (s *Service) ReceiptBatch(ctx context.Context, receipts []store.FileTransferReceipt) error {
	if err := s.config.Store.ReceiptFileTransferBatch(ctx, receipts); err != nil {
		return err
	}
	for _, receipt := range receipts {
		if err := os.Remove(s.contentPath(receipt.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return &Error{Code: StorageUnavailable, Cause: err}
		}
		s.cancels.Delete(receipt.ID)
	}
	return syncDir(s.config.Root)
}
func (s *Service) OpenContent(ctx context.Context, id string) (*os.File, store.FileTransfer, error) {
	transfer, err := s.config.Store.FileTransfer(ctx, id)
	if err != nil {
		return nil, transfer, &Error{Code: InvalidPath, Cause: err}
	}
	if transfer.State != "published" && transfer.State != "pending" && transfer.State != "delivered" {
		return nil, transfer, &Error{Code: InvalidPath}
	}
	file, err := os.Open(s.contentPath(id))
	if err != nil {
		return nil, transfer, &Error{Code: StorageUnavailable, Cause: err}
	}
	return file, transfer, nil
}

func (s *Service) PublishedPath(ctx context.Context, id string) (string, error) {
	transfer, err := s.config.Store.FileTransfer(ctx, id)
	if err != nil {
		return "", &Error{Code: InvalidPath, Cause: err}
	}
	if transfer.DestinationMachineID != s.config.LocalMachineID || transfer.State != "published" {
		return "", &Error{Code: InvalidPath}
	}
	contentPath := s.contentPath(id)
	if s.config.PublishRoot != "" {
		return s.publishToRoot(contentPath, transfer)
	}
	path := s.publishedPath(transfer)
	if err := os.Link(contentPath, path); err != nil && !errors.Is(err, os.ErrExist) {
		return "", &Error{Code: StorageUnavailable, Cause: err}
	}
	contentInfo, contentErr := os.Stat(contentPath)
	info, err := os.Lstat(path)
	if contentErr != nil || err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(contentInfo, info) {
		return "", &Error{Code: StorageUnavailable, Cause: errors.Join(contentErr, err)}
	}
	if err := syncDir(s.config.Root); err != nil {
		return "", &Error{Code: StorageUnavailable, Cause: err}
	}
	return path, nil
}

// ExistingPublishedPath resolves the already-published destination without
// creating or repairing any filesystem entry. Status requests use this path so
// a read-only inspection can report the exact collision-resolved Inbox name.
func (s *Service) ExistingPublishedPath(ctx context.Context, id string) (string, error) {
	transfer, err := s.config.Store.FileTransfer(ctx, id)
	if err != nil {
		return "", &Error{Code: InvalidPath, Cause: err}
	}
	if transfer.DestinationMachineID != s.config.LocalMachineID || transfer.State != "published" {
		return "", &Error{Code: InvalidPath}
	}
	contentInfo, err := os.Stat(s.contentPath(id))
	if err != nil {
		return "", &Error{Code: StorageUnavailable, Cause: err}
	}
	if s.config.PublishRoot == "" {
		path := s.publishedPath(transfer)
		matches, matchErr := publishedFileMatches(contentInfo, path)
		if matchErr != nil {
			return "", &Error{Code: StorageUnavailable, Cause: matchErr}
		}
		if !matches {
			return "", &Error{Code: InvalidPath}
		}
		return path, nil
	}
	root := filepath.Clean(s.config.PublishRoot)
	if !filepath.IsAbs(root) || root != s.config.PublishRoot {
		return "", &Error{Code: StorageUnavailable, Cause: errors.New("publish root is invalid")}
	}
	for index := 1; index <= 10000; index++ {
		path := filepath.Join(root, publishedName(transfer.Basename, index))
		matches, matchErr := publishedFileMatches(contentInfo, path)
		if matchErr != nil {
			return "", &Error{Code: StorageUnavailable, Cause: matchErr}
		}
		if matches {
			return path, nil
		}
	}
	return "", &Error{Code: InvalidPath}
}

func publishedFileMatches(contentInfo os.FileInfo, path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && os.SameFile(contentInfo, info), nil
}

func (s *Service) publishToRoot(contentPath string, transfer store.FileTransfer) (string, error) {
	root := filepath.Clean(s.config.PublishRoot)
	if !filepath.IsAbs(root) || root != s.config.PublishRoot {
		return "", &Error{Code: StorageUnavailable, Cause: errors.New("publish root is invalid")}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", &Error{Code: StorageUnavailable, Cause: err}
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return "", &Error{Code: StorageUnavailable, Cause: err}
	}
	contentInfo, err := os.Stat(contentPath)
	if err != nil {
		return "", &Error{Code: StorageUnavailable, Cause: err}
	}
	for index := 1; index <= 10000; index++ {
		path := filepath.Join(root, publishedName(transfer.Basename, index))
		info, statErr := os.Lstat(path)
		if statErr == nil {
			if info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && os.SameFile(contentInfo, info) {
				return path, nil
			}
			continue
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return "", &Error{Code: StorageUnavailable, Cause: statErr}
		}
		if err := os.Link(contentPath, path); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return "", &Error{Code: StorageUnavailable, Cause: err}
		}
		if err := syncDir(root); err != nil {
			return "", &Error{Code: StorageUnavailable, Cause: err}
		}
		return path, nil
	}
	return "", &Error{Code: StorageUnavailable, Cause: errors.New("inbox name collision limit reached")}
}

func publishedName(basename string, index int) string {
	if index <= 1 {
		return basename
	}
	extension := filepath.Ext(basename)
	stem := strings.TrimSuffix(basename, extension)
	return fmt.Sprintf("%s (%d)%s", stem, index, extension)
}
func (s *Service) Cancel(ctx context.Context, id string) error {
	transfer, err := s.config.Store.FileTransfer(ctx, id)
	if err != nil {
		return err
	}
	lock := s.lock("batch:" + transfer.BatchID)
	lock.Lock()
	defer lock.Unlock()
	transfers, err := s.config.Store.FileTransfersByBatch(ctx, transfer.BatchID)
	if err != nil {
		return err
	}
	return s.cancelBatchLocked(ctx, transfers)
}

func (s *Service) cancelBatch(ctx context.Context, transfers []store.FileTransfer) error {
	if len(transfers) == 0 {
		return nil
	}
	lock := s.lock("batch:" + transfers[0].BatchID)
	lock.Lock()
	defer lock.Unlock()
	return s.cancelBatchLocked(ctx, transfers)
}

func (s *Service) cancelBatchLocked(ctx context.Context, transfers []store.FileTransfer) error {
	var result error
	for _, transfer := range transfers {
		s.signalCancel(transfer.ID)
	}
	if len(transfers) > 0 {
		result = s.config.Store.CancelFileTransferBatch(ctx, transfers[0].BatchID)
	}
	if err := s.waitForWrites(ctx, transfers); err != nil {
		return errors.Join(result, &Error{Code: StorageUnavailable, Cause: err})
	}
	for _, transfer := range transfers {
		for _, path := range []string{s.partialPath(transfer.ID), s.contentPath(transfer.ID), s.publishedPath(transfer)} {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				result = errors.Join(result, err)
			}
		}
		s.cancels.Delete(transfer.ID)
	}
	return errors.Join(result, syncDir(s.config.Root))
}
func (s *Service) partialPath(id string) string { return filepath.Join(s.config.Root, id+".part") }
func (s *Service) contentPath(id string) string { return filepath.Join(s.config.Root, id+".content") }
func (s *Service) publishedPath(transfer store.FileTransfer) string {
	return filepath.Join(s.config.Root, transfer.ID+"-"+transfer.Basename)
}
func (s *Service) lock(id string) *sync.Mutex {
	value, _ := s.locks.LoadOrStore(id, &sync.Mutex{})
	return value.(*sync.Mutex)
}
func (s *Service) cancelSignal(id string) <-chan struct{} {
	value, _ := s.cancels.LoadOrStore(id, &transferCancellation{done: make(chan struct{})})
	return value.(*transferCancellation).done
}
func (s *Service) signalCancel(id string) {
	value, _ := s.cancels.LoadOrStore(id, &transferCancellation{done: make(chan struct{})})
	cancel := value.(*transferCancellation)
	cancel.once.Do(func() { close(cancel.done) })
}
func (s *Service) CancellationSignal(id string) <-chan struct{} { return s.cancelSignal(id) }

func (s *Service) beginWrite(id string) func() {
	write := &transferWrite{done: make(chan struct{})}
	s.writes.Store(id, write)
	return func() {
		close(write.done)
		s.writes.CompareAndDelete(id, write)
	}
}

func (s *Service) waitForWrites(ctx context.Context, transfers []store.FileTransfer) error {
	timeout := s.config.CancellationDrainTimeout
	if timeout <= 0 {
		timeout = cancellationDrainTimeout
	}
	drain, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for _, transfer := range transfers {
		value, ok := s.writes.Load(transfer.ID)
		if !ok {
			continue
		}
		write := value.(*transferWrite)
		select {
		case <-write.done:
		case <-drain.Done():
			return drain.Err()
		}
	}
	return nil
}
func (s *Service) newID(prefix string) (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(s.config.Random, value[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value[:]), nil
}
func validDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}
func validBasename(value string) bool {
	return value != "" && utf8.ValidString(value) && len(value) <= 255 && value == filepath.Base(value) && value != "." && value != ".." && !strings.ContainsAny(value, "/\\\x00")
}

type contextReader struct {
	ctx      context.Context
	reader   io.Reader
	canceled <-chan struct{}
}

func (r *contextReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	case <-r.canceled:
		return 0, context.Canceled
	default:
		return r.reader.Read(p)
	}
}
func classifyIO(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return &Error{Code: StorageUnavailable, Cause: err}
}
func (e *Error) Format(state fmt.State, verb rune) { _, _ = fmt.Fprint(state, e.Error()) }
