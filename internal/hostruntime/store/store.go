package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/store/storesqlc"
	_ "modernc.org/sqlite"
)

const (
	CurrentVersion          = 2
	MaxOperationResultBytes = 64 << 10
)

var (
	ErrIncompatible   = errors.New("store version is incompatible")
	ErrCorrupt        = errors.New("store is corrupt")
	ErrConflict       = errors.New("store state conflict")
	ErrReplayGap      = errors.New("replay gap")
	ErrResultTooLarge = errors.New("operation result is too large")
)

type Config struct {
	Root        string
	FailureHook func(string) error
}
type Store struct {
	db   *sql.DB
	q    *storesqlc.Queries
	hook func(string) error
}

type Session struct {
	ID               string
	Name             string
	CWD              string
	CommandPath      string
	CommandArgs      []string
	CommandEnv       []string
	Columns          uint16
	Rows             uint16
	State            string
	Generation       uint64
	ExitCode         *int
	ExitSignal       string
	ExitedAt         *time.Time
	EarliestSequence uint64
	LatestSequence   uint64
	CreatedAt        time.Time
	UpdatedAt        time.Time
}
type OutputEvent struct {
	Channel       byte
	StartSequence uint64
	EndSequence   uint64
	Data          []byte
}
type GapError struct{ Requested, Earliest, Latest uint64 }

func (e *GapError) Error() string {
	return fmt.Sprintf("%v: requested %d retained [%d,%d)", ErrReplayGap, e.Requested, e.Earliest, e.Latest)
}
func (e *GapError) Unwrap() error { return ErrReplayGap }

type InputDecision struct {
	SessionID    string
	ClientID     string
	AttachmentID string
	Generation   uint64
	InputID      string
	Hash         []byte
	Status       string
	BytesWritten int
	ErrorCode    string
	CreatedAt    time.Time
}
type OperationResult struct {
	OperationID string
	RequestHash []byte
	State       string
	Result      []byte
	ErrorCode   string
	CompletedAt time.Time
	ExpiresAt   time.Time
}

type FileTransfer struct {
	ID                   string    `json:"transfer_id"`
	BatchID              string    `json:"batch_id"`
	SourceMachineID      string    `json:"source_machine_id"`
	DestinationMachineID string    `json:"destination_machine_id"`
	InitiatingUserID     string    `json:"initiating_user_id"`
	SessionID            string    `json:"session_id,omitempty"`
	DeliveryClientID     string    `json:"-"`
	Basename             string    `json:"basename"`
	Size                 int64     `json:"size"`
	SHA256               string    `json:"sha256"`
	CommittedOffset      int64     `json:"committed_offset"`
	CommittedChunks      uint64    `json:"-"`
	State                string    `json:"state"`
	ResultCode           string    `json:"result_code,omitempty"`
	ReceiptPath          string    `json:"receipt_path,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	E2EETransferID       string    `json:"-"`
	TransferGeneration   uint64    `json:"-"`
	FileOrdinal          uint64    `json:"-"`
}

type FileTransferReceipt struct {
	ID         string
	ClientID   string
	ResultCode string
	Path       string
}

func (s *Store) CreateFileTransfers(ctx context.Context, transfers []FileTransfer) error {
	return s.CreateFileTransfersWithinLimits(ctx, transfers, 0, 0)
}

func (s *Store) CreateFileTransfersWithinSpool(ctx context.Context, transfers []FileTransfer, maxSpoolBytes int64) error {
	return s.CreateFileTransfersWithinLimits(ctx, transfers, maxSpoolBytes, 0)
}

func (s *Store) CreateFileTransfersWithinLimits(ctx context.Context, transfers []FileTransfer, maxSpoolBytes int64, maxActiveBatches int) error {
	if len(transfers) < 1 || len(transfers) > 10 {
		return ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if maxActiveBatches > 0 {
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(DISTINCT batch_id) FROM file_transfers WHERE state IN ('created','uploading','pending')`).Scan(&active); err != nil {
			return err
		}
		if active >= maxActiveBatches {
			return ErrConflict
		}
	}
	if maxSpoolBytes > 0 {
		var used int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(size),0) FROM file_transfers WHERE state IN ('created','uploading','pending')`).Scan(&used); err != nil {
			return err
		}
		var incoming int64
		for _, transfer := range transfers {
			incoming += transfer.Size
		}
		if incoming < 0 || used > maxSpoolBytes-incoming {
			return ErrConflict
		}
	}
	for _, transfer := range transfers {
		e2ee := transfer.E2EETransferID != "" || transfer.TransferGeneration != 0
		if transfer.ID == "" || transfer.BatchID == "" || transfer.SourceMachineID == "" || transfer.DestinationMachineID == "" || transfer.InitiatingUserID == "" || transfer.Basename == "" || transfer.Size < 0 || transfer.CommittedOffset != 0 || transfer.CreatedAt.IsZero() || transfer.ExpiresAt.IsZero() || e2ee != (transfer.E2EETransferID != "" && transfer.TransferGeneration > 0) {
			return ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO file_transfers(id,batch_id,source_machine_id,destination_machine_id,initiating_user_id,session_id,delivery_client_id,basename,size,sha256,committed_offset,state,result_code,receipt_path,created_at,expires_at,e2ee_transfer_id,transfer_generation,file_ordinal) VALUES(?,?,?,?,?,?,?,?,?,?,0,'created',NULL,NULL,?,?,?,?,?)`, transfer.ID, transfer.BatchID, transfer.SourceMachineID, transfer.DestinationMachineID, transfer.InitiatingUserID, nullableString(transfer.SessionID), nullableString(transfer.DeliveryClientID), transfer.Basename, transfer.Size, transfer.SHA256, transfer.CreatedAt.UnixNano(), transfer.ExpiresAt.UnixNano(), nullableString(transfer.E2EETransferID), nullableUint64(transfer.TransferGeneration), nullableUint64IfEncrypted(transfer.FileOrdinal, e2ee)); err != nil {
			return classify(err)
		}
	}
	return tx.Commit()
}

func (s *Store) FileTransfer(ctx context.Context, id string) (FileTransfer, error) {
	row, err := s.q.FileTransfer(ctx, id)
	if err != nil {
		return FileTransfer{}, err
	}
	return fileTransferFromSQLC(row), nil
}

func (s *Store) FileTransfersByBatch(ctx context.Context, batchID string) ([]FileTransfer, error) {
	if batchID == "" {
		return nil, ErrConflict
	}
	rows, err := s.q.FileTransfersByBatch(ctx, batchID)
	if err != nil {
		return nil, err
	}
	transfers := make([]FileTransfer, 0, len(rows))
	for _, row := range rows {
		transfers = append(transfers, fileTransferFromSQLC(row))
	}
	if len(transfers) == 0 {
		return nil, ErrConflict
	}
	return transfers, nil
}

func (s *Store) FileTransfersForSource(ctx context.Context, sourceMachineID, userID, sessionID string, limit int) ([]FileTransfer, error) {
	if sourceMachineID == "" || userID == "" {
		return nil, ErrConflict
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := fileTransferSelect + ` WHERE source_machine_id=? AND initiating_user_id=?`
	args := []any{sourceMachineID, userID}
	if sessionID != "" {
		query += ` AND session_id=?`
		args = append(args, sessionID)
	}
	query += ` ORDER BY created_at DESC,id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	transfers := make([]FileTransfer, 0)
	for rows.Next() {
		transfer, scanErr := scanFileTransfer(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		transfers = append(transfers, transfer)
	}
	return transfers, rows.Err()
}

func (s *Store) CommitFileTransferOffset(ctx context.Context, id string, expected, next int64) error {
	if expected < 0 || next < expected {
		return ErrConflict
	}
	result, err := s.db.ExecContext(ctx, `UPDATE file_transfers SET committed_offset=?,state='uploading' WHERE id=? AND committed_offset=? AND state IN ('created','uploading') AND ?<=size`, next, id, expected, next)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrConflict
	}
	return nil
}

func (s *Store) CommitFileTransferChunk(ctx context.Context, id string, ordinal uint64, expectedOffset, nextOffset int64, ciphertextDigest [32]byte, ciphertextLength, plaintextLength int) (bool, error) {
	if id == "" || ordinal > uint64(^uint64(0)>>1) || expectedOffset < 0 || nextOffset < expectedOffset || ciphertextLength < 16 || ciphertextLength > (1<<20)+16 || plaintextLength < 0 || plaintextLength > 1<<20 || nextOffset-expectedOffset != int64(plaintextLength) {
		return false, ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var existingDigest []byte
	var existingCiphertextLength, existingPlaintextLength int
	err = tx.QueryRowContext(ctx, `SELECT ciphertext_sha256,ciphertext_length,plaintext_length FROM file_transfer_chunks WHERE transfer_id=? AND ordinal=?`, id, int64(ordinal)).Scan(&existingDigest, &existingCiphertextLength, &existingPlaintextLength)
	if err == nil {
		if !bytes.Equal(existingDigest, ciphertextDigest[:]) || existingCiphertextLength != ciphertextLength || existingPlaintextLength != plaintextLength {
			return false, ErrConflict
		}
		return true, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE file_transfers SET committed_offset=?,committed_chunks=?,state='uploading' WHERE id=? AND committed_offset=? AND committed_chunks=? AND state IN ('created','uploading') AND ?<=size`, nextOffset, int64(ordinal+1), id, expectedOffset, int64(ordinal), nextOffset)
	if err != nil {
		return false, err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return false, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO file_transfer_chunks(transfer_id,ordinal,ciphertext_sha256,ciphertext_length,plaintext_length) VALUES(?,?,?,?,?)`, id, int64(ordinal), ciphertextDigest[:], ciphertextLength, plaintextLength); err != nil {
		return false, classify(err)
	}
	return false, tx.Commit()
}

func (s *Store) CompleteFileTransfer(ctx context.Context, id, localMachineID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE file_transfers SET state=CASE destination_machine_id WHEN ? THEN 'published' ELSE 'pending' END,result_code=CASE destination_machine_id WHEN ? THEN 'published' ELSE 'pending' END WHERE id=? AND committed_offset=size AND state IN ('created','uploading')`, localMachineID, localMachineID, id)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		transfer, getErr := s.FileTransfer(ctx, id)
		if getErr == nil && (transfer.State == "published" || transfer.State == "pending" || transfer.State == "delivered") {
			return nil
		}
		return ErrConflict
	}
	return nil
}

func (s *Store) CompleteFileTransferBatch(ctx context.Context, batchID, localMachineID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var total, ready int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(CASE WHEN committed_offset=size AND state IN ('created','uploading') THEN 1 ELSE 0 END),0) FROM file_transfers WHERE batch_id=?`, batchID).Scan(&total, &ready); err != nil {
		return err
	}
	if total < 1 || ready != total {
		var terminal int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM file_transfers WHERE batch_id=? AND state IN ('published','pending','delivered')`, batchID).Scan(&terminal); err == nil && terminal == total {
			return nil
		}
		return ErrConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE file_transfers SET state=CASE destination_machine_id WHEN ? THEN 'published' ELSE 'pending' END,result_code=CASE destination_machine_id WHEN ? THEN 'published' ELSE 'pending' END WHERE batch_id=? AND committed_offset=size AND state IN ('created','uploading')`, localMachineID, localMachineID, batchID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if int(changed) != total {
		return ErrConflict
	}
	return tx.Commit()
}

func (s *Store) CancelFileTransferBatch(ctx context.Context, batchID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE file_transfers SET state='canceled',result_code='canceled' WHERE batch_id=? AND state IN ('created','uploading','pending')`, batchID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		var total, canceled int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(CASE WHEN state='canceled' THEN 1 ELSE 0 END),0) FROM file_transfers WHERE batch_id=?`, batchID).Scan(&total, &canceled); err == nil && total > 0 && total == canceled {
			return nil
		}
		return ErrConflict
	}
	return nil
}

func (s *Store) PendingFileTransfers(ctx context.Context, clientID, sessionID string, now time.Time, limit int) ([]FileTransfer, error) {
	if clientID == "" || sessionID == "" || limit < 1 || limit > 10 {
		return nil, ErrConflict
	}
	rows, err := s.q.PendingFileTransfers(ctx, storesqlc.PendingFileTransfersParams{
		DeliveryClientID: nullableSQLString(clientID), SessionID: nullableSQLString(sessionID),
		ExpiresAt: now.UnixNano(), Limit: int64(limit),
	})
	if err != nil {
		return nil, err
	}
	transfers := make([]FileTransfer, 0, len(rows))
	for _, row := range rows {
		transfers = append(transfers, fileTransferFromSQLC(row))
	}
	return transfers, nil
}

func (s *Store) ExpiredFileTransfers(ctx context.Context, now time.Time) ([]FileTransfer, error) {
	rows, err := s.q.ExpiredFileTransfers(ctx, now.UnixNano())
	if err != nil {
		return nil, err
	}
	transfers := make([]FileTransfer, 0, len(rows))
	for _, row := range rows {
		transfers = append(transfers, fileTransferFromSQLC(row))
	}
	return transfers, nil
}

func (s *Store) ExpireFileTransfers(ctx context.Context, transfers []FileTransfer) error {
	if len(transfers) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, transfer := range transfers {
		state, code := "canceled", "canceled"
		if transfer.DeliveryClientID != "" {
			state, code = "failed", "delivery_timeout"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE file_transfers SET state=?,result_code=? WHERE id=? AND expires_at<=? AND state IN ('created','uploading','published','pending')`, state, code, transfer.ID, transfer.ExpiresAt.UnixNano()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ReceiptFileTransfer(ctx context.Context, id, clientID, resultCode, receiptPath string) error {
	state := "failed"
	if resultCode == "stored" {
		state = "delivered"
	} else if resultCode == "" {
		return ErrConflict
	}
	result, err := s.db.ExecContext(ctx, `UPDATE file_transfers SET state=?,result_code=?,receipt_path=? WHERE id=? AND delivery_client_id=? AND (state='pending' OR (state IN ('delivered','failed') AND COALESCE(result_code,'')=? AND COALESCE(receipt_path,'')=?))`, state, resultCode, nullableString(receiptPath), id, clientID, resultCode, receiptPath)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrConflict
	}
	return nil
}

func (s *Store) ReceiptFileTransferBatch(ctx context.Context, receipts []FileTransferReceipt) error {
	if len(receipts) == 0 || len(receipts) > 10 {
		return ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, receipt := range receipts {
		state := "failed"
		if receipt.ResultCode == "stored" {
			state = "delivered"
		} else if receipt.ResultCode == "" || receipt.Path != "" {
			return ErrConflict
		}
		result, err := tx.ExecContext(ctx, `UPDATE file_transfers SET state=?,result_code=?,receipt_path=? WHERE id=? AND delivery_client_id=? AND (state='pending' OR (state IN ('delivered','failed') AND COALESCE(result_code,'')=? AND COALESCE(receipt_path,'')=?))`, state, receipt.ResultCode, nullableString(receipt.Path), receipt.ID, receipt.ClientID, receipt.ResultCode, receipt.Path)
		if err != nil {
			return err
		}
		changed, _ := result.RowsAffected()
		if changed != 1 {
			return ErrConflict
		}
	}
	return tx.Commit()
}

func (s *Store) CancelFileTransfer(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE file_transfers SET state='canceled',result_code='canceled' WHERE id=? AND state IN ('created','uploading','pending')`, id)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		transfer, getErr := s.FileTransfer(ctx, id)
		if getErr == nil && transfer.State == "canceled" {
			return nil
		}
		return ErrConflict
	}
	return nil
}

const fileTransferSelect = `SELECT id,batch_id,source_machine_id,destination_machine_id,initiating_user_id,COALESCE(session_id,''),COALESCE(delivery_client_id,''),basename,size,sha256,committed_offset,state,COALESCE(result_code,''),COALESCE(receipt_path,''),created_at,expires_at FROM file_transfers`

func scanFileTransfer(row scanner) (FileTransfer, error) {
	var transfer FileTransfer
	var created, expires int64
	err := row.Scan(&transfer.ID, &transfer.BatchID, &transfer.SourceMachineID, &transfer.DestinationMachineID, &transfer.InitiatingUserID, &transfer.SessionID, &transfer.DeliveryClientID, &transfer.Basename, &transfer.Size, &transfer.SHA256, &transfer.CommittedOffset, &transfer.State, &transfer.ResultCode, &transfer.ReceiptPath, &created, &expires)
	if err != nil {
		return FileTransfer{}, err
	}
	transfer.CreatedAt, transfer.ExpiresAt = time.Unix(0, created).UTC(), time.Unix(0, expires).UTC()
	return transfer, nil
}

func fileTransferFromSQLC(row storesqlc.FileTransfer) FileTransfer {
	return FileTransfer{
		ID: row.ID, BatchID: row.BatchID, SourceMachineID: row.SourceMachineID,
		DestinationMachineID: row.DestinationMachineID, InitiatingUserID: row.InitiatingUserID,
		SessionID: row.SessionID.String, DeliveryClientID: row.DeliveryClientID.String,
		Basename: row.Basename, Size: row.Size, SHA256: row.Sha256, CommittedOffset: row.CommittedOffset,
		State: row.State, ResultCode: row.ResultCode.String, ReceiptPath: row.ReceiptPath.String,
		CreatedAt: time.Unix(0, row.CreatedAt).UTC(), ExpiresAt: time.Unix(0, row.ExpiresAt).UTC(),
		E2EETransferID: row.E2eeTransferID.String, TransferGeneration: uint64(row.TransferGeneration.Int64), FileOrdinal: uint64(row.FileOrdinal.Int64),
		CommittedChunks: uint64(row.CommittedChunks),
	}
}

func nullableUint64(value uint64) any {
	if value == 0 {
		return nil
	}
	return int64(value)
}

func nullableUint64IfEncrypted(value uint64, encrypted bool) any {
	if !encrypted {
		return nil
	}
	return int64(value)
}

func Open(ctx context.Context, config Config) (*Store, error) {
	if !filepath.IsAbs(config.Root) {
		return nil, ErrCorrupt
	}
	if err := ensureDirectory(config.Root); err != nil {
		return nil, err
	}
	path := filepath.Join(config.Root, "state.db")
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, ErrCorrupt
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	dsnURL := &url.URL{Scheme: "file", Path: sqliteURIPath(path)}
	query := dsnURL.Query()
	// These PRAGMAs are connection-local. Put them in the DSN so every
	// database/sql connection gets the same locking and integrity policy.
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(ON)")
	query.Add("_pragma", "synchronous(FULL)")
	dsnURL.RawQuery = query.Encode()
	dsn := dsnURL.String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Schema validation can issue nested reads while Goose still owns its
	// connection. A single-connection pool deadlocks on Linux/arm64.
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	store := &Store{db: db, q: storesqlc.New(db), hook: config.FailureHook}
	if err := store.configure(ctx); err != nil {
		db.Close()
		return nil, classifyDBError(err)
	}
	if err := store.migrate(ctx); err != nil {
		db.Close()
		return nil, classifyDBError(err)
	}
	if err := validateDatabaseSchema(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	if err := secureStoreFile(path); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.check(ctx); err != nil {
		db.Close()
		return nil, classifyDBError(err)
	}
	return store, nil
}

// sqliteURIPath keeps a Windows volume path in the URI path component. Without
// the leading slash, net/url serializes C: as a URI authority and modernc
// SQLite rejects the resulting file://C:... DSN before it can open state.db.
func sqliteURIPath(path string) string {
	if volume := filepath.VolumeName(path); volume != "" {
		return "/" + strings.ReplaceAll(path, `\`, "/")
	}
	return path
}

func (s *Store) Close() error {
	_, checkpointErr := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return errors.Join(checkpointErr, s.db.Close())
}
func (s *Store) CreateSession(ctx context.Context, session Session) error {
	now := time.Now().UTC()
	if session.CreatedAt.IsZero() {
		session.CreatedAt = now
	}
	if session.UpdatedAt.IsZero() {
		session.UpdatedAt = now
	}
	args, err := json.Marshal(session.CommandArgs)
	if err != nil {
		return err
	}
	environment, err := json.Marshal(session.CommandEnv)
	if err != nil {
		return err
	}
	err = s.q.CreateSession(ctx, storesqlc.CreateSessionParams{
		ID: session.ID, Name: session.Name, Cwd: session.CWD, CommandPath: session.CommandPath,
		CommandArgs: args, CommandEnv: environment, Columns: int64(session.Columns), Rows: int64(session.Rows),
		State: session.State, Generation: int64(session.Generation), ExitCode: nullableInt(session.ExitCode),
		ExitSignal: nullableSQLString(session.ExitSignal), ExitedAt: nullableTimestamp(session.ExitedAt),
		EarliestSequence: int64(session.EarliestSequence), LatestSequence: int64(session.LatestSequence),
		CreatedAt: session.CreatedAt.UnixNano(), UpdatedAt: session.UpdatedAt.UnixNano(),
	})
	return classify(err)
}

func (s *Store) Sessions(ctx context.Context) ([]Session, error) {
	rows, err := s.q.ListSessions(ctx)
	if err != nil {
		return nil, err
	}
	sessions := make([]Session, 0, len(rows))
	for _, row := range rows {
		session, err := sessionFromSQLC(row)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}

func (s *Store) UpdateSession(ctx context.Context, id, expectedState string, next Session) error {
	// Output bounds are owned by AppendOutput and ClearOutput. Updating them
	// here can expose a cursor whose output rows have not committed yet.
	result, err := s.db.ExecContext(ctx, `UPDATE sessions SET cwd=?,columns=?,rows=?,state=?,generation=?,exit_code=?,exit_signal=?,exited_at=?,updated_at=? WHERE id=? AND state=?`, next.CWD, next.Columns, next.Rows, next.State, next.Generation, next.ExitCode, nullableString(next.ExitSignal), nullableTime(next.ExitedAt), time.Now().UTC().UnixNano(), id, expectedState)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrConflict
	}
	return nil
}

func (s *Store) ClearOutput(ctx context.Context, sessionID string, nextSequence uint64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var latest uint64
	if err := tx.QueryRowContext(ctx, `SELECT latest_sequence FROM sessions WHERE id=?`, sessionID).Scan(&latest); err != nil {
		return err
	}
	if latest != nextSequence {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM output_events WHERE session_id=?`, sessionID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET earliest_sequence=?,latest_sequence=?,updated_at=? WHERE id=?`, nextSequence, nextSequence, time.Now().UTC().UnixNano(), sessionID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) OutputBounds(ctx context.Context, sessionID string) (earliest, latest uint64, err error) {
	row, err := s.q.SessionBounds(ctx, sessionID)
	return uint64(row.EarliestSequence), uint64(row.LatestSequence), err
}

// AdvanceOutput drops a persistence tail that has already fallen behind the
// bounded live history. The expected cursor prevents concurrent writers from
// skipping an unseen committed range.
func (s *Store) AdvanceOutput(ctx context.Context, sessionID string, expectedLatest, nextSequence uint64) error {
	if nextSequence < expectedLatest {
		return ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var latest uint64
	if err := tx.QueryRowContext(ctx, `SELECT latest_sequence FROM sessions WHERE id=?`, sessionID).Scan(&latest); err != nil {
		return err
	}
	if latest != expectedLatest {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM output_events WHERE session_id=?`, sessionID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET earliest_sequence=?,latest_sequence=?,updated_at=? WHERE id=?`, nextSequence, nextSequence, time.Now().UTC().UnixNano(), sessionID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	changed, err := s.q.DeleteClosedSession(ctx, id)
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrConflict
	}
	return nil
}

func (s *Store) AppendOutput(ctx context.Context, sessionID string, channel byte, start uint64, data []byte, maxRetained uint64) (OutputEvent, uint64, error) {
	if len(data) == 0 || maxRetained == 0 {
		return OutputEvent{}, 0, ErrConflict
	}
	end := start + uint64(len(data))
	if end < start {
		return OutputEvent{}, 0, ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OutputEvent{}, 0, err
	}
	defer tx.Rollback()
	var latest, earliest uint64
	if err := tx.QueryRowContext(ctx, `SELECT latest_sequence,earliest_sequence FROM sessions WHERE id=?`, sessionID).Scan(&latest, &earliest); err != nil {
		return OutputEvent{}, 0, err
	}
	if latest != start || earliest > latest {
		return OutputEvent{}, 0, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO output_events(session_id,start_sequence,end_sequence,channel,data) VALUES(?,?,?,?,?)`, sessionID, start, end, channel, append([]byte(nil), data...)); err != nil {
		return OutputEvent{}, 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET latest_sequence=?,updated_at=? WHERE id=?`, end, time.Now().UTC().UnixNano(), sessionID); err != nil {
		return OutputEvent{}, 0, err
	}
	// Session bounds are contiguous by construction, so they are the exact
	// retained byte count. Avoid scanning every historical BLOB on each PTY
	// write: that can starve terminal attach behind high-output sessions.
	retained := end - earliest
	for retained > maxRetained {
		var eventStart, eventEnd, size uint64
		if err := tx.QueryRowContext(ctx, `SELECT start_sequence,end_sequence,length(data) FROM output_events WHERE session_id=? ORDER BY start_sequence LIMIT 1`, sessionID).Scan(&eventStart, &eventEnd, &size); err != nil {
			return OutputEvent{}, 0, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM output_events WHERE session_id=? AND start_sequence=?`, sessionID, eventStart); err != nil {
			return OutputEvent{}, 0, err
		}
		retained -= size
		earliest = eventEnd
	}
	if retained == 0 {
		earliest = end
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET earliest_sequence=? WHERE id=?`, earliest, sessionID); err != nil {
		return OutputEvent{}, 0, err
	}
	if s.hook != nil {
		if err := s.hook("append_before_commit"); err != nil {
			return OutputEvent{}, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return OutputEvent{}, 0, err
	}
	if s.hook != nil {
		if err := s.hook("append_after_commit"); err != nil {
			return OutputEvent{}, 0, err
		}
	}
	return OutputEvent{Channel: channel, StartSequence: start, EndSequence: end, Data: append([]byte(nil), data...)}, earliest, nil
}

func (s *Store) Replay(ctx context.Context, sessionID string, from, limit uint64) ([]OutputEvent, uint64, uint64, error) {
	earliest, latest, err := s.OutputBounds(ctx, sessionID)
	if err != nil {
		return nil, 0, 0, err
	}
	if from < earliest {
		return nil, earliest, latest, &GapError{from, earliest, latest}
	}
	if from > latest {
		return nil, earliest, latest, ErrConflict
	}
	rows, err := s.q.ReplayOutput(ctx, storesqlc.ReplayOutputParams{SessionID: sessionID, EndSequence: int64(from)})
	if err != nil {
		return nil, earliest, latest, err
	}
	var events []OutputEvent
	remaining := limit
	for _, row := range rows {
		event := OutputEvent{Channel: byte(row.Channel), StartSequence: uint64(row.StartSequence), EndSequence: uint64(row.EndSequence), Data: row.Data}
		start := max(from, event.StartSequence)
		end := event.EndSequence
		if limit > 0 && end-start > remaining {
			end = start + remaining
		}
		offsetStart := start - event.StartSequence
		offsetEnd := end - event.StartSequence
		if end > start {
			event.StartSequence = start
			event.EndSequence = end
			event.Data = append([]byte(nil), event.Data[offsetStart:offsetEnd]...)
			events = append(events, event)
			if limit > 0 {
				remaining -= end - start
				if remaining == 0 {
					break
				}
			}
		}
	}
	return events, earliest, latest, nil
}

// TrimOutput compacts a session's retained output to maxRetained bytes. It is
// used at startup so a reduced configured history limit takes effect before
// old output is restored into memory or replayed to a newly attached client.
func (s *Store) TrimOutput(ctx context.Context, sessionID string, maxRetained uint64) (uint64, error) {
	if maxRetained == 0 {
		return 0, ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var earliest, latest uint64
	if err := tx.QueryRowContext(ctx, `SELECT earliest_sequence,latest_sequence FROM sessions WHERE id=?`, sessionID).Scan(&earliest, &latest); err != nil {
		return 0, err
	}
	retained := latest - earliest
	for retained > maxRetained {
		var start, end, size uint64
		if err := tx.QueryRowContext(ctx, `SELECT start_sequence,end_sequence,length(data) FROM output_events WHERE session_id=? ORDER BY start_sequence LIMIT 1`, sessionID).Scan(&start, &end, &size); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM output_events WHERE session_id=? AND start_sequence=?`, sessionID, start); err != nil {
			return 0, err
		}
		retained -= size
		earliest = end
	}
	if retained == 0 {
		earliest = latest
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET earliest_sequence=? WHERE id=?`, earliest, sessionID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return earliest, nil
}

func (s *Store) PutInputDecision(ctx context.Context, decision InputDecision) (bool, error) {
	result, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO input_decisions(session_id,client_id,attachment_id,generation,input_id,request_hash,status,bytes_written,error_code,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, decision.SessionID, decision.ClientID, decision.AttachmentID, decision.Generation, decision.InputID, decision.Hash, decision.Status, decision.BytesWritten, nullableString(decision.ErrorCode), decision.CreatedAt.UnixNano())
	if err != nil {
		return false, err
	}
	changed, _ := result.RowsAffected()
	if changed == 1 {
		return true, nil
	}
	var hash []byte
	if err := s.db.QueryRowContext(ctx, `SELECT request_hash FROM input_decisions WHERE session_id=? AND client_id=? AND attachment_id=? AND generation=? AND input_id=?`, decision.SessionID, decision.ClientID, decision.AttachmentID, decision.Generation, decision.InputID).Scan(&hash); err != nil {
		return false, err
	}
	if !bytes.Equal(hash, decision.Hash) {
		return false, ErrConflict
	}
	return false, nil
}

func (s *Store) InputDecisions(ctx context.Context, sessionID string) ([]InputDecision, error) {
	rows, err := s.q.ListInputDecisions(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	decisions := make([]InputDecision, 0, len(rows))
	for _, row := range rows {
		decisions = append(decisions, InputDecision{
			SessionID: row.SessionID, ClientID: row.ClientID, AttachmentID: row.AttachmentID,
			Generation: uint64(row.Generation), InputID: row.InputID, Hash: row.RequestHash,
			Status: row.Status, BytesWritten: int(row.BytesWritten), ErrorCode: row.ErrorCode,
			CreatedAt: time.Unix(0, row.CreatedAt).UTC(),
		})
	}
	return decisions, nil
}

func (s *Store) UpdateInputDecision(ctx context.Context, decision InputDecision) error {
	result, err := s.db.ExecContext(ctx, `UPDATE input_decisions SET status=?,bytes_written=?,error_code=? WHERE session_id=? AND client_id=? AND attachment_id=? AND generation=? AND input_id=? AND request_hash=?`, decision.Status, decision.BytesWritten, nullableString(decision.ErrorCode), decision.SessionID, decision.ClientID, decision.AttachmentID, decision.Generation, decision.InputID, decision.Hash)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return ErrConflict
	}
	return nil
}

func (s *Store) PutOperation(ctx context.Context, operation OperationResult) error {
	_, _, err := s.ReserveOperation(ctx, operation.OperationID, operation.RequestHash, operation.ExpiresAt)
	if err != nil {
		return err
	}
	return s.CompleteOperation(ctx, operation)
}

func (s *Store) ReserveOperation(ctx context.Context, operationID string, requestHash []byte, expiresAt time.Time) (OperationResult, bool, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO operation_results(operation_id,request_hash,state,result,error_code,completed_at,expires_at) VALUES(?,?,'pending',NULL,NULL,NULL,?) ON CONFLICT(operation_id) DO NOTHING`, operationID, requestHash, expiresAt.UnixNano())
	if err != nil {
		return OperationResult{}, false, err
	}
	changed, _ := result.RowsAffected()
	if changed == 1 {
		return OperationResult{OperationID: operationID, RequestHash: append([]byte(nil), requestHash...), State: "pending", ExpiresAt: expiresAt}, true, nil
	}
	existing, err := s.operation(ctx, operationID)
	if err != nil {
		return OperationResult{}, false, err
	}
	if !bytes.Equal(existing.RequestHash, requestHash) {
		return OperationResult{}, false, ErrConflict
	}
	return existing, false, nil
}

func (s *Store) CompleteOperation(ctx context.Context, operation OperationResult) error {
	if len(operation.Result) > MaxOperationResultBytes {
		return ErrResultTooLarge
	}
	const attempts = 20
	for attempt := 0; attempt < attempts; attempt++ {
		result, err := s.db.ExecContext(ctx, `UPDATE operation_results SET state='completed',result=?,error_code=?,completed_at=?,expires_at=? WHERE operation_id=? AND request_hash=? AND state='pending'`, operation.Result, nullableString(operation.ErrorCode), operation.CompletedAt.UnixNano(), operation.ExpiresAt.UnixNano(), operation.OperationID, operation.RequestHash)
		if err != nil {
			if !strings.Contains(err.Error(), "SQLITE_BUSY") && !strings.Contains(err.Error(), "database is locked") {
				return err
			}
			if attempt+1 < attempts {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(50 * time.Millisecond):
				}
				continue
			}
			return err
		}
		changed, _ := result.RowsAffected()
		if changed == 1 {
			return nil
		}
		existing, err := s.operation(ctx, operation.OperationID)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing.RequestHash, operation.RequestHash) {
			return ErrConflict
		}
		if existing.State == "completed" {
			if bytes.Equal(existing.Result, operation.Result) && existing.ErrorCode == operation.ErrorCode {
				return nil
			}
			return ErrConflict
		}
		if attempt+1 < attempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	return ErrConflict
}

func (s *Store) DeleteExpiredOperations(ctx context.Context, now time.Time) error {
	return s.q.DeleteExpiredOperations(ctx, now.UnixNano())
}

func (s *Store) Operations(ctx context.Context, now time.Time, limit int) ([]OperationResult, error) {
	if limit < 1 {
		return nil, ErrConflict
	}
	if err := s.q.DeleteExpiredOperations(ctx, now.UnixNano()); err != nil {
		return nil, err
	}
	// Older helpers persisted terminal replay inside attach outcomes. Discard
	// those oversized payloads without releasing the operation ID for reuse:
	// pending makes a retry uncertain instead of rerunning a mutation.
	if err := s.q.ResetOversizedOperations(ctx, MaxOperationResultBytes); err != nil {
		return nil, err
	}
	rows, err := s.q.ListOperations(ctx, int64(limit))
	if err != nil {
		return nil, err
	}
	operations := make([]OperationResult, 0, len(rows))
	for _, row := range rows {
		operations = append(operations, operationFromSQLC(row.OperationID, row.RequestHash, row.State, row.Result, row.ErrorCode, row.CompletedAt, row.ExpiresAt))
	}
	return operations, nil
}

func (s *Store) OperationsWithPrefix(ctx context.Context, prefix string, now time.Time, limit int) ([]OperationResult, error) {
	return s.operationsByPrefix(ctx, prefix, false, now, limit)
}

func (s *Store) OperationsExcludingPrefix(ctx context.Context, prefix string, now time.Time, limit int) ([]OperationResult, error) {
	return s.operationsByPrefix(ctx, prefix, true, now, limit)
}

func (s *Store) operationsByPrefix(ctx context.Context, prefix string, exclude bool, now time.Time, limit int) ([]OperationResult, error) {
	if prefix == "" || limit < 1 || limit > 1<<20 {
		return nil, ErrConflict
	}
	if err := s.DeleteExpiredOperations(ctx, now); err != nil {
		return nil, err
	}
	comparison := "LIKE"
	if exclude {
		comparison = "NOT LIKE"
	}
	query := `SELECT operation_id,request_hash,state,result,COALESCE(error_code,''),completed_at,expires_at FROM operation_results WHERE operation_id ` + comparison + ` ? ESCAPE '\' ORDER BY CASE state WHEN 'pending' THEN 0 ELSE 1 END,completed_at ASC LIMIT ?`
	rows, err := s.db.QueryContext(ctx, query, escapeLike(prefix)+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	operations := make([]OperationResult, 0)
	for rows.Next() {
		var operationID, state, errorCode string
		var requestHash, result []byte
		var completed sql.NullInt64
		var expires int64
		if err := rows.Scan(&operationID, &requestHash, &state, &result, &errorCode, &completed, &expires); err != nil {
			return nil, err
		}
		operations = append(operations, operationFromSQLC(operationID, requestHash, state, result, errorCode, completed, expires))
	}
	return operations, rows.Err()
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}

func (s *Store) operation(ctx context.Context, operationID string) (OperationResult, error) {
	row, err := s.q.GetOperation(ctx, operationID)
	if err != nil {
		return OperationResult{}, err
	}
	return operationFromSQLC(row.OperationID, row.RequestHash, row.State, row.Result, row.ErrorCode, row.CompletedAt, row.ExpiresAt), nil
}

func (s *Store) configure(ctx context.Context) error {
	for _, statement := range []string{"PRAGMA foreign_keys=ON", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA busy_timeout=5000"} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) migrate(ctx context.Context) error {
	return migrateDatabase(ctx, s.db, s.hook)
}
func (s *Store) check(ctx context.Context) error {
	var result string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("%w: %s", ErrCorrupt, result)
	}
	return nil
}

type scanner interface{ Scan(...any) error }

func operationFromSQLC(operationID string, requestHash []byte, state string, result []byte, errorCode string, completed sql.NullInt64, expires int64) OperationResult {
	operation := OperationResult{OperationID: operationID, RequestHash: requestHash, State: state, Result: result, ErrorCode: errorCode}
	if completed.Valid {
		operation.CompletedAt = time.Unix(0, completed.Int64).UTC()
	}
	operation.ExpiresAt = time.Unix(0, expires).UTC()
	return operation
}

func sessionFromSQLC(row storesqlc.ListSessionsRow) (Session, error) {
	session := Session{
		ID: row.ID, Name: row.Name, CWD: row.Cwd, CommandPath: row.CommandPath,
		Columns: uint16(row.Columns), Rows: uint16(row.Rows), State: row.State,
		Generation: uint64(row.Generation), ExitSignal: row.ExitSignal,
		EarliestSequence: uint64(row.EarliestSequence), LatestSequence: uint64(row.LatestSequence),
		CreatedAt: time.Unix(0, row.CreatedAt).UTC(), UpdatedAt: time.Unix(0, row.UpdatedAt).UTC(),
	}
	if err := json.Unmarshal(row.CommandArgs, &session.CommandArgs); err != nil {
		return Session{}, fmt.Errorf("%w: command args", ErrCorrupt)
	}
	if err := json.Unmarshal(row.CommandEnv, &session.CommandEnv); err != nil {
		return Session{}, fmt.Errorf("%w: command environment", ErrCorrupt)
	}
	if row.ExitCode.Valid {
		value := int(row.ExitCode.Int64)
		session.ExitCode = &value
	}
	if row.ExitedAt.Valid {
		value := time.Unix(0, row.ExitedAt.Int64).UTC()
		session.ExitedAt = &value
	}
	return session, nil
}

func nullableInt(value *int) sql.NullInt64 {
	if value == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*value), Valid: true}
}

func nullableSQLString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

func nullableTimestamp(value *time.Time) sql.NullInt64 {
	if value == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: value.UnixNano(), Valid: true}
}
func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UnixNano()
}
func classify(err error) error {
	if err == nil {
		return nil
	}
	return err
}

func classifyDBError(err error) error {
	if err == nil {
		return nil
	}
	var sqliteError interface{ Code() int }
	if errors.As(err, &sqliteError) {
		code := sqliteError.Code() & 0xff
		if code == 11 || code == 26 {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
	}
	return err
}
func ensureDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrCorrupt
	}
	return secureStoreDirectory(path)
}
