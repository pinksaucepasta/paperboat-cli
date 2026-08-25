package filetransfer

import (
	"context"
	"errors"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/diagnosticlog"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
	"github.com/pinksaucepasta/paperboat/internal/resolver"
)

type EncryptedUploader struct {
	Client     *Client
	Keys       *KeyCoordinator
	Target     resolver.ConnectInfo
	Retention  time.Duration
	Generation uint64
	// CleanupWarning reports a local sender-key cleanup failure after the host
	// has durably delivered and acknowledged the batch. The callback must not
	// reinterpret that irreversible delivery as a failed upload.
	CleanupWarning func(error)
}

func (u *EncryptedUploader) SendBatch(ctx context.Context, batchID, sessionID string, sources []Source) (Batch, error) {
	if u == nil || u.Client == nil || u.Keys == nil || ctx == nil || batchID == "" {
		return Batch{}, errors.New("encrypted file uploader is unavailable")
	}
	generation := u.Generation
	if generation == 0 {
		generation = 1
	}
	retention := u.Retention
	if retention <= 0 || retention > 7*24*time.Hour {
		retention = 7 * 24 * time.Hour
	}
	binding := transfercrypto.KeyControlBinding{OperationID: KeyOperationID(batchID), TransferID: batchID, Generation: generation, ExpiresAt: time.Now().UTC().Truncate(time.Second).Add(retention)}
	prepared, err := u.Keys.Prepare(ctx, u.Target, binding)
	if err != nil {
		return Batch{}, err
	}
	defer prepared.Close()
	defer prepared.Material.Destroy()
	batch, err := u.Client.SendEncryptedBatch(ctx, batchID, sessionID, sources, generation, prepared)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			_ = u.Keys.Erase(batchID)
		}
		return Batch{}, err
	}
	if err := u.Keys.Erase(batchID); err != nil {
		diagnosticlog.TryInfo("delivered file transfer sender-key cleanup failed", "batch_id", batchID, "error", err)
		if u.CleanupWarning != nil {
			u.CleanupWarning(err)
		}
	}
	return batch, nil
}
