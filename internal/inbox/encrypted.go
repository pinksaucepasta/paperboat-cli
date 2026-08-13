package inbox

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

type encryptedStage struct {
	file     transfercrypto.ManifestFile
	tempPath string
	path     string
	result   transfercrypto.CollisionResult
	prior    bool
}

func (i *Inbox) DeliverEncrypted(ctx context.Context, batch filetransfer.EncryptedPendingBatch) ([]string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.config.Encrypted == nil || i.config.Keys == nil || batch.TransferID == "" || batch.TransferGeneration == 0 || batch.ExpiresAt.IsZero() || len(batch.Resources) == 0 {
		return nil, errors.New("invalid encrypted inbox delivery")
	}
	binding := transfercrypto.KeyControlBinding{OperationID: filetransfer.KeyOperationID(batch.TransferID), TransferID: batch.TransferID, Generation: batch.TransferGeneration, ExpiresAt: batch.ExpiresAt.UTC()}
	prepared, err := i.config.Keys.Receive(ctx, i.config.Target, binding)
	if err != nil {
		return nil, err
	}
	defer prepared.Close()
	defer prepared.Material.Destroy()
	client := i.config.Encrypted
	if prepared.Direct != nil {
		base, ok := i.config.Client.(*filetransfer.Client)
		if !ok {
			return nil, errors.New("encrypted inbox direct transport is unavailable")
		}
		direct := base.WithTransport(prepared.Direct)
		if direct == nil {
			return nil, errors.New("encrypted inbox direct transport is unavailable")
		}
		client = direct
	}
	record := reverseRecordContext(prepared.Context, batch.TransferID, batch.TransferGeneration)
	envelope, err := client.EncryptedManifest(ctx, batch, prepared.Material, record)
	if err != nil {
		return nil, err
	}
	manifestHash, err := envelope.Manifest.Hash()
	if err != nil {
		return nil, err
	}
	root := i.config.Path
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, storageError(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, storageError(err)
	}
	journal, err := loadJournal(root)
	if err != nil {
		return nil, storageError(err)
	}
	stages := make([]encryptedStage, len(envelope.Manifest.Files))
	for index, file := range envelope.Manifest.Files {
		if file.FileOrdinal != uint64(index) || file.TransferID != batch.Resources[index].TransferID || file.RelativeDestination != "Paperboat Inbox/"+file.Name {
			return nil, errors.New("encrypted manifest destination is invalid")
		}
		stage := encryptedStage{file: file, tempPath: filepath.Join(root, ".paperboat-transfer-"+file.TransferID+".part")}
		digest := hex.EncodeToString(file.PlaintextSHA256[:])
		if prior, ok := journal.Entries[file.TransferID]; ok {
			name := strings.TrimPrefix(filepath.ToSlash(prior.Path), "Paperboat Inbox/")
			if prior.Digest != digest || name == prior.Path || filepath.Base(name) != name {
				return nil, errors.New("digest_mismatch")
			}
			finalPath := filepath.Join(root, filepath.FromSlash(name))
			if info, statErr := os.Lstat(finalPath); statErr == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && uint64(info.Size()) == file.Size {
				matches, verifyErr := fileDigestMatches(finalPath, digest)
				if verifyErr != nil || !matches {
					return nil, errors.Join(errors.New("digest_mismatch"), verifyErr)
				}
				stage.path, stage.prior = prior.Path, true
				if filepath.Base(finalPath) == localBasename(file.Name, runtime.GOOS) {
					stage.result = transfercrypto.CollisionOriginal
				} else {
					stage.result = transfercrypto.CollisionRenamed
				}
				stages[index] = stage
				continue
			}
		}
		if err := i.stageEncryptedFile(ctx, client, prepared, batch, file, stage.tempPath); err != nil {
			return nil, err
		}
		stages[index] = stage
	}

	created := make([]string, 0, len(stages))
	rollback := func() {
		for _, path := range created {
			_ = os.Remove(path)
		}
	}
	for index := range stages {
		stage := &stages[index]
		if stage.prior {
			continue
		}
		name, err := availableName(root, localBasename(stage.file.Name, runtime.GOOS))
		if err != nil {
			rollback()
			return nil, storageError(err)
		}
		finalPath := filepath.Join(root, filepath.FromSlash(name))
		if err := os.Link(stage.tempPath, finalPath); err != nil {
			rollback()
			return nil, storageError(err)
		}
		created = append(created, finalPath)
		stage.path = filepath.ToSlash(filepath.Join("Paperboat Inbox", name))
		stage.result = transfercrypto.CollisionOriginal
		if name != localBasename(stage.file.Name, runtime.GOOS) {
			stage.result = transfercrypto.CollisionRenamed
		}
	}
	if err := syncDir(root); err != nil {
		rollback()
		return nil, storageError(err)
	}
	for _, stage := range stages {
		journal.Entries[stage.file.TransferID] = receipt{Digest: hex.EncodeToString(stage.file.PlaintextSHA256[:]), Path: stage.path, At: i.configNow()}
	}
	boundJournal(&journal)
	if err := saveJournal(root, journal); err != nil {
		rollback()
		return nil, storageError(err)
	}
	receiptRecord := transfercrypto.FinalReceipt{ManifestHash: manifestHash, Files: make([]transfercrypto.ReceiptFile, len(stages))}
	paths := make([]string, len(stages))
	for index, stage := range stages {
		receiptRecord.Files[index] = transfercrypto.ReceiptFile{FileOrdinal: stage.file.FileOrdinal, Result: stage.result, RelativePath: stage.path}
		paths[index] = stage.path
	}
	ciphertext, err := transfercrypto.EncryptFinalReceipt(prepared.Material, record, receiptRecord)
	if err != nil {
		return nil, err
	}
	if err := client.EncryptedReceipt(ctx, batch.Resources[0].TransferID, ciphertext); err != nil {
		clear(ciphertext)
		return nil, err
	}
	clear(ciphertext)
	for _, stage := range stages {
		if !stage.prior {
			_ = os.Remove(stage.tempPath)
		}
	}
	if err := syncDir(root); err != nil {
		return nil, storageError(err)
	}
	if err := i.config.Keys.Erase(batch.TransferID); err != nil {
		return nil, err
	}
	return paths, nil
}

func (i *Inbox) stageEncryptedFile(ctx context.Context, client EncryptedClient, prepared filetransfer.PreparedKey, batch filetransfer.EncryptedPendingBatch, expected transfercrypto.ManifestFile, tempPath string) error {
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return storageError(err)
	}
	defer file.Close()
	chunkContext := reverseChunkContext(prepared.Context, batch.TransferID, batch.TransferGeneration, expected.FileOrdinal)
	writer, ordinal, err := filetransfer.NewResumingEncryptedChunkWriter(file, prepared.Material, chunkContext, expected)
	if err != nil {
		return err
	}
	defer writer.Close()
	for ; ordinal < expected.ChunkCount; ordinal++ {
		ciphertext, err := client.EncryptedChunk(ctx, expected.TransferID, ordinal)
		if err != nil {
			return err
		}
		err = writer.WriteChunk(ciphertext)
		clear(ciphertext)
		if err != nil {
			_ = file.Truncate(int64(ordinal) * int64(transfercrypto.ChunkSize))
			return err
		}
		if err := file.Sync(); err != nil {
			return storageError(err)
		}
	}
	if err := writer.Complete(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	return file.Sync()
}

func reverseRecordContext(peer peercontext.Context, transferID string, generation uint64) transfercrypto.RecordContext {
	return transfercrypto.RecordContext{AccountID: peer.AccountID, DeviceID: peer.DeviceID, MachineID: peer.MachineID, InitiatorCertificateHash: peer.InitiatorCertificateHash, ResponderCertificateHash: peer.ResponderCertificateHash, OperationID: peer.OperationID, TransferID: transferID, Direction: transfercrypto.DirectionFromMachine, TransferGeneration: generation}
}

func reverseChunkContext(peer peercontext.Context, transferID string, generation, ordinal uint64) transfercrypto.ChunkContext {
	return transfercrypto.ChunkContext{AccountID: peer.AccountID, DeviceID: peer.DeviceID, MachineID: peer.MachineID, InitiatorCertificateHash: peer.InitiatorCertificateHash, ResponderCertificateHash: peer.ResponderCertificateHash, OperationID: peer.OperationID, TransferID: transferID, Direction: transfercrypto.DirectionFromMachine, TransferGeneration: generation, FileOrdinal: ordinal}
}

func (i *Inbox) configNow() time.Time { return time.Now().UTC() }
