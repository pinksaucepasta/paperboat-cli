package filetransfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

type encryptedResource struct {
	TransferID     string    `json:"transfer_id"`
	CommittedChunk uint64    `json:"committed_chunk"`
	State          string    `json:"state"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type encryptedCreateResult struct {
	BatchID   string              `json:"batch_id"`
	Resources []encryptedResource `json:"resources"`
}

type encryptedCompleteResult struct {
	Resource         encryptedResource `json:"resource"`
	EncryptedReceipt string            `json:"encrypted_receipt"`
	ReceiptDigest    string            `json:"receipt_digest"`
}

func (c *Client) SendEncryptedBatch(ctx context.Context, batchID, sessionID string, sources []Source, generation uint64, prepared PreparedKey) (Batch, error) {
	if c == nil || ctx == nil || batchID == "" || generation == 0 || !prepared.Material.Valid() || !validPreparedPeerContext(prepared.Context, c.binding) || len(sources) == 0 || len(sources) > 10 {
		return Batch{}, errors.New("invalid encrypted file transfer")
	}
	if prepared.Direct != nil {
		transport, err := newDirectFallbackTransport(prepared.Direct, c.HTTPClient.Transport)
		if err != nil {
			return Batch{}, err
		}
		directClient := NewClient(c.Endpoint, c.currentAuth(), c.binding, &http.Client{Transport: transport, Timeout: c.HTTPClient.Timeout})
		directClient.RefreshAuth = c.RefreshAuth
		directClient.MaxConcurrent = c.MaxConcurrent
		directClient.DeliveryTimeout = c.DeliveryTimeout
		c = directClient
	}
	manifest := transfercrypto.Manifest{BatchID: batchID, Files: make([]transfercrypto.ManifestFile, len(sources))}
	readers := make([]*EncryptedChunkReader, len(sources))
	defer func() {
		for _, reader := range readers {
			if reader != nil {
				_ = reader.Close()
			}
		}
	}()
	for index, source := range sources {
		if source.Reader == nil || source.Size < 0 {
			return Batch{}, errors.New("invalid encrypted file source")
		}
		chunks := uint64(source.Size) / uint64(transfercrypto.ChunkSize)
		if source.Size%int64(transfercrypto.ChunkSize) != 0 || chunks == 0 {
			chunks++
		}
		resourceID := batchID + "." + strconv.Itoa(index)
		manifest.Files[index] = transfercrypto.ManifestFile{TransferID: resourceID, FileOrdinal: uint64(index), Name: source.Basename, RelativeDestination: "Paperboat Inbox/" + source.Basename, Mode: 0o600, Size: uint64(source.Size), PlaintextSHA256: source.SHA256, ChunkCount: chunks}
		chunkContext := chunkContextFromPeer(prepared.Context, batchID, generation, uint64(index))
		reader, err := NewEncryptedChunkReader(source, prepared.Material, chunkContext)
		if err != nil {
			return Batch{}, err
		}
		readers[index] = reader
	}
	manifestCiphertext, err := transfercrypto.EncryptManifest(prepared.Material, recordContextFromPeer(prepared.Context, batchID, generation), manifest)
	if err != nil {
		return Batch{}, err
	}
	manifestDigest := sha256.Sum256(manifestCiphertext)
	payload, err := json.Marshal(map[string]any{
		"batch_id": batchID, "source_machine_id": c.binding.SourceMachineID, "destination_machine_id": c.binding.DestinationMachineID, "initiating_user_id": c.binding.InitiatingUserID, "session_id": sessionID,
		"e2ee": map[string]any{"version": 1, "transfer_id": batchID, "transfer_generation": generation, "encrypted_manifest": base64.RawURLEncoding.EncodeToString(manifestCiphertext), "manifest_digest": hex.EncodeToString(manifestDigest[:])},
	})
	if err != nil {
		return Batch{}, err
	}
	var created encryptedCreateResult
	if err := c.retryJSONRequest(ctx, http.MethodPost, c.Endpoint, operationID("create", batchID), "application/json", 0, payload, &created); err != nil {
		return Batch{}, err
	}
	if created.BatchID != batchID || len(created.Resources) != len(sources) {
		return Batch{}, errors.New("encrypted transfer create returned invalid resources")
	}
	for index := range sources {
		if created.Resources[index].TransferID != manifest.Files[index].TransferID {
			return Batch{}, errors.New("encrypted transfer resource identity mismatch")
		}
		if err := c.uploadEncrypted(ctx, created.Resources[index], readers[index], manifest.Files[index].ChunkCount); err != nil {
			c.cancelEncryptedBatch(created.Resources)
			return Batch{}, err
		}
	}
	var completed encryptedCompleteResult
	if err := c.retryJSONRequest(ctx, http.MethodPost, c.Endpoint+"/"+created.Resources[0].TransferID+"/complete", operationID("complete", batchID), "", 0, nil, &completed); err != nil {
		return Batch{}, err
	}
	receiptCiphertext, err := base64.RawURLEncoding.Strict().DecodeString(completed.EncryptedReceipt)
	digest := sha256.Sum256(receiptCiphertext)
	if err != nil || base64.RawURLEncoding.EncodeToString(receiptCiphertext) != completed.EncryptedReceipt || hex.EncodeToString(digest[:]) != completed.ReceiptDigest {
		return Batch{}, errors.New("encrypted transfer receipt encoding is invalid")
	}
	receipt, err := transfercrypto.DecryptFinalReceipt(prepared.Material, recordContextFromPeer(prepared.Context, batchID, generation), receiptCiphertext)
	manifestHash, hashErr := manifest.Hash()
	if err != nil || hashErr != nil || receipt.ManifestHash != manifestHash || len(receipt.Files) != len(sources) {
		return Batch{}, errors.New("encrypted transfer receipt authentication failed")
	}
	batch := Batch{BatchID: batchID, Transfers: make([]Manifest, len(sources)), Paths: make([]string, len(sources))}
	for index, file := range receipt.Files {
		if file.FileOrdinal != uint64(index) || file.Result != transfercrypto.CollisionOriginal && file.Result != transfercrypto.CollisionRenamed || file.RelativePath == "" {
			return Batch{}, errors.New("encrypted transfer receipt is invalid")
		}
		batch.Transfers[index] = Manifest{TransferID: manifest.Files[index].TransferID, BatchID: batchID, SourceMachineID: c.binding.SourceMachineID, DestinationMachineID: c.binding.DestinationMachineID, InitiatingUserID: c.binding.InitiatingUserID, SessionID: sessionID, Basename: sources[index].Basename, Size: sources[index].Size, SHA256: hex.EncodeToString(sources[index].SHA256[:]), CommittedOffset: sources[index].Size, State: "delivered", ResultCode: "published", ReceiptPath: file.RelativePath}
		batch.Paths[index] = file.RelativePath
	}
	acknowledgement, err := json.Marshal(map[string]string{"receipt_digest": completed.ReceiptDigest})
	if err != nil {
		return Batch{}, err
	}
	if err := c.retryJSONRequest(ctx, http.MethodPost, c.Endpoint+"/"+created.Resources[0].TransferID+"/receipt", operationID("receipt", batchID), "application/json", 0, acknowledgement, nil); err != nil {
		return Batch{}, err
	}
	return batch, nil
}

func (c *Client) uploadEncrypted(ctx context.Context, resource encryptedResource, reader *EncryptedChunkReader, chunkCount uint64) error {
	for uncertain := 0; uncertain < 4; uncertain++ {
		current, err := c.encryptedStatus(ctx, resource.TransferID)
		if err != nil {
			if waitErr := waitOperationRetry(ctx, uncertain); waitErr != nil {
				return errors.Join(err, waitErr)
			}
			continue
		}
		if current.CommittedChunk > chunkCount {
			return errors.New("host returned invalid committed chunk ordinal")
		}
		if current.CommittedChunk == chunkCount {
			return nil
		}
		for ordinal := current.CommittedChunk; ordinal < chunkCount; ordinal++ {
			ciphertext, _, readErr := reader.ReadChunk(ordinal)
			if readErr != nil {
				return readErr
			}
			response, requestErr := c.request(ctx, http.MethodPut, c.Endpoint+"/"+resource.TransferID+"/chunks/"+strconv.FormatUint(ordinal, 10), operationID("chunk", resource.TransferID+":"+strconv.FormatUint(ordinal, 10)), "application/octet-stream", 0, bytes.NewReader(ciphertext))
			clear(ciphertext)
			if response != nil {
				_ = response.Body.Close()
			}
			if requestErr != nil {
				break
			}
			if ordinal+1 == chunkCount {
				return nil
			}
		}
	}
	return errors.New("encrypted file transfer did not commit all chunks")
}

func (c *Client) encryptedStatus(ctx context.Context, id string) (encryptedResource, error) {
	manifest, err := c.Status(ctx, id)
	if err != nil {
		return encryptedResource{}, err
	}
	return encryptedResource{TransferID: manifest.TransferID, CommittedChunk: manifest.CommittedChunk, State: manifest.State, ExpiresAt: manifest.ExpiresAt}, nil
}

func (c *Client) cancelEncryptedBatch(resources []encryptedResource) {
	ctx, cancel := context.WithTimeout(context.Background(), operationRecoveryWindow)
	defer cancel()
	for _, resource := range resources {
		_ = c.Cancel(ctx, resource.TransferID)
	}
}

func validPreparedPeerContext(value peercontext.Context, binding Binding) bool {
	if value.AccountID != binding.InitiatingUserID || value.MachineID != binding.DestinationMachineID || value.Consumer != "file_transfer_key" || value.OperationID == "" {
		return false
	}
	_, err := value.MarshalBinary()
	return err == nil
}

func chunkContextFromPeer(peer peercontext.Context, transferID string, generation, fileOrdinal uint64) transfercrypto.ChunkContext {
	return transfercrypto.ChunkContext{AccountID: peer.AccountID, DeviceID: peer.DeviceID, MachineID: peer.MachineID, InitiatorCertificateHash: peer.InitiatorCertificateHash, ResponderCertificateHash: peer.ResponderCertificateHash, OperationID: peer.OperationID, TransferID: transferID, Direction: transfercrypto.DirectionToMachine, TransferGeneration: generation, FileOrdinal: fileOrdinal}
}

func recordContextFromPeer(peer peercontext.Context, transferID string, generation uint64) transfercrypto.RecordContext {
	return transfercrypto.RecordContext{AccountID: peer.AccountID, DeviceID: peer.DeviceID, MachineID: peer.MachineID, InitiatorCertificateHash: peer.InitiatorCertificateHash, ResponderCertificateHash: peer.ResponderCertificateHash, OperationID: peer.OperationID, TransferID: transferID, Direction: transfercrypto.DirectionToMachine, TransferGeneration: generation}
}
