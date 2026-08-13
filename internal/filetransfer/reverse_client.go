package filetransfer

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

type EncryptedPendingBatch struct {
	TransferID         string
	TransferGeneration uint64
	State              string
	ExpiresAt          time.Time
	Resources          []EncryptedResource
}

type EncryptedResource struct {
	TransferID     string
	CommittedChunk uint64
	State          string
	ExpiresAt      time.Time
}

type EncryptedManifest struct {
	Manifest  transfercrypto.Manifest
	Resources []EncryptedResource
}

type encryptedPendingDocument struct {
	TransferID         string              `json:"transfer_id"`
	TransferGeneration uint64              `json:"transfer_generation"`
	State              string              `json:"state"`
	ExpiresAt          time.Time           `json:"expires_at"`
	Resources          []encryptedResource `json:"resources"`
}

func (c *Client) PendingEncrypted(ctx context.Context, sessionID string, waitSeconds int) ([]EncryptedPendingBatch, error) {
	if sessionID == "" || waitSeconds < 0 || waitSeconds > 30 {
		return nil, errors.New("invalid encrypted pending transfer request")
	}
	target := c.Endpoint + "/pending?session_id=" + url.QueryEscape(sessionID) + "&wait_seconds=" + strconv.Itoa(waitSeconds)
	var response struct {
		Transfers []json.RawMessage `json:"transfers"`
	}
	if err := c.jsonRequest(ctx, http.MethodGet, target, operationID("pending-encrypted", sessionID), "", 0, nil, &response); err != nil {
		return nil, err
	}
	result := make([]EncryptedPendingBatch, 0, len(response.Transfers))
	for _, raw := range response.Transfers {
		var document encryptedPendingDocument
		if err := json.Unmarshal(raw, &document); err != nil {
			return nil, errors.New("invalid encrypted pending transfer response")
		}
		if document.TransferGeneration == 0 {
			continue
		}
		if document.TransferID == "" || document.State != "pending" || document.ExpiresAt.IsZero() || len(document.Resources) == 0 || len(document.Resources) > 10 {
			return nil, errors.New("invalid encrypted pending transfer batch")
		}
		batch := EncryptedPendingBatch{TransferID: document.TransferID, TransferGeneration: document.TransferGeneration, State: document.State, ExpiresAt: document.ExpiresAt, Resources: make([]EncryptedResource, len(document.Resources))}
		for index, resource := range document.Resources {
			if resource.TransferID == "" || resource.State != "pending" || resource.ExpiresAt.IsZero() {
				return nil, errors.New("invalid encrypted pending transfer resource")
			}
			batch.Resources[index] = EncryptedResource(resource)
		}
		result = append(result, batch)
	}
	return result, nil
}

func (c *Client) EncryptedManifest(ctx context.Context, batch EncryptedPendingBatch, material transfercrypto.KeyMaterial, record transfercrypto.RecordContext) (EncryptedManifest, error) {
	if batch.TransferID == "" || batch.TransferGeneration == 0 || len(batch.Resources) == 0 || !material.Valid() || record.TransferID != batch.TransferID || record.TransferGeneration != batch.TransferGeneration || record.Direction != transfercrypto.DirectionFromMachine {
		return EncryptedManifest{}, errors.New("invalid encrypted manifest request")
	}
	var response struct {
		TransferID         string              `json:"transfer_id"`
		TransferGeneration uint64              `json:"transfer_generation"`
		EncryptedManifest  string              `json:"encrypted_manifest"`
		ManifestDigest     string              `json:"manifest_digest"`
		Resources          []encryptedResource `json:"resources"`
	}
	resourceID := batch.Resources[0].TransferID
	if err := c.retryJSONRequest(ctx, http.MethodGet, c.Endpoint+"/"+resourceID+"/e2ee-manifest", operationID("encrypted-manifest", batch.TransferID), "", 0, nil, &response); err != nil {
		return EncryptedManifest{}, err
	}
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(response.EncryptedManifest)
	if err != nil || base64.RawURLEncoding.EncodeToString(ciphertext) != response.EncryptedManifest || response.TransferID != batch.TransferID || response.TransferGeneration != batch.TransferGeneration || len(response.Resources) != len(batch.Resources) {
		return EncryptedManifest{}, errors.New("invalid encrypted manifest envelope")
	}
	digest := sha256.Sum256(ciphertext)
	if response.ManifestDigest != hex.EncodeToString(digest[:]) {
		return EncryptedManifest{}, errors.New("encrypted manifest digest mismatch")
	}
	manifest, err := transfercrypto.DecryptManifest(material, record, ciphertext)
	if err != nil || manifest.BatchID != batch.TransferID || len(manifest.Files) != len(batch.Resources) {
		return EncryptedManifest{}, errors.New("encrypted manifest authentication failed")
	}
	resources := make([]EncryptedResource, len(response.Resources))
	for index, resource := range response.Resources {
		if resource.TransferID != manifest.Files[index].TransferID || resource.TransferID != batch.Resources[index].TransferID {
			return EncryptedManifest{}, errors.New("encrypted manifest resource identity mismatch")
		}
		resources[index] = EncryptedResource(resource)
	}
	return EncryptedManifest{Manifest: manifest, Resources: resources}, nil
}

func (c *Client) EncryptedChunk(ctx context.Context, resourceID string, ordinal uint64) ([]byte, error) {
	if resourceID == "" {
		return nil, errors.New("invalid encrypted chunk request")
	}
	response, err := c.request(ctx, http.MethodGet, c.Endpoint+"/"+resourceID+"/chunks/"+strconv.FormatUint(ordinal, 10), operationID("encrypted-chunk", resourceID+":"+strconv.FormatUint(ordinal, 10)), "", 0, nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/octet-stream" || response.ContentLength > transfercrypto.ChunkSize+16 {
		return nil, errors.New("invalid encrypted chunk response")
	}
	ciphertext, err := io.ReadAll(io.LimitReader(response.Body, transfercrypto.ChunkSize+17))
	if err != nil || len(ciphertext) < 16 || len(ciphertext) > transfercrypto.ChunkSize+16 {
		clear(ciphertext)
		return nil, errors.New("invalid encrypted chunk response")
	}
	return ciphertext, nil
}

func (c *Client) EncryptedReceipt(ctx context.Context, resourceID string, ciphertext []byte) error {
	if resourceID == "" || len(ciphertext) < 16 || len(ciphertext) > transfercrypto.ChunkSize+16 {
		return errors.New("invalid encrypted receipt")
	}
	digest := sha256.Sum256(ciphertext)
	payload, err := json.Marshal(map[string]string{"encrypted_receipt": base64.RawURLEncoding.EncodeToString(ciphertext), "receipt_digest": hex.EncodeToString(digest[:])})
	if err != nil {
		return err
	}
	return c.retryJSONRequest(ctx, http.MethodPost, c.Endpoint+"/"+resourceID+"/receipt", operationID("encrypted-receipt", resourceID), "application/json", 0, payload, nil)
}
