package filetransfer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

type LocalSender struct {
	Endpoint   string
	Token      string
	HTTPClient *http.Client
}

func (s *LocalSender) SendBatch(ctx context.Context, batchID, sourceMachineID, destinationMachineID, initiatingUserID, sessionID string, sources []Source, generation uint64, expiresAt time.Time) (Batch, error) {
	if s == nil || ctx == nil || s.Endpoint == "" || len(s.Token) < 32 || batchID == "" || sourceMachineID == "" || destinationMachineID == "" || sourceMachineID == destinationMachineID || initiatingUserID == "" || sessionID == "" || len(sources) == 0 || len(sources) > 10 || generation == 0 || !expiresAt.After(time.Now().UTC()) || expiresAt.Nanosecond() != 0 {
		return Batch{}, errors.New("invalid local encrypted file transfer")
	}
	material, err := transfercrypto.GenerateKeyMaterial()
	if err != nil {
		return Batch{}, err
	}
	defer material.Destroy()
	encodedKey, err := material.MarshalBinary()
	if err != nil {
		return Batch{}, err
	}
	defer clear(encodedKey)
	files := make([]map[string]any, len(sources))
	for index, source := range sources {
		if source.Reader == nil || source.Basename == "" || source.Size < 0 {
			return Batch{}, errors.New("invalid local encrypted file source")
		}
		files[index] = map[string]any{"transfer_id": batchID + "." + strconv.Itoa(index), "basename": source.Basename, "size": source.Size, "sha256": hex.EncodeToString(source.SHA256[:]), "file_ordinal": index}
	}
	payload, err := json.Marshal(map[string]any{"batch_id": batchID, "destination_machine_id": destinationMachineID, "initiating_user_id": initiatingUserID, "session_id": sessionID, "transfer_generation": generation, "expires_at": expiresAt, "key_material": base64.RawURLEncoding.EncodeToString(encodedKey), "files": files})
	if err != nil {
		return Batch{}, err
	}
	client := NewClient(s.Endpoint, Auth{Token: s.Token}, Binding{SourceMachineID: sourceMachineID, DestinationMachineID: destinationMachineID, InitiatingUserID: initiatingUserID}, s.HTTPClient)
	var created struct {
		BatchID   string     `json:"batch_id"`
		Transfers []Manifest `json:"transfers"`
	}
	if err := client.retryJSONRequest(ctx, http.MethodPost, client.Endpoint, operationID("local-create", batchID), "application/json", 0, payload, &created); err != nil {
		return Batch{}, err
	}
	if created.BatchID != batchID || len(created.Transfers) != len(sources) {
		return Batch{}, errors.New("local runtime returned invalid transfer resources")
	}
	for index, transfer := range created.Transfers {
		if transfer.TransferID != batchID+"."+strconv.Itoa(index) {
			return Batch{}, errors.New("local runtime returned invalid resource identity")
		}
		if err := s.upload(ctx, client, transfer, sources[index]); err != nil {
			return Batch{}, err
		}
	}
	for _, transfer := range created.Transfers {
		var completed Manifest
		if err := client.retryJSONRequest(ctx, http.MethodPost, client.Endpoint+"/"+transfer.TransferID+"/complete", operationID("local-complete", transfer.TransferID), "", 0, nil, &completed); err != nil {
			return Batch{}, err
		}
		if completed.State != "pending" && completed.State != "delivered" {
			return Batch{}, errors.New("local runtime did not queue encrypted transfer")
		}
	}
	results := make([]Manifest, len(created.Transfers))
	deadline := time.NewTimer(time.Until(expiresAt))
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		remaining := 0
		for index, transfer := range created.Transfers {
			if results[index].State == "delivered" || results[index].State == "failed" {
				continue
			}
			remaining++
			current, err := client.Status(ctx, transfer.TransferID)
			if err != nil {
				continue
			}
			results[index] = current
		}
		if remaining == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return Batch{}, ctx.Err()
		case <-deadline.C:
			return Batch{}, errors.New("encrypted file delivery timed out")
		case <-ticker.C:
		}
	}
	paths := make([]string, len(results))
	for index, result := range results {
		if result.State != "delivered" || result.ResultCode != "stored" || result.ReceiptPath == "" {
			return Batch{BatchID: batchID, Transfers: results}, errors.New("encrypted file delivery failed")
		}
		paths[index] = result.ReceiptPath
	}
	return Batch{BatchID: batchID, Transfers: results, Paths: paths}, nil
}

func (s *LocalSender) upload(ctx context.Context, client *Client, manifest Manifest, source Source) error {
	for attempt := 0; attempt < 4; attempt++ {
		current, err := client.Status(ctx, manifest.TransferID)
		if err != nil {
			if waitErr := waitOperationRetry(ctx, attempt); waitErr != nil {
				return err
			}
			continue
		}
		if current.CommittedOffset == source.Size {
			return nil
		}
		if current.CommittedOffset < 0 || current.CommittedOffset > source.Size {
			return errors.New("local runtime returned invalid committed offset")
		}
		if err := client.patchRequest(ctx, manifest.TransferID, current.CommittedOffset, source); err != nil {
			var responseErr *Error
			if errors.As(err, &responseErr) {
				return err
			}
			continue
		}
	}
	return errors.New("local encrypted transfer did not commit all bytes")
}
