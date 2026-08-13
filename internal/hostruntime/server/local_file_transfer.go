package server

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/store"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

type LocalFileTransferConfig struct {
	Token            string
	MachineID        string
	Service          *filetransfer.Service
	TransferKeys     *transfercrypto.KeyVault
	ResolveRecipient func(sessionID, destinationMachineID string) (string, error)
}

type LocalFileTransferHandler struct{ config LocalFileTransferConfig }

type localFileTransferCreate struct {
	BatchID              string              `json:"batch_id"`
	DestinationMachineID string              `json:"destination_machine_id"`
	InitiatingUserID     string              `json:"initiating_user_id"`
	SessionID            string              `json:"session_id"`
	TransferGeneration   uint64              `json:"transfer_generation"`
	ExpiresAt            time.Time           `json:"expires_at"`
	KeyMaterial          string              `json:"key_material"`
	Files                []filetransfer.File `json:"files"`
}

func NewLocalFileTransferHandler(config LocalFileTransferConfig) (*LocalFileTransferHandler, error) {
	if len(config.Token) < 32 || config.MachineID == "" || config.Service == nil || config.TransferKeys == nil || config.ResolveRecipient == nil {
		return nil, ErrInvalidConfiguration
	}
	return &LocalFileTransferHandler{config: config}, nil
}

func (h *LocalFileTransferHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if !h.authorized(request) {
		writeHTTPError(writer, request.Header.Get(HeaderRequestID), "not_found", http.StatusNotFound, false)
		return
	}
	relative := strings.TrimPrefix(path.Clean(request.URL.Path), "/v1/local-file-transfers")
	if relative == "." || relative == "" || relative == "/" {
		h.create(writer, request)
		return
	}
	parts := strings.Split(strings.Trim(relative, "/"), "/")
	if len(parts) == 1 {
		h.status(writer, request, parts[0])
		return
	}
	if len(parts) == 2 && parts[1] == "content" {
		h.content(writer, request, parts[0])
		return
	}
	if len(parts) == 2 && parts[1] == "complete" {
		h.complete(writer, request, parts[0])
		return
	}
	writeHTTPError(writer, request.Header.Get(HeaderRequestID), "not_found", http.StatusNotFound, false)
}

func (h *LocalFileTransferHandler) authorized(request *http.Request) bool {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	return len(token) == len(h.config.Token) && subtle.ConstantTimeCompare([]byte(token), []byte(h.config.Token)) == 1
}

func (h *LocalFileTransferHandler) create(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.RawQuery != "" {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 2<<20))
	decoder.DisallowUnknownFields()
	var input localFileTransferCreate
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF || input.BatchID == "" || input.TransferGeneration == 0 || input.SessionID == "" || input.DestinationMachineID == "" || input.InitiatingUserID == "" || !input.ExpiresAt.After(time.Now().UTC()) || input.ExpiresAt.Nanosecond() != 0 {
		writeHTTPError(writer, request.Header.Get(HeaderRequestID), "invalid_request", http.StatusBadRequest, false)
		return
	}
	encoded, err := base64.RawURLEncoding.Strict().DecodeString(input.KeyMaterial)
	material, parseErr := transfercrypto.ParseKeyMaterial(encoded)
	clear(encoded)
	if err != nil || parseErr != nil || base64.RawURLEncoding.EncodeToString(mustMarshalKey(material)) != input.KeyMaterial {
		material.Destroy()
		writeHTTPError(writer, request.Header.Get(HeaderRequestID), "invalid_request", http.StatusBadRequest, false)
		return
	}
	defer material.Destroy()
	clientID, err := h.config.ResolveRecipient(input.SessionID, input.DestinationMachineID)
	if err != nil || clientID == "" {
		writeHTTPError(writer, request.Header.Get(HeaderRequestID), "recipient_unavailable", http.StatusConflict, true)
		return
	}
	if existing, found, matches := h.recover(request, input, clientID); found {
		if !matches {
			writeHTTPError(writer, request.Header.Get(HeaderRequestID), "idempotency_conflict", http.StatusConflict, false)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"batch_id": input.BatchID, "transfers": existing})
		return
	}
	if err := h.config.TransferKeys.Save(input.BatchID, input.TransferGeneration, material, input.ExpiresAt); err != nil {
		writeHTTPError(writer, request.Header.Get(HeaderRequestID), "storage_unavailable", http.StatusServiceUnavailable, true)
		return
	}
	created, err := h.config.Service.Create(request.Context(), filetransfer.CreateRequest{BatchID: input.BatchID, SourceMachineID: h.config.MachineID, DestinationMachineID: input.DestinationMachineID, InitiatingUserID: input.InitiatingUserID, SessionID: input.SessionID, DeliveryClientID: clientID, Files: input.Files, E2EETransferID: input.BatchID, TransferGeneration: input.TransferGeneration})
	if err != nil {
		_ = h.config.TransferKeys.Delete(input.BatchID)
		writeFileTransferError(writer, request.Header.Get(HeaderRequestID), err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"batch_id": input.BatchID, "transfers": created})
}

func mustMarshalKey(material transfercrypto.KeyMaterial) []byte {
	encoded, _ := material.MarshalBinary()
	return encoded
}

func (h *LocalFileTransferHandler) recover(request *http.Request, input localFileTransferCreate, clientID string) ([]store.FileTransfer, bool, bool) {
	existing, err := h.config.Service.Batch(request.Context(), input.BatchID)
	if err != nil {
		return nil, false, false
	}
	if len(existing) != len(input.Files) {
		return existing, true, false
	}
	for index, transfer := range existing {
		file := input.Files[index]
		if transfer.ID != file.ID || transfer.FileOrdinal != file.Ordinal || transfer.Basename != file.Basename || transfer.Size != file.Size || transfer.SHA256 != file.SHA256 || transfer.SourceMachineID != h.config.MachineID || transfer.DestinationMachineID != input.DestinationMachineID || transfer.InitiatingUserID != input.InitiatingUserID || transfer.SessionID != input.SessionID || transfer.DeliveryClientID != clientID || transfer.E2EETransferID != input.BatchID || transfer.TransferGeneration != input.TransferGeneration {
			return existing, true, false
		}
	}
	return existing, true, true
}

func (h *LocalFileTransferHandler) status(writer http.ResponseWriter, request *http.Request, id string) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	transfer, err := h.config.Service.Get(request.Context(), id)
	if err != nil || transfer.SourceMachineID != h.config.MachineID || transfer.E2EETransferID == "" {
		writeHTTPError(writer, request.Header.Get(HeaderRequestID), "not_found", http.StatusNotFound, false)
		return
	}
	writeJSON(writer, http.StatusOK, transfer)
}

func (h *LocalFileTransferHandler) content(writer http.ResponseWriter, request *http.Request, id string) {
	if request.Method != http.MethodPatch || request.Header.Get("Content-Type") != "application/offset+octet-stream" {
		methodNotAllowed(writer, http.MethodPatch)
		return
	}
	transfer, err := h.config.Service.Get(request.Context(), id)
	if err != nil || transfer.SourceMachineID != h.config.MachineID || transfer.E2EETransferID == "" {
		writeHTTPError(writer, request.Header.Get(HeaderRequestID), "not_found", http.StatusNotFound, false)
		return
	}
	offset, err := strconv.ParseInt(request.Header.Get(HeaderUploadOffset), 10, 64)
	if err != nil {
		writeHTTPError(writer, request.Header.Get(HeaderRequestID), "invalid_request", http.StatusBadRequest, false)
		return
	}
	updated, err := h.config.Service.Append(request.Context(), id, offset, request.Body)
	if err != nil {
		writeFileTransferError(writer, request.Header.Get(HeaderRequestID), err)
		return
	}
	writer.Header().Set(HeaderUploadOffset, strconv.FormatInt(updated.CommittedOffset, 10))
	writer.WriteHeader(http.StatusNoContent)
}

func (h *LocalFileTransferHandler) complete(writer http.ResponseWriter, request *http.Request, id string) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	transfer, err := h.config.Service.Get(request.Context(), id)
	if err != nil || transfer.SourceMachineID != h.config.MachineID || transfer.E2EETransferID == "" {
		writeHTTPError(writer, request.Header.Get(HeaderRequestID), "not_found", http.StatusNotFound, false)
		return
	}
	completed, err := h.config.Service.Complete(request.Context(), id)
	if err != nil {
		writeFileTransferError(writer, request.Header.Get(HeaderRequestID), err)
		return
	}
	if completed.State != "pending" && completed.State != "delivered" {
		writeHTTPError(writer, request.Header.Get(HeaderRequestID), "invalid_request", http.StatusConflict, false)
		return
	}
	writeJSON(writer, http.StatusOK, completed)
}
