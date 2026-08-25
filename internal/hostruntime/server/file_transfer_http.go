package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/hostruntime/filetransfer"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/operation"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/protocol"
	"github.com/pinksaucepasta/paperboat/internal/hostruntime/store"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/peercontext"
	"github.com/pinksaucepasta/paperboat/internal/peertransport/transfercrypto"
)

const (
	HeaderUploadOffset = "Upload-Offset"
	HeaderUploadLength = "Upload-Length"
	HeaderUploadDigest = "Upload-Digest"
)

type FileTransferHandlerConfig struct {
	Service               *filetransfer.Service
	Journal               *operation.Journal
	Authorizer            AuthorizerFactory
	AuthorizeCreate       func(Authorization, CreateFileTransferRequest) bool
	ResolveDeliveryClient func(Authorization, CreateFileTransferRequest) (string, error)
	Owns                  func(Authorization, store.FileTransfer) bool
	MaxCreateBytes        int64
	TransferKeys          *transfercrypto.KeyVault
}

type FileTransferHandler struct{ config FileTransferHandlerConfig }

type CreateFileTransferRequest struct {
	BatchID              string              `json:"batch_id"`
	SourceMachineID      string              `json:"source_machine_id"`
	DestinationMachineID string              `json:"destination_machine_id"`
	InitiatingUserID     string              `json:"initiating_user_id"`
	SessionID            string              `json:"session_id,omitempty"`
	Files                []filetransfer.File `json:"files,omitempty"`
	E2EE                 *fileTransferE2EE   `json:"e2ee,omitempty"`
}

type fileTransferE2EE struct {
	Version            int    `json:"version"`
	TransferID         string `json:"transfer_id"`
	TransferGeneration uint64 `json:"transfer_generation"`
	EncryptedManifest  string `json:"encrypted_manifest"`
	ManifestDigest     string `json:"manifest_digest"`
}

type encryptedTransferResource struct {
	TransferID     string    `json:"transfer_id"`
	CommittedChunk uint64    `json:"committed_chunk"`
	State          string    `json:"state"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type sourceEncryptedTransferStatus struct {
	store.FileTransfer
	CommittedChunk uint64 `json:"committed_chunk"`
}

type encryptedCreateResponse struct {
	BatchID   string                      `json:"batch_id"`
	Resources []encryptedTransferResource `json:"resources"`
}

type createFileTransferResponse struct {
	BatchID   string               `json:"batch_id"`
	Transfers []store.FileTransfer `json:"transfers"`
}

type completeFileTransferResponse struct {
	Transfer store.FileTransfer `json:"transfer"`
	Result   struct {
		Code string `json:"code"`
		Path string `json:"path,omitempty"`
	} `json:"result"`
}

type encryptedCompleteResponse struct {
	Resource         encryptedTransferResource `json:"resource"`
	EncryptedReceipt string                    `json:"encrypted_receipt"`
	ReceiptDigest    string                    `json:"receipt_digest"`
}

type encryptedPendingBatch struct {
	TransferID         string                      `json:"transfer_id"`
	TransferGeneration uint64                      `json:"transfer_generation"`
	State              string                      `json:"state"`
	ExpiresAt          time.Time                   `json:"expires_at"`
	Resources          []encryptedTransferResource `json:"resources"`
}

type encryptedManifestResponse struct {
	TransferID         string                      `json:"transfer_id"`
	TransferGeneration uint64                      `json:"transfer_generation"`
	EncryptedManifest  string                      `json:"encrypted_manifest"`
	ManifestDigest     string                      `json:"manifest_digest"`
	Resources          []encryptedTransferResource `json:"resources"`
}

func NewFileTransferHandler(config FileTransferHandlerConfig) (*FileTransferHandler, error) {
	if config.MaxCreateBytes == 0 {
		config.MaxCreateBytes = 2 << 20
	}
	if config.Service == nil || config.Journal == nil || config.Authorizer == nil || config.AuthorizeCreate == nil || config.MaxCreateBytes < 1024 || config.MaxCreateBytes > 2<<20 {
		return nil, ErrInvalidConfiguration
	}
	return &FileTransferHandler{config: config}, nil
}

func (h *FileTransferHandler) Capabilities() []string { return []string{"file-transfer.v1"} }

func (h *FileTransferHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID := request.Header.Get(HeaderRequestID)
	authorization, release, ok := h.authorize(writer, request, requestID)
	if !ok {
		return
	}
	defer release()
	if authorization.Revoked != nil && authorization.Revoked.Load() {
		writeHTTPError(writer, requestID, "canceled", http.StatusUnauthorized, false)
		return
	}
	if authorization.RevokedSignal != nil {
		ctx, cancel := context.WithCancel(request.Context())
		defer cancel()
		go func() {
			select {
			case <-authorization.RevokedSignal:
				cancel()
				_ = request.Body.Close()
			case <-ctx.Done():
			}
		}()
		request = request.WithContext(ctx)
	}
	relative := strings.TrimPrefix(path.Clean(request.URL.Path), "/v1/file-transfers")
	if relative == "." || relative == "" || relative == "/" {
		h.serveCollection(writer, request, requestID, authorization)
		return
	}
	if relative == "/pending" {
		h.servePending(writer, request, requestID, authorization)
		return
	}
	parts := strings.Split(strings.Trim(relative, "/"), "/")
	if len(parts) < 1 || len(parts) > 3 || parts[0] == "" {
		writeHTTPError(writer, requestID, "not_found", http.StatusNotFound, false)
		return
	}
	id := parts[0]
	if len(parts) == 1 {
		h.serveManifest(writer, request, requestID, authorization, id)
		return
	}
	if len(parts) == 3 && parts[1] == "chunks" {
		h.serveEncryptedChunk(writer, request, requestID, authorization, id, parts[2])
		return
	}
	if len(parts) != 2 {
		writeHTTPError(writer, requestID, "not_found", http.StatusNotFound, false)
		return
	}
	switch parts[1] {
	case "e2ee-manifest":
		h.serveEncryptedManifest(writer, request, requestID, authorization, id)
	case "content":
		h.serveContent(writer, request, requestID, authorization, id)
	case "complete":
		h.serveComplete(writer, request, requestID, authorization, id)
	case "receipt":
		h.serveReceipt(writer, request, requestID, authorization, id)
	default:
		writeHTTPError(writer, requestID, "not_found", http.StatusNotFound, false)
	}
}

func (h *FileTransferHandler) authorize(writer http.ResponseWriter, request *http.Request, requestID string) (Authorization, func(), bool) {
	release := func() {}
	token, ok := bearerToken(request.Header.Values("Authorization"))
	if !ok {
		writeHTTPError(writer, requestID, "unauthorized", http.StatusUnauthorized, false)
		return Authorization{}, release, false
	}
	authorizer, err := h.config.Authorizer(token)
	if err != nil || authorizer == nil {
		writeHTTPError(writer, requestID, "unauthorized", http.StatusUnauthorized, false)
		return Authorization{}, release, false
	}
	if closer, ok := authorizer.(AuthorizationCloser); ok {
		release = closer.CloseAuthorization
	}
	frame := protocol.Frame{Type: "request", Version: protocol.ProtocolVersion, RequestID: requestID, OperationID: request.Header.Get(HeaderOperationID), Capability: "file-transfer.v1"}
	authz, err := authorizer.Authorize(request.Context(), frame)
	if err != nil || authz.JournalBinding == "" {
		release()
		writeHTTPError(writer, requestID, "unauthorized", http.StatusUnauthorized, false)
		return Authorization{}, func() {}, false
	}
	return authz, release, true
}

func (h *FileTransferHandler) serveCollection(writer http.ResponseWriter, request *http.Request, requestID string, authorization Authorization) {
	if request.Method == http.MethodGet {
		if authorization.SourceMachineID == "" || authorization.UserID == "" {
			writeHTTPError(writer, requestID, "not_found_or_forbidden", http.StatusNotFound, false)
			return
		}
		limit := 50
		if raw := request.URL.Query().Get("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 1 || parsed > 200 {
				writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
				return
			}
			limit = parsed
		}
		sessionID := request.URL.Query().Get("session_id")
		if authorization.SessionID != "" && sessionID != authorization.SessionID {
			writeHTTPError(writer, requestID, "not_found_or_forbidden", http.StatusNotFound, false)
			return
		}
		items, err := h.config.Service.List(request.Context(), authorization.SourceMachineID, authorization.UserID, sessionID, limit)
		if err != nil {
			writeFileTransferError(writer, requestID, err)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"items": items})
		return
	}
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodGet, http.MethodPost)
		return
	}
	operationID := request.Header.Get(HeaderOperationID)
	if len(operationID) < 8 || len(operationID) > 128 {
		writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, h.config.MaxCreateBytes))
	if err != nil {
		writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
		return
	}
	var input CreateFileTransferRequest
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || decoder.Decode(&struct{}{}) != io.EOF || input.BatchID == "" || input.SourceMachineID == "" || input.DestinationMachineID == "" || input.InitiatingUserID == "" || authorization.SessionID != "" && input.SessionID != authorization.SessionID || !h.config.AuthorizeCreate(authorization, input) {
		writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
		return
	}
	if input.E2EE != nil {
		if err := h.openEncryptedCreate(input.E2EE, &input, authorization); err != nil {
			writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
			return
		}
	} else if len(input.Files) == 0 {
		writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
		return
	}
	if transfers, exists, matches := h.recoverBatch(request.Context(), authorization, input); exists {
		if !matches {
			writeHTTPError(writer, requestID, "operation_conflict", http.StatusConflict, false)
			return
		}
		writer.Header().Set(HeaderReplayed, "true")
		if input.E2EE != nil {
			writeJSON(writer, http.StatusCreated, encryptedBatchResponse(input.BatchID, transfers))
		} else {
			writeJSON(writer, http.StatusCreated, createFileTransferResponse{BatchID: input.BatchID, Transfers: transfers})
		}
		return
	}
	canonical, _ := json.Marshal(struct {
		Binding string                    `json:"binding"`
		Request CreateFileTransferRequest `json:"request"`
	}{authorization.JournalBinding, input})
	clientID := ""
	var resolveErr error
	if h.config.ResolveDeliveryClient != nil {
		clientID, resolveErr = h.config.ResolveDeliveryClient(authorization, input)
	}
	if resolveErr != nil {
		writeHTTPError(writer, requestID, "no_active_writer", http.StatusConflict, false)
		return
	}
	outcome, replay, err := h.config.Journal.Execute(request.Context(), operationID, canonical, func(ctx context.Context) operation.Outcome {
		create := filetransfer.CreateRequest{BatchID: input.BatchID, SourceMachineID: input.SourceMachineID, DestinationMachineID: input.DestinationMachineID, InitiatingUserID: input.InitiatingUserID, SessionID: input.SessionID, DeliveryClientID: clientID, Files: input.Files}
		if input.E2EE != nil {
			create.E2EETransferID, create.TransferGeneration = input.E2EE.TransferID, input.E2EE.TransferGeneration
		}
		transfers, createErr := h.config.Service.Create(ctx, create)
		if createErr != nil {
			return operation.Outcome{ErrorCode: fileTransferErrorCode(createErr)}
		}
		var response any = createFileTransferResponse{BatchID: input.BatchID, Transfers: transfers}
		if input.E2EE != nil {
			response = encryptedBatchResponse(input.BatchID, transfers)
		}
		encoded, marshalErr := json.Marshal(response)
		if marshalErr != nil {
			return operation.Outcome{ErrorCode: "storage_unavailable"}
		}
		return operation.Outcome{Result: encoded}
	})
	if err != nil {
		writeHTTPError(writer, requestID, operationErrorCode(err), operationHTTPStatus(operationErrorCode(err)), false)
		return
	}
	if outcome.ErrorCode != "" {
		writeHTTPError(writer, requestID, outcome.ErrorCode, fileTransferHTTPStatus(outcome.ErrorCode), false)
		return
	}
	if replay {
		writer.Header().Set(HeaderReplayed, "true")
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusCreated)
	_, _ = writer.Write(outcome.Result)
}

func encryptedBatchResponse(batchID string, transfers []store.FileTransfer) encryptedCreateResponse {
	response := encryptedCreateResponse{BatchID: batchID, Resources: make([]encryptedTransferResource, len(transfers))}
	for index, transfer := range transfers {
		response.Resources[index] = encryptedTransferResource{TransferID: transfer.ID, CommittedChunk: transfer.CommittedChunks, State: transfer.State, ExpiresAt: transfer.ExpiresAt}
	}
	return response
}

func (h *FileTransferHandler) openEncryptedCreate(envelope *fileTransferE2EE, input *CreateFileTransferRequest, authorization Authorization) error {
	if h.config.TransferKeys == nil || envelope == nil || input == nil || envelope.Version != 1 || envelope.TransferID != input.BatchID || envelope.TransferGeneration == 0 || len(input.Files) != 0 {
		return transfercrypto.ErrInvalid
	}
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(envelope.EncryptedManifest)
	if err != nil || base64.RawURLEncoding.EncodeToString(ciphertext) != envelope.EncryptedManifest || len(ciphertext) > transfercrypto.ChunkSize+32 {
		return transfercrypto.ErrInvalid
	}
	digest := sha256.Sum256(ciphertext)
	if hex.EncodeToString(digest[:]) != envelope.ManifestDigest {
		return transfercrypto.ErrAuthentication
	}
	material, peer, err := h.config.TransferKeys.LoadBound(envelope.TransferID, envelope.TransferGeneration)
	if err != nil {
		return err
	}
	defer material.Destroy()
	if peer.AccountID != authorization.UserID || peer.MachineID != input.DestinationMachineID || peer.Consumer != "file_transfer_key" {
		return transfercrypto.ErrAuthentication
	}
	manifest, err := transfercrypto.DecryptManifest(material, recordContext(peer, envelope.TransferID, envelope.TransferGeneration), ciphertext)
	if err != nil || manifest.BatchID != input.BatchID || len(manifest.Files) == 0 || len(manifest.Files) > filetransfer.MaxBatchFiles {
		return transfercrypto.ErrAuthentication
	}
	input.Files = make([]filetransfer.File, len(manifest.Files))
	for index, file := range manifest.Files {
		if file.FileOrdinal != uint64(index) || file.Size > uint64(filetransfer.MaxFileBytes) {
			return transfercrypto.ErrAuthentication
		}
		input.Files[index] = filetransfer.File{ID: file.TransferID, Basename: file.Name, Size: int64(file.Size), SHA256: hex.EncodeToString(file.PlaintextSHA256[:]), Ordinal: file.FileOrdinal}
	}
	return nil
}

func recordContext(peer peercontext.Context, transferID string, generation uint64) transfercrypto.RecordContext {
	return recordContextDirection(peer, transferID, generation, transfercrypto.DirectionToMachine)
}

func recordContextDirection(peer peercontext.Context, transferID string, generation uint64, direction transfercrypto.Direction) transfercrypto.RecordContext {
	return transfercrypto.RecordContext{AccountID: peer.AccountID, DeviceID: peer.DeviceID, MachineID: peer.MachineID, InitiatorCertificateHash: peer.InitiatorCertificateHash, ResponderCertificateHash: peer.ResponderCertificateHash, OperationID: peer.OperationID, TransferID: transferID, Direction: direction, TransferGeneration: generation}
}

func (h *FileTransferHandler) recoverBatch(ctx context.Context, authorization Authorization, input CreateFileTransferRequest) ([]store.FileTransfer, bool, bool) {
	existing, err := h.config.Service.Batch(ctx, input.BatchID)
	if err != nil {
		return nil, false, false
	}
	if len(existing) != len(input.Files) {
		return nil, true, false
	}
	ordered := make([]store.FileTransfer, len(input.Files))
	used := make([]bool, len(existing))
	for inputIndex, file := range input.Files {
		matched := -1
		for existingIndex, transfer := range existing {
			if used[existingIndex] || transfer.SourceMachineID != input.SourceMachineID || transfer.DestinationMachineID != input.DestinationMachineID || transfer.InitiatingUserID != input.InitiatingUserID || transfer.SessionID != input.SessionID || h.config.ResolveDeliveryClient == nil && transfer.DeliveryClientID != "" {
				continue
			}
			if transfer.Basename == file.Basename && transfer.Size == file.Size && transfer.SHA256 == file.SHA256 {
				matched = existingIndex
				break
			}
		}
		if matched < 0 {
			return nil, true, false
		}
		used[matched] = true
		ordered[inputIndex] = existing[matched]
	}
	return ordered, true, true
}

func (h *FileTransferHandler) serveManifest(writer http.ResponseWriter, request *http.Request, requestID string, authorization Authorization, id string) {
	transfer, ok := h.owned(writer, request, requestID, authorization, id)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		if transfer.E2EETransferID != "" && transfer.SourceMachineID != authorization.SourceMachineID {
			writeJSON(writer, http.StatusOK, encryptedBatchResponse(transfer.BatchID, []store.FileTransfer{transfer}).Resources[0])
			return
		}
		if transfer.E2EETransferID != "" {
			if transfer.State == "published" && transfer.ReceiptPath == "" {
				published, err := h.config.Service.ExistingPublishedPath(request.Context(), transfer.ID)
				if err == nil {
					transfer.ReceiptPath = "Paperboat Inbox/" + filepath.Base(published)
				}
			}
			writeJSON(writer, http.StatusOK, sourceEncryptedTransferStatus{FileTransfer: transfer, CommittedChunk: transfer.CommittedChunks})
			return
		}
		writeJSON(writer, http.StatusOK, transfer)
	case http.MethodDelete:
		if err := h.config.Service.Cancel(request.Context(), id); err != nil {
			writeFileTransferError(writer, requestID, err)
			return
		}
		if transfer.E2EETransferID != "" && h.config.TransferKeys != nil {
			if err := h.config.TransferKeys.Delete(transfer.E2EETransferID); err != nil {
				writeHTTPError(writer, requestID, "storage_unavailable", http.StatusServiceUnavailable, false)
				return
			}
		}
		writer.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(writer, http.MethodGet, http.MethodDelete)
	}
}

func (h *FileTransferHandler) serveContent(writer http.ResponseWriter, request *http.Request, requestID string, authorization Authorization, id string) {
	transfer, ok := h.owned(writer, request, requestID, authorization, id)
	if !ok {
		return
	}
	if transfer.E2EETransferID != "" {
		writeHTTPError(writer, requestID, "not_found", http.StatusNotFound, false)
		return
	}
	etag := `"sha256:` + transfer.SHA256 + `"`
	switch request.Method {
	case http.MethodHead:
		writer.Header().Set(HeaderUploadOffset, strconv.FormatInt(transfer.CommittedOffset, 10))
		writer.Header().Set(HeaderUploadLength, strconv.FormatInt(transfer.Size, 10))
		writer.Header().Set(HeaderUploadDigest, "sha256="+transfer.SHA256)
		writer.Header().Set("ETag", etag)
		writer.WriteHeader(http.StatusNoContent)
	case http.MethodPatch:
		if request.Header.Get("Content-Type") != "application/offset+octet-stream" {
			writeHTTPError(writer, requestID, "invalid_request", http.StatusUnsupportedMediaType, false)
			return
		}
		offset, err := strconv.ParseInt(request.Header.Get(HeaderUploadOffset), 10, 64)
		if err != nil {
			writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
			return
		}
		stopClose := make(chan struct{})
		go func() {
			select {
			case <-h.config.Service.CancellationSignal(id):
				_ = request.Body.Close()
			case <-request.Context().Done():
			case <-stopClose:
			}
		}()
		updated, err := h.config.Service.Append(request.Context(), id, offset, request.Body)
		close(stopClose)
		if err != nil {
			writeFileTransferError(writer, requestID, err)
			return
		}
		writer.Header().Set(HeaderUploadOffset, strconv.FormatInt(updated.CommittedOffset, 10))
		writer.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		if match := request.Header.Get("If-Match"); match != "" && match != etag {
			writeHTTPError(writer, requestID, "precondition_failed", http.StatusPreconditionFailed, false)
			return
		}
		file, current, err := h.config.Service.OpenContent(request.Context(), id)
		if err != nil {
			writeFileTransferError(writer, requestID, err)
			return
		}
		defer file.Close()
		writer.Header().Set("ETag", etag)
		writer.Header().Set("Content-Type", "application/octet-stream")
		writer.Header().Set("Accept-Ranges", "bytes")
		http.ServeContent(writer, request, current.Basename, current.CreatedAt, contextReadSeeker{ctx: request.Context(), reader: file})
	default:
		methodNotAllowed(writer, http.MethodHead, http.MethodPatch, http.MethodGet)
	}
}

func (h *FileTransferHandler) serveEncryptedChunk(writer http.ResponseWriter, request *http.Request, requestID string, authorization Authorization, id, ordinalValue string) {
	if request.Method != http.MethodPut && request.Method != http.MethodGet || h.config.TransferKeys == nil {
		methodNotAllowed(writer, http.MethodPut, http.MethodGet)
		return
	}
	transfer, ok := h.owned(writer, request, requestID, authorization, id)
	if !ok || transfer.E2EETransferID == "" || transfer.TransferGeneration == 0 {
		if ok {
			writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
		}
		return
	}
	if request.Method == http.MethodGet {
		h.readEncryptedChunk(writer, request, requestID, authorization, transfer, ordinalValue)
		return
	}
	ordinal, err := strconv.ParseUint(ordinalValue, 10, 64)
	if err != nil || ordinal > uint64(transfer.Size)/uint64(transfercrypto.ChunkSize)+1 || request.ContentLength > int64(transfercrypto.ChunkSize+32) {
		writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
		return
	}
	ciphertext, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, transfercrypto.ChunkSize+32))
	if err != nil {
		writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
		return
	}
	material, peer, err := h.config.TransferKeys.LoadBound(transfer.E2EETransferID, transfer.TransferGeneration)
	if err != nil {
		writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
		return
	}
	defer material.Destroy()
	if peer.MachineID != transfer.DestinationMachineID || peer.AccountID != authorization.UserID {
		writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
		return
	}
	chunkCount := uint64(transfer.Size) / uint64(transfercrypto.ChunkSize)
	if transfer.Size%int64(transfercrypto.ChunkSize) != 0 || chunkCount == 0 {
		chunkCount++
	}
	chunkContext := transfercrypto.ChunkContext{AccountID: peer.AccountID, DeviceID: peer.DeviceID, MachineID: peer.MachineID, InitiatorCertificateHash: peer.InitiatorCertificateHash, ResponderCertificateHash: peer.ResponderCertificateHash, OperationID: peer.OperationID, TransferID: transfer.E2EETransferID, Direction: transfercrypto.DirectionToMachine, TransferGeneration: transfer.TransferGeneration, FileOrdinal: transfer.FileOrdinal, ChunkOrdinal: ordinal, Final: ordinal+1 == chunkCount}
	plaintext, err := transfercrypto.DecryptChunk(material, chunkContext, ciphertext)
	if err != nil {
		writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
		return
	}
	defer clear(plaintext)
	offset := ordinal * uint64(transfercrypto.ChunkSize)
	if offset > uint64(^uint64(0)>>1) {
		writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
		return
	}
	ciphertextDigest := sha256.Sum256(ciphertext)
	updated, err := h.config.Service.AppendEncrypted(request.Context(), id, ordinal, ciphertextDigest, len(ciphertext), plaintext)
	if err != nil {
		writeFileTransferError(writer, requestID, err)
		return
	}
	writer.Header().Set("Upload-Chunk-Ordinal", strconv.FormatUint(ordinal+1, 10))
	writer.Header().Set(HeaderUploadOffset, strconv.FormatInt(updated.CommittedOffset, 10))
	writer.WriteHeader(http.StatusNoContent)
}

func (h *FileTransferHandler) serveEncryptedManifest(writer http.ResponseWriter, request *http.Request, requestID string, authorization Authorization, id string) {
	if request.Method != http.MethodGet || h.config.TransferKeys == nil {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	transfer, ok := h.owned(writer, request, requestID, authorization, id)
	if !ok || transfer.E2EETransferID == "" || transfer.TransferGeneration == 0 || transfer.SourceMachineID == transfer.DestinationMachineID {
		if ok {
			writeHTTPError(writer, requestID, "not_found", http.StatusNotFound, false)
		}
		return
	}
	material, peer, err := h.config.TransferKeys.LoadBound(transfer.E2EETransferID, transfer.TransferGeneration)
	if err != nil {
		writeHTTPError(writer, requestID, "e2ee_key_unavailable", http.StatusConflict, true)
		return
	}
	defer material.Destroy()
	if peer.AccountID != authorization.UserID || peer.MachineID != transfer.SourceMachineID {
		writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
		return
	}
	transfers, err := h.config.Service.Batch(request.Context(), transfer.BatchID)
	if err != nil || len(transfers) == 0 {
		writeHTTPError(writer, requestID, "not_found", http.StatusNotFound, false)
		return
	}
	manifest := transfercrypto.Manifest{BatchID: transfer.E2EETransferID, Files: make([]transfercrypto.ManifestFile, len(transfers))}
	for _, item := range transfers {
		if item.E2EETransferID != transfer.E2EETransferID || item.TransferGeneration != transfer.TransferGeneration || item.FileOrdinal >= uint64(len(transfers)) || item.State != "pending" {
			writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
			return
		}
		digest, decodeErr := hex.DecodeString(item.SHA256)
		if decodeErr != nil || len(digest) != sha256.Size {
			writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
			return
		}
		var plaintextDigest [sha256.Size]byte
		copy(plaintextDigest[:], digest)
		chunks := uint64(item.Size) / uint64(transfercrypto.ChunkSize)
		if item.Size%int64(transfercrypto.ChunkSize) != 0 || chunks == 0 {
			chunks++
		}
		manifest.Files[item.FileOrdinal] = transfercrypto.ManifestFile{TransferID: item.ID, FileOrdinal: item.FileOrdinal, Name: item.Basename, RelativeDestination: "Paperboat Inbox/" + item.Basename, Mode: 0o600, Size: uint64(item.Size), PlaintextSHA256: plaintextDigest, ChunkCount: chunks}
	}
	ciphertext, err := transfercrypto.EncryptManifest(material, recordContextDirection(peer, transfer.E2EETransferID, transfer.TransferGeneration, transfercrypto.DirectionFromMachine), manifest)
	if err != nil {
		writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
		return
	}
	digest := sha256.Sum256(ciphertext)
	writeJSON(writer, http.StatusOK, encryptedManifestResponse{TransferID: transfer.E2EETransferID, TransferGeneration: transfer.TransferGeneration, EncryptedManifest: base64.RawURLEncoding.EncodeToString(ciphertext), ManifestDigest: hex.EncodeToString(digest[:]), Resources: encryptedBatchResponse(transfer.BatchID, transfers).Resources})
}

func (h *FileTransferHandler) readEncryptedChunk(writer http.ResponseWriter, request *http.Request, requestID string, authorization Authorization, transfer store.FileTransfer, ordinalValue string) {
	if transfer.State != "pending" || transfer.DestinationMachineID == transfer.SourceMachineID {
		writeHTTPError(writer, requestID, "not_found", http.StatusNotFound, false)
		return
	}
	ordinal, err := strconv.ParseUint(ordinalValue, 10, 64)
	chunkCount := uint64(transfer.Size) / uint64(transfercrypto.ChunkSize)
	if transfer.Size%int64(transfercrypto.ChunkSize) != 0 || chunkCount == 0 {
		chunkCount++
	}
	if err != nil || ordinal >= chunkCount {
		writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
		return
	}
	material, peer, err := h.config.TransferKeys.LoadBound(transfer.E2EETransferID, transfer.TransferGeneration)
	if err != nil || peer.AccountID != authorization.UserID || peer.MachineID != transfer.SourceMachineID {
		material.Destroy()
		writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
		return
	}
	defer material.Destroy()
	file, _, err := h.config.Service.OpenContent(request.Context(), transfer.ID)
	if err != nil {
		writeFileTransferError(writer, requestID, err)
		return
	}
	defer file.Close()
	offset := int64(ordinal) * int64(transfercrypto.ChunkSize)
	want := transfer.Size - offset
	if want > int64(transfercrypto.ChunkSize) {
		want = int64(transfercrypto.ChunkSize)
	}
	plaintext := make([]byte, want)
	if want > 0 {
		read, readErr := file.ReadAt(plaintext, offset)
		if readErr != nil && !errors.Is(readErr, io.EOF) || int64(read) != want {
			clear(plaintext)
			writeHTTPError(writer, requestID, "storage_unavailable", http.StatusServiceUnavailable, true)
			return
		}
	}
	chunkContext := transfercrypto.ChunkContext{AccountID: peer.AccountID, DeviceID: peer.DeviceID, MachineID: peer.MachineID, InitiatorCertificateHash: peer.InitiatorCertificateHash, ResponderCertificateHash: peer.ResponderCertificateHash, OperationID: peer.OperationID, TransferID: transfer.E2EETransferID, Direction: transfercrypto.DirectionFromMachine, TransferGeneration: transfer.TransferGeneration, FileOrdinal: transfer.FileOrdinal, ChunkOrdinal: ordinal, Final: ordinal+1 == chunkCount}
	ciphertext, err := transfercrypto.EncryptChunk(material, chunkContext, plaintext)
	clear(plaintext)
	if err != nil {
		writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Length", strconv.Itoa(len(ciphertext)))
	writer.Header().Set("Upload-Chunk-Ordinal", strconv.FormatUint(ordinal, 10))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(ciphertext)
}

type contextReadSeeker struct {
	ctx    context.Context
	reader io.ReadSeeker
}

func (r contextReadSeeker) Read(buffer []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.reader.Read(buffer)
	}
}

func (r contextReadSeeker) Seek(offset int64, whence int) (int64, error) {
	return r.reader.Seek(offset, whence)
}

func (h *FileTransferHandler) serveComplete(writer http.ResponseWriter, request *http.Request, requestID string, authorization Authorization, id string) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	requested, ok := h.owned(writer, request, requestID, authorization, id)
	if !ok {
		return
	}
	transfer, err := h.config.Service.Complete(request.Context(), id)
	if err != nil {
		writeFileTransferError(writer, requestID, err)
		return
	}
	if requested.E2EETransferID != "" {
		response, err := h.encryptedCompletion(request.Context(), authorization, transfer)
		if err != nil {
			writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
			return
		}
		writeJSON(writer, http.StatusOK, response)
		return
	}
	result := completeFileTransferResponse{Transfer: transfer}
	result.Result.Code = "published"
	if transfer.State == "pending" {
		result.Result.Code = "pending"
	}
	if transfer.State == "published" {
		published, err := h.config.Service.PublishedPath(request.Context(), id)
		if err != nil {
			writeFileTransferError(writer, requestID, err)
			return
		}
		result.Result.Path = published
	}
	writeJSON(writer, http.StatusOK, result)
}

func (h *FileTransferHandler) encryptedCompletion(ctx context.Context, authorization Authorization, completed store.FileTransfer) (encryptedCompleteResponse, error) {
	if h.config.TransferKeys == nil || completed.E2EETransferID == "" || completed.TransferGeneration == 0 {
		return encryptedCompleteResponse{}, transfercrypto.ErrInvalid
	}
	material, peer, err := h.config.TransferKeys.LoadBound(completed.E2EETransferID, completed.TransferGeneration)
	if err != nil {
		return encryptedCompleteResponse{}, err
	}
	defer material.Destroy()
	if peer.AccountID != authorization.UserID || peer.MachineID != completed.DestinationMachineID {
		return encryptedCompleteResponse{}, transfercrypto.ErrAuthentication
	}
	transfers, err := h.config.Service.Batch(ctx, completed.BatchID)
	if err != nil || len(transfers) == 0 {
		return encryptedCompleteResponse{}, transfercrypto.ErrInvalid
	}
	manifest := transfercrypto.Manifest{BatchID: completed.BatchID, Files: make([]transfercrypto.ManifestFile, len(transfers))}
	receipt := transfercrypto.FinalReceipt{Files: make([]transfercrypto.ReceiptFile, len(transfers))}
	for _, transfer := range transfers {
		if transfer.E2EETransferID != completed.E2EETransferID || transfer.TransferGeneration != completed.TransferGeneration || transfer.FileOrdinal >= uint64(len(transfers)) || transfer.State != "published" {
			return encryptedCompleteResponse{}, transfercrypto.ErrInvalid
		}
		digest, decodeErr := hex.DecodeString(transfer.SHA256)
		if decodeErr != nil || len(digest) != sha256.Size {
			return encryptedCompleteResponse{}, transfercrypto.ErrInvalid
		}
		chunks := uint64(transfer.Size) / uint64(transfercrypto.ChunkSize)
		if transfer.Size%int64(transfercrypto.ChunkSize) != 0 || chunks == 0 {
			chunks++
		}
		var plaintextDigest [sha256.Size]byte
		copy(plaintextDigest[:], digest)
		manifest.Files[transfer.FileOrdinal] = transfercrypto.ManifestFile{TransferID: transfer.ID, FileOrdinal: transfer.FileOrdinal, Name: transfer.Basename, RelativeDestination: "Paperboat Inbox/" + transfer.Basename, Mode: 0o600, Size: uint64(transfer.Size), PlaintextSHA256: plaintextDigest, ChunkCount: chunks}
		published, pathErr := h.config.Service.PublishedPath(ctx, transfer.ID)
		if pathErr != nil {
			return encryptedCompleteResponse{}, pathErr
		}
		result := transfercrypto.CollisionOriginal
		if filepath.Base(published) != transfer.Basename {
			result = transfercrypto.CollisionRenamed
		}
		receipt.Files[transfer.FileOrdinal] = transfercrypto.ReceiptFile{FileOrdinal: transfer.FileOrdinal, Result: result, RelativePath: "Paperboat Inbox/" + filepath.Base(published)}
	}
	receipt.ManifestHash, err = manifest.Hash()
	if err != nil {
		return encryptedCompleteResponse{}, err
	}
	ciphertext, err := transfercrypto.EncryptFinalReceipt(material, recordContext(peer, completed.E2EETransferID, completed.TransferGeneration), receipt)
	if err != nil {
		return encryptedCompleteResponse{}, err
	}
	digest := sha256.Sum256(ciphertext)
	resource := encryptedBatchResponse(completed.BatchID, []store.FileTransfer{completed}).Resources[0]
	return encryptedCompleteResponse{Resource: resource, EncryptedReceipt: base64.RawURLEncoding.EncodeToString(ciphertext), ReceiptDigest: hex.EncodeToString(digest[:])}, nil
}

func (h *FileTransferHandler) servePending(writer http.ResponseWriter, request *http.Request, requestID string, authorization Authorization) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	sessionID := request.URL.Query().Get("session_id")
	if sessionID == "" || authorization.SessionID != "" && sessionID != authorization.SessionID {
		writeHTTPError(writer, requestID, "not_found_or_forbidden", http.StatusNotFound, false)
		return
	}
	waitSeconds, err := strconv.Atoi(request.URL.Query().Get("wait_seconds"))
	if err != nil || waitSeconds < 0 || waitSeconds > 30 {
		writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
		return
	}
	deadline := time.NewTimer(time.Duration(waitSeconds) * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		transfers, err := h.config.Service.Pending(request.Context(), authorization.ClientID, sessionID, 10)
		if err != nil {
			writeFileTransferError(writer, requestID, err)
			return
		}
		if len(transfers) > 0 {
			writeJSON(writer, http.StatusOK, map[string]any{"transfers": opaquePendingTransfers(transfers)})
			return
		}
		if waitSeconds == 0 {
			writeJSON(writer, http.StatusOK, map[string]any{"transfers": []store.FileTransfer{}})
			return
		}
		select {
		case <-request.Context().Done():
			return
		case <-deadline.C:
			writeJSON(writer, http.StatusOK, map[string]any{"transfers": []store.FileTransfer{}})
			return
		case <-ticker.C:
		}
	}
}

func opaquePendingTransfers(transfers []store.FileTransfer) any {
	encrypted := make([]encryptedPendingBatch, 0)
	plain := make([]store.FileTransfer, 0)
	byTransfer := make(map[string]int)
	for _, transfer := range transfers {
		if transfer.E2EETransferID == "" {
			plain = append(plain, transfer)
			continue
		}
		index, ok := byTransfer[transfer.E2EETransferID]
		if !ok {
			index = len(encrypted)
			byTransfer[transfer.E2EETransferID] = index
			encrypted = append(encrypted, encryptedPendingBatch{TransferID: transfer.E2EETransferID, TransferGeneration: transfer.TransferGeneration, State: transfer.State, ExpiresAt: transfer.ExpiresAt.UTC().Truncate(time.Second)})
		}
		encrypted[index].Resources = append(encrypted[index].Resources, encryptedTransferResource{TransferID: transfer.ID, CommittedChunk: transfer.CommittedChunks, State: transfer.State, ExpiresAt: transfer.ExpiresAt.UTC().Truncate(time.Second)})
	}
	if len(encrypted) == 0 {
		return plain
	}
	if len(plain) == 0 {
		return encrypted
	}
	result := make([]any, 0, len(plain)+len(encrypted))
	for _, transfer := range plain {
		result = append(result, transfer)
	}
	for _, transfer := range encrypted {
		result = append(result, transfer)
	}
	return result
}

func (h *FileTransferHandler) serveReceipt(writer http.ResponseWriter, request *http.Request, requestID string, authorization Authorization, id string) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	transfer, ok := h.owned(writer, request, requestID, authorization, id)
	if !ok {
		return
	}
	if transfer.E2EETransferID != "" {
		h.serveEncryptedReceiptAcknowledgement(writer, request, requestID, authorization, transfer)
		return
	}
	var input struct {
		ResultCode string `json:"result_code"`
		Path       string `json:"path"`
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || !validReceipt(input.ResultCode, input.Path) {
		writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
		return
	}
	if err := h.config.Service.Receipt(request.Context(), id, transfer.DeliveryClientID, input.ResultCode, input.Path); err != nil {
		writeFileTransferError(writer, requestID, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (h *FileTransferHandler) serveEncryptedReceiptAcknowledgement(writer http.ResponseWriter, request *http.Request, requestID string, authorization Authorization, transfer store.FileTransfer) {
	material, peer, keyErr := h.config.TransferKeys.LoadBound(transfer.E2EETransferID, transfer.TransferGeneration)
	if keyErr == nil && transfer.SourceMachineID == peer.MachineID && transfer.DestinationMachineID != peer.MachineID {
		defer material.Destroy()
		h.serveEncryptedReverseReceipt(writer, request, requestID, authorization, transfer, peer, material)
		return
	}
	material.Destroy()
	if keyErr != nil && (transfer.State == "delivered" || transfer.State == "failed") {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	var input struct {
		ReceiptDigest string `json:"receipt_digest"`
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
		return
	}
	providedDigest, decodeErr := hex.DecodeString(input.ReceiptDigest)
	if decodeErr != nil || len(providedDigest) != sha256.Size || hex.EncodeToString(providedDigest) != input.ReceiptDigest {
		writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
		return
	}
	response, err := h.encryptedCompletion(request.Context(), authorization, transfer)
	if errors.Is(err, transfercrypto.ErrKeyUnavailable) {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	expectedDigest, decodeErr := hex.DecodeString(response.ReceiptDigest)
	if err != nil || decodeErr != nil || subtle.ConstantTimeCompare(providedDigest, expectedDigest) != 1 {
		writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
		return
	}
	if err := h.config.TransferKeys.Delete(transfer.E2EETransferID); err != nil {
		writeHTTPError(writer, requestID, "storage_unavailable", http.StatusServiceUnavailable, false)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (h *FileTransferHandler) serveEncryptedReverseReceipt(writer http.ResponseWriter, request *http.Request, requestID string, authorization Authorization, transfer store.FileTransfer, peer peercontext.Context, material transfercrypto.KeyMaterial) {
	if peer.AccountID != authorization.UserID || transfer.DeliveryClientID != authorization.ClientID {
		writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
		return
	}
	var input struct {
		EncryptedReceipt string `json:"encrypted_receipt"`
		ReceiptDigest    string `json:"receipt_digest"`
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, transfercrypto.ChunkSize+1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
		return
	}
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(input.EncryptedReceipt)
	digest := sha256.Sum256(ciphertext)
	if err != nil || base64.RawURLEncoding.EncodeToString(ciphertext) != input.EncryptedReceipt || input.ReceiptDigest != hex.EncodeToString(digest[:]) {
		writeHTTPError(writer, requestID, "invalid_request", http.StatusBadRequest, false)
		return
	}
	receipt, err := transfercrypto.DecryptFinalReceipt(material, recordContextDirection(peer, transfer.E2EETransferID, transfer.TransferGeneration, transfercrypto.DirectionFromMachine), ciphertext)
	transfers, batchErr := h.config.Service.Batch(request.Context(), transfer.BatchID)
	if err != nil || batchErr != nil || len(transfers) == 0 || len(receipt.Files) != len(transfers) {
		writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
		return
	}
	manifest := transfercrypto.Manifest{BatchID: transfer.E2EETransferID, Files: make([]transfercrypto.ManifestFile, len(transfers))}
	updates := make([]store.FileTransferReceipt, len(transfers))
	for _, item := range transfers {
		if item.E2EETransferID != transfer.E2EETransferID || item.TransferGeneration != transfer.TransferGeneration || item.FileOrdinal >= uint64(len(transfers)) || item.State != "pending" && item.State != "delivered" {
			writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
			return
		}
		plaintextDigest, decodeErr := hex.DecodeString(item.SHA256)
		if decodeErr != nil || len(plaintextDigest) != sha256.Size {
			writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
			return
		}
		var checksum [sha256.Size]byte
		copy(checksum[:], plaintextDigest)
		chunks := uint64(item.Size) / uint64(transfercrypto.ChunkSize)
		if item.Size%int64(transfercrypto.ChunkSize) != 0 || chunks == 0 {
			chunks++
		}
		manifest.Files[item.FileOrdinal] = transfercrypto.ManifestFile{TransferID: item.ID, FileOrdinal: item.FileOrdinal, Name: item.Basename, RelativeDestination: "Paperboat Inbox/" + item.Basename, Mode: 0o600, Size: uint64(item.Size), PlaintextSHA256: checksum, ChunkCount: chunks}
	}
	manifestHash, err := manifest.Hash()
	if err != nil || receipt.ManifestHash != manifestHash {
		writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
		return
	}
	for _, file := range receipt.Files {
		if file.FileOrdinal >= uint64(len(transfers)) {
			writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
			return
		}
		item := transfers[file.FileOrdinal]
		code, receiptPath := "stored", file.RelativePath
		if file.Result == transfercrypto.CollisionRejected {
			code, receiptPath = "invalid_path", ""
		} else if file.Result != transfercrypto.CollisionOriginal && file.Result != transfercrypto.CollisionRenamed || !strings.HasPrefix(file.RelativePath, "Paperboat Inbox/") {
			writeHTTPError(writer, requestID, "e2ee_authentication_failed", http.StatusBadRequest, false)
			return
		}
		updates[file.FileOrdinal] = store.FileTransferReceipt{ID: item.ID, ClientID: item.DeliveryClientID, ResultCode: code, Path: receiptPath}
	}
	if err := h.config.Service.ReceiptBatch(request.Context(), updates); err != nil {
		writeFileTransferError(writer, requestID, err)
		return
	}
	if err := h.config.TransferKeys.Delete(transfer.E2EETransferID); err != nil {
		writeHTTPError(writer, requestID, "storage_unavailable", http.StatusServiceUnavailable, false)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func validReceipt(code, path string) bool {
	if code == "stored" {
		return path != "" && !strings.HasPrefix(path, "/") && strings.HasPrefix(path, "Paperboat Inbox/")
	}
	if path != "" {
		return false
	}
	switch code {
	case "invalid_path", "invalid_size", "digest_mismatch", "offset_conflict", "recipient_unavailable", "storage_unavailable", "resource_limit", "canceled", "delivery_timeout":
		return true
	default:
		return false
	}
}

func (h *FileTransferHandler) owned(writer http.ResponseWriter, request *http.Request, requestID string, authorization Authorization, id string) (store.FileTransfer, bool) {
	transfer, err := h.config.Service.Get(request.Context(), id)
	owned := transfer.DeliveryClientID != "" && transfer.DeliveryClientID == authorization.ClientID && (authorization.SessionID == "" || transfer.SessionID == authorization.SessionID)
	if authorization.SourceMachineID != "" && transfer.SourceMachineID == authorization.SourceMachineID && (authorization.UserID == "" || transfer.InitiatingUserID == authorization.UserID) && (authorization.SessionID == "" || transfer.SessionID == authorization.SessionID) {
		owned = true
	}
	if authorization.MachineID != "" && transfer.DestinationMachineID == authorization.MachineID && (authorization.UserID == "" || transfer.InitiatingUserID == authorization.UserID) {
		owned = true
	}
	if h.config.Owns != nil {
		owned = h.config.Owns(authorization, transfer)
	}
	if err != nil || !owned {
		writeHTTPError(writer, requestID, "not_found_or_forbidden", http.StatusNotFound, false)
		return store.FileTransfer{}, false
	}
	return transfer, true
}
func methodNotAllowed(writer http.ResponseWriter, methods ...string) {
	writer.Header().Set("Allow", strings.Join(methods, ", "))
	http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}
func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
func writeFileTransferError(writer http.ResponseWriter, requestID string, err error) {
	code := fileTransferErrorCode(err)
	writeHTTPError(writer, requestID, code, fileTransferHTTPStatus(code), code == "storage_unavailable" || code == "resource_limit")
}
func fileTransferErrorCode(err error) string {
	var transferErr *filetransfer.Error
	if errors.As(err, &transferErr) {
		return string(transferErr.Code)
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "delivery_timeout"
	}
	return "storage_unavailable"
}
func fileTransferHTTPStatus(code string) int {
	switch code {
	case "invalid_path":
		return http.StatusNotFound
	case "invalid_size", "batch_limit":
		return http.StatusBadRequest
	case "offset_conflict":
		return http.StatusConflict
	case "no_active_writer", "recipient_unavailable":
		return http.StatusConflict
	case "digest_mismatch":
		return http.StatusUnprocessableEntity
	case "canceled":
		return 499
	case "resource_limit":
		return http.StatusTooManyRequests
	default:
		return http.StatusServiceUnavailable
	}
}
