package filetransfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const contentType = "application/offset+octet-stream"

const operationRecoveryWindow = 10 * time.Second

type Auth struct {
	Token     string
	ExpiresAt time.Time
}
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
type Source struct {
	Basename string
	Size     int64
	SHA256   [sha256.Size]byte
	Reader   io.ReadSeeker
}
type Manifest struct {
	TransferID      string    `json:"transfer_id"`
	BatchID         string    `json:"batch_id"`
	Direction       string    `json:"direction"`
	SessionID       string    `json:"session_id"`
	Basename        string    `json:"basename"`
	Size            int64     `json:"size"`
	SHA256          string    `json:"sha256"`
	CommittedOffset int64     `json:"committed_offset"`
	State           string    `json:"state"`
	ResultCode      string    `json:"result_code,omitempty"`
	ReceiptPath     string    `json:"receipt_path,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}
type Batch struct {
	BatchID   string     `json:"batch_id"`
	Transfers []Manifest `json:"transfers"`
	Paths     []string   `json:"-"`
}
type completion struct {
	Transfer Manifest `json:"transfer"`
	Result   struct {
		Code string `json:"code"`
		Path string `json:"path"`
	} `json:"result"`
}

type Error struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	RequestID  string `json:"request_id,omitempty"`
	Retryable  bool   `json:"retryable"`
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("file transfer failed (%s): %s", e.Code, e.Message)
	}
	return "file transfer failed: " + e.Code
}

type Client struct {
	Endpoint      string
	HTTPClient    *http.Client
	RefreshAuth   func(context.Context) (Auth, error)
	MaxConcurrent int
	authMu        sync.RWMutex
	refreshMu     sync.Mutex
	auth          Auth
}

func NewClient(endpoint string, auth Auth, client *http.Client) *Client {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	return &Client{Endpoint: strings.TrimRight(endpoint, "/"), HTTPClient: client, MaxConcurrent: 2, auth: auth}
}

func (c *Client) UpdateAuth(auth Auth) { c.setAuth(auth) }

func (c *Client) Close() error {
	if c == nil || c.HTTPClient == nil || c.HTTPClient.Transport == nil {
		return nil
	}
	if closer, ok := c.HTTPClient.Transport.(io.Closer); ok {
		return closer.Close()
	}
	if closer, ok := c.HTTPClient.Transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	return nil
}

func (c *Client) VerifyPolicy(ctx context.Context, expected Policy) error {
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return err
	}
	u.Path, u.RawPath, u.RawQuery, u.Fragment = "/healthz", "", "", ""
	response, err := c.requestWithHeaders(ctx, http.MethodGet, u.String(), operationID("policy", u.Host), nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var capability struct {
		Policy Policy `json:"file_transfer_policy"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(&capability); err != nil {
		return err
	}
	if capability.Policy != expected {
		return errors.New("file transfer policy mismatch")
	}
	return nil
}

func (c *Client) UploadBatch(ctx context.Context, batchID, sessionID string, sources []Source) (Batch, error) {
	return c.uploadBatch(ctx, batchID, sessionID, "pb_to_pbh", sources)
}
func (c *Client) SendBatch(ctx context.Context, batchID, sessionID string, sources []Source) (Batch, error) {
	return c.uploadBatch(ctx, batchID, sessionID, "pbh_to_pb", sources)
}
func (c *Client) uploadBatch(ctx context.Context, batchID, sessionID, direction string, sources []Source) (Batch, error) {
	if len(sources) < 1 || len(sources) > 10 {
		return Batch{}, errors.New("file transfer batch must contain one through ten files")
	}
	files := make([]map[string]any, len(sources))
	for i, source := range sources {
		if source.Reader == nil || source.Size < 0 {
			return Batch{}, errors.New("invalid file transfer source")
		}
		files[i] = map[string]any{"basename": source.Basename, "size": source.Size, "sha256": hex.EncodeToString(source.SHA256[:])}
	}
	payload, _ := json.Marshal(map[string]any{"batch_id": batchID, "direction": direction, "session_id": sessionID, "files": files})
	var batch Batch
	if err := c.retryJSONRequest(ctx, http.MethodPost, c.Endpoint, operationID("create", batchID), "application/json", 0, payload, &batch); err != nil {
		return Batch{}, err
	}
	if len(batch.Transfers) != len(sources) {
		return Batch{}, errors.New("file transfer create returned wrong manifest count")
	}
	workers := c.MaxConcurrent
	if workers < 1 {
		workers = 2
	}
	if workers > 2 {
		workers = 2
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	errs := make(chan error, len(sources))
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				if err := c.uploadOne(workCtx, batch.Transfers[index], sources[index]); err != nil {
					errs <- err
					cancel()
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for i := range sources {
			select {
			case jobs <- i:
			case <-workCtx.Done():
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		c.cancelBatch(batch.Transfers)
		return Batch{}, err
	}
	batch.Paths = make([]string, len(batch.Transfers))
	for i := range batch.Transfers {
		var completed completion
		if err := c.retryJSONRequest(ctx, http.MethodPost, c.Endpoint+"/"+batch.Transfers[i].TransferID+"/complete", operationID("complete", batch.Transfers[i].TransferID), "", 0, nil, &completed); err != nil {
			c.cancelBatch(batch.Transfers)
			return Batch{}, err
		}
		if direction == "pb_to_pbh" && (completed.Result.Code != "published" || completed.Result.Path == "") || direction == "pbh_to_pb" && completed.Result.Code != "pending" {
			c.cancelBatch(batch.Transfers)
			return Batch{}, errors.New("helper did not publish completed transfer")
		}
		batch.Transfers[i] = completed.Transfer
		if direction == "pb_to_pbh" {
			batch.Paths[i] = completed.Result.Path
		}
	}
	return batch, nil
}

func (c *Client) cancelBatch(transfers []Manifest) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, manifest := range transfers {
		_ = c.Cancel(ctx, manifest.TransferID)
	}
}

func (c *Client) WaitReceipt(ctx context.Context, id string) (Manifest, error) {
	for {
		var manifest Manifest
		if err := c.jsonRequest(ctx, http.MethodGet, c.Endpoint+"/"+id, operationID("status", id), "", 0, nil, &manifest); err != nil {
			var responseErr *Error
			if errors.As(err, &responseErr) {
				return Manifest{}, err
			}
			select {
			case <-ctx.Done():
				return Manifest{}, ctx.Err()
			case <-time.After(250 * time.Millisecond):
				continue
			}
		}
		switch manifest.State {
		case "delivered":
			return manifest, nil
		case "failed":
			return manifest, errors.New("file delivery failed: " + manifest.ResultCode)
		case "canceled":
			return manifest, errors.New("file delivery canceled")
		}
		select {
		case <-ctx.Done():
			return Manifest{}, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (c *Client) Pending(ctx context.Context, sessionID string, waitSeconds int) ([]Manifest, error) {
	if sessionID == "" || waitSeconds < 0 || waitSeconds > 30 {
		return nil, errors.New("invalid pending transfer request")
	}
	target := c.Endpoint + "/pending?session_id=" + url.QueryEscape(sessionID) + "&wait_seconds=" + strconv.Itoa(waitSeconds)
	var response struct {
		Transfers []Manifest `json:"transfers"`
	}
	if err := c.jsonRequest(ctx, http.MethodGet, target, operationID("pending", sessionID), "", 0, nil, &response); err != nil {
		return nil, err
	}
	return response.Transfers, nil
}

func (c *Client) Content(ctx context.Context, manifest Manifest, offset int64) (*http.Response, error) {
	if offset < 0 || offset > manifest.Size || len(manifest.SHA256) != 64 {
		return nil, errors.New("invalid content download request")
	}
	headers := make(http.Header)
	headers.Set("If-Match", `"sha256:`+manifest.SHA256+`"`)
	if offset > 0 {
		headers.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
	}
	return c.requestWithHeaders(ctx, http.MethodGet, c.Endpoint+"/"+manifest.TransferID+"/content", operationID("download", manifest.TransferID), headers)
}

func (c *Client) Receipt(ctx context.Context, id, resultCode, path string) error {
	payload, err := json.Marshal(map[string]string{"result_code": resultCode, "path": path})
	if err != nil {
		return err
	}
	return c.jsonRequest(ctx, http.MethodPost, c.Endpoint+"/"+id+"/receipt", operationID("receipt", id), "application/json", 0, bytes.NewReader(payload), nil)
}

func (c *Client) requestWithHeaders(ctx context.Context, method, target, operation string, headers http.Header) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if err := c.refreshIfExpiring(ctx); err != nil {
			return nil, err
		}
		request, err := http.NewRequestWithContext(ctx, method, target, nil)
		if err != nil {
			return nil, err
		}
		request.Header = headers.Clone()
		if request.Header == nil {
			request.Header = make(http.Header)
		}
		request.Header.Set("Authorization", "Bearer "+c.currentAuth().Token)
		request.Header.Set("X-Paperboat-Request-ID", operation)
		request.Header.Set("X-Paperboat-Operation-ID", operation)
		response, err := c.HTTPClient.Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return response, nil
		}
		failure := decodeError(response)
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 && c.RefreshAuth != nil {
			old := c.currentAuth()
			c.refreshMu.Lock()
			if c.currentAuth() == old {
				fresh, refreshErr := c.RefreshAuth(ctx)
				if refreshErr != nil {
					c.refreshMu.Unlock()
					return nil, errors.Join(failure, refreshErr)
				}
				c.setAuth(fresh)
			}
			c.refreshMu.Unlock()
			continue
		}
		return nil, failure
	}
	return nil, errors.New("file transfer authorization retry exhausted")
}

func (c *Client) uploadOne(ctx context.Context, manifest Manifest, source Source) error {
	for attempts := 0; attempts < 4; attempts++ {
		offset, err := c.Offset(ctx, manifest.TransferID)
		if err != nil {
			var responseErr *Error
			if errors.As(err, &responseErr) {
				return err
			}
			if waitErr := waitOperationRetry(ctx, attempts); waitErr != nil {
				return waitErr
			}
			continue
		}
		if offset == source.Size {
			return nil
		}
		if offset < 0 || offset > source.Size {
			return errors.New("helper returned invalid committed offset")
		}
		err = c.patchRequest(ctx, manifest.TransferID, offset, source)
		if err == nil {
			continue
		}
		var responseErr *Error
		if errors.As(err, &responseErr) {
			return err
		}
		// The request outcome is uncertain. The next HEAD is authoritative.
	}
	return errors.New("file transfer did not reach its declared size")
}

func (c *Client) Offset(ctx context.Context, id string) (int64, error) {
	response, err := c.request(ctx, http.MethodHead, c.Endpoint+"/"+id+"/content", operationID("head", id), "", 0, nil)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	offset, err := strconv.ParseInt(response.Header.Get("Upload-Offset"), 10, 64)
	if err != nil {
		return 0, errors.New("helper returned invalid Upload-Offset")
	}
	return offset, nil
}

func (c *Client) Cancel(ctx context.Context, id string) error {
	return c.rawRequest(ctx, http.MethodDelete, c.Endpoint+"/"+id, operationID("cancel", id), "", 0, nil, nil)
}

func (c *Client) patchRequest(ctx context.Context, id string, offset int64, source Source) error {
	response, err := c.requestWithBody(ctx, http.MethodPatch, c.Endpoint+"/"+id+"/content", operationID("patch", id), contentType, offset, func() (io.Reader, error) {
		if _, err := source.Reader.Seek(offset, io.SeekStart); err != nil {
			return nil, err
		}
		return io.LimitReader(source.Reader, source.Size-offset), nil
	})
	if response != nil {
		_ = response.Body.Close()
	}
	return err
}

func (c *Client) jsonRequest(ctx context.Context, method, url, operation, mediaType string, offset int64, body io.Reader, target any) error {
	response, err := c.request(ctx, method, url, operation, mediaType, offset, body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if target == nil {
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func (c *Client) retryJSONRequest(ctx context.Context, method, url, operation, mediaType string, offset int64, body []byte, target any) error {
	retryCtx, cancel := context.WithTimeout(ctx, operationRecoveryWindow)
	defer cancel()
	for attempt := 0; ; attempt++ {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		err := c.jsonRequest(retryCtx, method, url, operation, mediaType, offset, reader, target)
		if err == nil {
			return nil
		}
		var responseErr *Error
		if errors.As(err, &responseErr) {
			return err
		}
		if waitErr := waitOperationRetry(retryCtx, attempt); waitErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
	}
}

func waitOperationRetry(ctx context.Context, attempt int) error {
	delay := 100 * time.Millisecond
	for index := 0; index < attempt && delay < time.Second; index++ {
		delay *= 2
	}
	if delay > time.Second {
		delay = time.Second
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (c *Client) rawRequest(ctx context.Context, method, url, operation, mediaType string, offset int64, body io.Reader, target any) error {
	return c.jsonRequest(ctx, method, url, operation, mediaType, offset, body, target)
}

func (c *Client) request(ctx context.Context, method, url, operation, mediaType string, offset int64, body io.Reader) (*http.Response, error) {
	var replay []byte
	if body != nil {
		var err error
		replay, err = io.ReadAll(body)
		if err != nil {
			return nil, err
		}
	}
	return c.requestWithBody(ctx, method, url, operation, mediaType, offset, func() (io.Reader, error) {
		if replay == nil {
			return nil, nil
		}
		return bytes.NewReader(replay), nil
	})
}

func (c *Client) requestWithBody(ctx context.Context, method, url, operation, mediaType string, offset int64, body func() (io.Reader, error)) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if err := c.refreshIfExpiring(ctx); err != nil {
			return nil, err
		}
		requestBody, err := body()
		if err != nil {
			return nil, err
		}
		request, err := http.NewRequestWithContext(ctx, method, url, requestBody)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "Bearer "+c.currentAuth().Token)
		request.Header.Set("X-Paperboat-Request-ID", operation)
		request.Header.Set("X-Paperboat-Operation-ID", operation)
		if mediaType != "" {
			request.Header.Set("Content-Type", mediaType)
		}
		if method == http.MethodPatch {
			request.Header.Set("Upload-Offset", strconv.FormatInt(offset, 10))
		}
		response, err := c.HTTPClient.Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return response, nil
		}
		failure := decodeError(response)
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 && c.RefreshAuth != nil {
			old := c.currentAuth()
			c.refreshMu.Lock()
			if c.currentAuth() == old {
				fresh, refreshErr := c.RefreshAuth(ctx)
				if refreshErr != nil {
					c.refreshMu.Unlock()
					return nil, errors.Join(failure, refreshErr)
				}
				c.setAuth(fresh)
			}
			c.refreshMu.Unlock()
			continue
		}
		return nil, failure
	}
	return nil, errors.New("file transfer authorization retry exhausted")
}

func (c *Client) refreshIfExpiring(ctx context.Context) error {
	if c.RefreshAuth == nil {
		return nil
	}
	current := c.currentAuth()
	if current.ExpiresAt.IsZero() || time.Until(current.ExpiresAt) > 30*time.Second {
		return nil
	}
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	current = c.currentAuth()
	if current.ExpiresAt.IsZero() || time.Until(current.ExpiresAt) > 30*time.Second {
		return nil
	}
	fresh, err := c.RefreshAuth(ctx)
	if err != nil {
		return err
	}
	c.setAuth(fresh)
	return nil
}
func decodeError(response *http.Response) error {
	defer response.Body.Close()
	failure := &Error{Code: "http_error", StatusCode: response.StatusCode}
	_ = json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(failure)
	if failure.Code == "" {
		failure.Code = "http_error"
	}
	return failure
}
func (c *Client) currentAuth() Auth { c.authMu.RLock(); defer c.authMu.RUnlock(); return c.auth }
func (c *Client) setAuth(auth Auth) { c.authMu.Lock(); c.auth = auth; c.authMu.Unlock() }
func operationID(kind, value string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + value))
	return "ft_" + kind + "_" + hex.EncodeToString(sum[:16])
}
