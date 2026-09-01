package preview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const ownerSessionLeaseResponseLimit = 16 << 10

const (
	ownerSessionLeaseAcquireAttempts   = 2
	ownerSessionLeaseAcquireRetryDelay = 25 * time.Millisecond
)

type ownerSessionLeaseTransportError struct{ err error }

func (e *ownerSessionLeaseTransportError) Error() string {
	if e == nil || e.err == nil {
		return "owner-session lease transport failed"
	}
	return e.err.Error()
}

func (e *ownerSessionLeaseTransportError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

// LocalOwnerSessionClient talks only to the authenticated loopback hostd
// owner-lease endpoint. Its control token is read from the owner-only runtime
// state directory and its lease token is held in memory for one foreground
// process.
type LocalOwnerSessionClient struct {
	base  *url.URL
	token string
	http  *http.Client
	now   func() time.Time
}

func NewLocalOwnerSessionClient(endpoint, controlToken string, client *http.Client) (*LocalOwnerSessionClient, error) {
	base, err := LocalOwnerSessionEndpoint(endpoint)
	if err != nil || strings.TrimSpace(controlToken) == "" {
		return nil, ErrOwnerSessionLeaseInvalid
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	} else {
		copy := *client
		client = &copy
	}
	// The endpoint is a local capability boundary. Redirects could otherwise
	// disclose the bearer control token to an attacker-controlled destination.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrOwnerSessionLeaseInvalid }
	return &LocalOwnerSessionClient{base: base, token: strings.TrimSpace(controlToken), http: client, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (c *LocalOwnerSessionClient) Acquire(ctx context.Context, ownerSessionID string, target LeaseTarget) (OwnerSessionLease, error) {
	key, err := newSessionIdempotencyKey(nil)
	if err != nil {
		return OwnerSessionLease{}, err
	}
	return c.AcquireWithKey(ctx, ownerSessionID, target, key)
}

// AcquireWithKey is the retry-safe form of Acquire. Callers that observe an
// uncertain POST can replay the exact idempotency key and body; hostd will
// return the original lease rather than minting another owner session.
func (c *LocalOwnerSessionClient) AcquireWithKey(ctx context.Context, ownerSessionID string, target LeaseTarget, key string) (OwnerSessionLease, error) {
	if c == nil || ctx == nil || !validLocalTrace(key) {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseInvalid
	}
	ownerSessionID = strings.TrimSpace(ownerSessionID)
	if ownerSessionID != "" && !validLeaseID(ownerSessionID) {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseInvalid
	}
	if err := validateLeaseTarget(target); err != nil {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseInvalid
	}
	body, err := json.Marshal(OwnerSessionLeaseRequest{OwnerSessionID: ownerSessionID, Target: target})
	if err != nil {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseInvalid
	}
	var lastErr error
	for attempt := 0; attempt < ownerSessionLeaseAcquireAttempts; attempt++ {
		response, data, requestErr := c.do(ctx, http.MethodPost, "/v1/preview-owner-sessions", bytes.NewReader(body), key, "")
		if requestErr == nil {
			if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
				return OwnerSessionLease{}, ownerSessionLeaseHTTPError(response.StatusCode, data)
			}
			lease, decodeErr := decodeOwnerSessionLease(data)
			if decodeErr != nil {
				return OwnerSessionLease{}, decodeErr
			}
			if lease.Target != target || lease.MachineID == "" || !lease.ExpiresAt.After(c.now().UTC()) {
				return OwnerSessionLease{}, ErrOwnerSessionLeaseInvalid
			}
			lease.idempotencyKey = key
			return lease, nil
		}
		lastErr = requestErr
		var transportErr *ownerSessionLeaseTransportError
		if !errors.As(requestErr, &transportErr) || attempt+1 >= ownerSessionLeaseAcquireAttempts {
			return OwnerSessionLease{}, requestErr
		}
		if err := waitOwnerSessionLeaseRetry(ctx); err != nil {
			return OwnerSessionLease{}, err
		}
	}
	return OwnerSessionLease{}, lastErr
}

func waitOwnerSessionLeaseRetry(ctx context.Context) error {
	timer := time.NewTimer(ownerSessionLeaseAcquireRetryDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *LocalOwnerSessionClient) Heartbeat(ctx context.Context, lease OwnerSessionLease) (OwnerSessionLease, error) {
	if c == nil || ctx == nil || !validLeaseID(lease.ID) || strings.TrimSpace(lease.Token) == "" {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseInvalid
	}
	response, data, err := c.do(ctx, http.MethodPut, "/v1/preview-owner-sessions/"+url.PathEscape(lease.ID), nil, "", lease.Token)
	if err != nil {
		return OwnerSessionLease{}, err
	}
	if response.StatusCode != http.StatusOK {
		return OwnerSessionLease{}, ownerSessionLeaseHTTPError(response.StatusCode, data)
	}
	updated, err := decodeOwnerSessionLease(data)
	if err != nil {
		return OwnerSessionLease{}, err
	}
	if updated.ID != lease.ID || updated.OwnerSessionID != lease.OwnerSessionID || updated.Target != lease.Target || updated.Token != lease.Token || !updated.ExpiresAt.After(c.now().UTC()) {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseInvalid
	}
	updated.idempotencyKey = lease.idempotencyKey
	return updated, nil
}

func (c *LocalOwnerSessionClient) Release(ctx context.Context, lease OwnerSessionLease) error {
	if c == nil || ctx == nil || !validLeaseID(lease.ID) || strings.TrimSpace(lease.Token) == "" {
		return ErrOwnerSessionLeaseInvalid
	}
	response, data, err := c.do(ctx, http.MethodDelete, "/v1/preview-owner-sessions/"+url.PathEscape(lease.ID), nil, "", lease.Token)
	if err != nil {
		return err
	}
	if response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusGone || response.StatusCode == http.StatusNotFound {
		return nil
	}
	return ownerSessionLeaseHTTPError(response.StatusCode, data)
}

// KeepAlive heartbeats until ctx is canceled or hostd fences the lease. A
// heartbeat failure is returned to the caller so it can stop the foreground
// session instead of silently letting the remote owner lifetime expire.
func (c *LocalOwnerSessionClient) KeepAlive(ctx context.Context, lease OwnerSessionLease) error {
	if c == nil || ctx == nil {
		return ErrOwnerSessionLeaseInvalid
	}
	current := lease
	for {
		interval := time.Until(current.ExpiresAt.UTC()) / 3
		if interval < time.Second {
			interval = time.Second
		}
		if interval > 5*time.Second {
			interval = 5 * time.Second
		}
		timer := time.NewTimer(interval)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil
		}
		updated, err := c.Heartbeat(ctx, current)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		current = updated
	}
}

func (c *LocalOwnerSessionClient) do(ctx context.Context, method, path string, body io.Reader, idempotencyKey, leaseToken string) (*http.Response, []byte, error) {
	endpoint := *c.base
	endpoint.Path = strings.TrimRight(c.base.Path, "/") + path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if leaseToken != "" {
		request.Header.Set("X-Paperboat-Owner-Session-Token", leaseToken)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, nil, &ownerSessionLeaseTransportError{err: err}
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, ownerSessionLeaseResponseLimit+1))
	if err != nil || len(data) > ownerSessionLeaseResponseLimit {
		return response, nil, ErrOwnerSessionLeaseInvalid
	}
	return response, data, nil
}

func decodeOwnerSessionLease(data []byte) (OwnerSessionLease, error) {
	if len(data) > ownerSessionLeaseResponseLimit || rejectAttachmentDuplicateFields(data) != nil {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseInvalid
	}
	var lease OwnerSessionLease
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lease); err != nil {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseInvalid
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || lease.Schema != OwnerSessionLeaseSchema || !validLeaseID(lease.ID) || !validLeaseID(lease.MachineID) || !validLeaseID(lease.OwnerSessionID) || strings.TrimSpace(lease.Token) == "" {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseInvalid
	}
	if err := validateLeaseTarget(lease.Target); err != nil {
		return OwnerSessionLease{}, ErrOwnerSessionLeaseInvalid
	}
	return lease, nil
}

func ownerSessionLeaseHTTPError(status int, data []byte) error {
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &envelope)
	}
	switch envelope.Error.Code {
	case "owner_session_unauthorized":
		return ErrOwnerSessionLeaseUnauthorized
	case "owner_session_conflict":
		return ErrOwnerSessionLeaseConflict
	case "owner_session_limit":
		return ErrOwnerSessionLeaseLimit
	case "owner_session_lost":
		return ErrOwnerSessionLeaseLost
	default:
		if status == http.StatusUnauthorized {
			return ErrOwnerSessionLeaseUnauthorized
		}
		if status == http.StatusGone || status == http.StatusNotFound {
			return ErrOwnerSessionLeaseLost
		}
		return fmt.Errorf("%w: status %d", ErrOwnerSessionLeaseInvalid, status)
	}
}
