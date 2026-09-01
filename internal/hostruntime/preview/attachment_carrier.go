package preview

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat/internal/api"
)

var (
	ErrAttachmentCarrierInvalid     = errors.New("invalid preview attachment carrier")
	ErrAttachmentCarrierClosed      = errors.New("preview attachment carrier is closed")
	ErrAttachmentCarrierUnavailable = errors.New("preview attachment carrier is unavailable")
)

// AttachmentAllocator is the small request/response boundary used by the
// lazy carrier. AttachmentClient is the production implementation; the
// interface keeps lifecycle tests independent of HTTP while preserving the
// exact server-issued attachment contract.
type AttachmentAllocator interface {
	Allocate(context.Context, AttachmentRequest) (Attachment, error)
}

// AttachmentCarrierConfig composes the machine-proof attachment client with
// the route-scoped provider. Allocation is intentionally lazy because the
// create operation ID exists only after the server creates the preview lease.
type AttachmentCarrierConfig struct {
	Attachments AttachmentAllocator
	Provider    PreviewCarrierProvider

	RequestID     func() (string, error)
	CorrelationID func() (string, error)
	CloseTimeout  time.Duration
}

// AttachmentCarrier allocates one short-lived server attachment on the first
// carrier attempt, then delegates streams to the provider's generation-fenced
// DataCarrierPreviewHub. The request is retained across retry attempts so an
// uncertain HTTP result replays the same operation/body hash rather than
// accidentally creating a conflicting attachment.
type AttachmentCarrier struct {
	attachments AttachmentAllocator
	provider    PreviewCarrierProvider
	requestID   func() (string, error)
	correlation func() (string, error)
	closeWait   time.Duration

	mu      sync.Mutex
	closed  bool
	request AttachmentRequest
	set     bool
	current Carrier
}

func NewAttachmentCarrier(config AttachmentCarrierConfig) (*AttachmentCarrier, error) {
	if config.Attachments == nil || config.Provider == nil {
		return nil, ErrAttachmentCarrierInvalid
	}
	if config.CloseTimeout == 0 {
		config.CloseTimeout = PreviewLeaseDefaultShutdown
	}
	if config.CloseTimeout <= 0 || config.CloseTimeout > time.Minute {
		return nil, ErrAttachmentCarrierInvalid
	}
	if config.RequestID == nil {
		config.RequestID = func() (string, error) { return newAttachmentTraceID("request_") }
	}
	if config.CorrelationID == nil {
		config.CorrelationID = func() (string, error) { return newAttachmentTraceID("correlation_") }
	}
	return &AttachmentCarrier{
		attachments: config.Attachments,
		provider:    config.Provider,
		requestID:   config.RequestID,
		correlation: config.CorrelationID,
		closeWait:   config.CloseTimeout,
	}, nil
}

func (c *AttachmentCarrier) Run(ctx context.Context, lease Lease, ready func(Lease) error) error {
	if c == nil || ctx == nil || ready == nil {
		return ErrAttachmentCarrierInvalid
	}
	request, err := c.requestForLease(lease)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrAttachmentCarrierClosed
	}
	c.mu.Unlock()
	attachment, err := c.attachments.Allocate(ctx, request)
	if err != nil {
		return classifyAttachmentCarrierError(err)
	}
	if waiter, ok := c.attachments.(AttachmentAdmissionWaiter); ok {
		attachment, err = waiter.WaitForAdmission(ctx, request, attachment)
		if err != nil {
			return classifyAttachmentCarrierError(err)
		}
	} else if attachment.State == "pending" {
		return classifyAttachmentCarrierError(ErrAttachmentAdmissionPending)
	}
	carrier, err := c.provider.CarrierForAttachment(ctx, lease, attachment)
	if err != nil {
		return classifyAttachmentCarrierError(err)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.closeWait)
		defer cancel()
		_ = carrier.Close(closeCtx)
		return ErrAttachmentCarrierClosed
	}
	c.current = carrier
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.current == carrier {
			c.current = nil
		}
		c.mu.Unlock()
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.closeWait)
		defer cancel()
		_ = carrier.Close(closeCtx)
	}()
	var observedAttachment = attachment
	return carrier.Run(ctx, lease, func(observed Lease) error {
		if observedAttachment.State != "ready" || !observedAttachment.OriginReady {
			observer, ok := c.attachments.(AttachmentReadinessObserver)
			if !ok {
				return classifyAttachmentCarrierError(fmt.Errorf("%w: attachment readiness observer is unavailable", ErrAttachmentClientUnavailable))
			}
			next, err := observer.ObserveOrigin(ctx, request, observedAttachment, observed.OriginState == "ready")
			if err != nil {
				return classifyAttachmentCarrierError(err)
			}
			observedAttachment = next
		}
		return ready(observed)
	})
}

func (c *AttachmentCarrier) requestForLease(lease Lease) (AttachmentRequest, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return AttachmentRequest{}, ErrAttachmentCarrierClosed
	}
	if c.set {
		if c.request.PreviewID != lease.ID || c.request.OperationID != lease.CreateOperationID || c.request.OwnerDeviceID != lease.OwnerDeviceID || c.request.OwnerSessionID != lease.OwnerSessionID {
			return AttachmentRequest{}, fmt.Errorf("%w: lease identity changed during retry", ErrAttachmentCarrierInvalid)
		}
		// Lease renewal advances only the strong ETag. The signed operation
		// body remains immutable, but subsequent If-Match headers must use
		// the latest lease generation.
		if strings.TrimSpace(lease.ETag) != "" && lease.ETag != c.request.LeaseETag {
			if err := api.ValidatePreviewLeaseETag(lease.ID, lease.ETag); err != nil {
				return AttachmentRequest{}, fmt.Errorf("%w: renewed lease ETag: %v", ErrAttachmentCarrierInvalid, err)
			}
			c.request.LeaseETag = strings.TrimSpace(lease.ETag)
		}
		return c.request, nil
	}
	requestID, err := c.requestID()
	if err != nil {
		return AttachmentRequest{}, errors.Join(ErrAttachmentCarrierUnavailable, err)
	}
	correlationID, err := c.correlation()
	if err != nil {
		return AttachmentRequest{}, errors.Join(ErrAttachmentCarrierUnavailable, err)
	}
	request, err := AttachmentRequestForLease(lease, strings.TrimSpace(requestID), strings.TrimSpace(correlationID))
	if err != nil {
		return AttachmentRequest{}, err
	}
	c.request = request
	c.set = true
	return request, nil
}

func classifyAttachmentCarrierError(err error) error {
	if err == nil {
		return nil
	}
	var httpErr *AttachmentHTTPError
	if errors.As(err, &httpErr) && httpErr.Retryable {
		return &RetryableCarrierError{Err: err}
	}
	if errors.Is(err, ErrAttachmentClientUnavailable) || errors.Is(err, ErrPreviewCarrierProviderUnavailable) {
		return &RetryableCarrierError{Err: err}
	}
	if errors.Is(err, ErrAttachmentAdmissionPending) {
		return &RetryableCarrierError{Err: err}
	}
	// Hostd owns renewal while carrier admission and origin probing are in
	// flight. A successful renewal can therefore make the readiness If-Match
	// stale. Retry the same attachment operation with Session.currentLease;
	// requestForLease updates only the transport ETag and keeps the immutable
	// operation body and endpoint identity.
	if errors.Is(err, ErrAttachmentLeaseETagStale) {
		return &RetryableCarrierError{Err: err}
	}
	return err
}

func (c *AttachmentCarrier) Close(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrAttachmentCarrierInvalid
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	carrier := c.current
	c.current = nil
	c.mu.Unlock()
	if carrier == nil {
		return nil
	}
	return carrier.Close(ctx)
}

func newAttachmentTraceID(prefix string) (string, error) {
	value, err := api.NewPreviewLeaseIdempotencyKey()
	if err != nil {
		return "", err
	}
	return prefix + strings.TrimPrefix(value, "preview_"), nil
}

var _ Carrier = (*AttachmentCarrier)(nil)
var _ AttachmentAllocator = (*AttachmentClient)(nil)
