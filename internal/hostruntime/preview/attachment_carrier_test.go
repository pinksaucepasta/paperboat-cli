package preview

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestAttachmentCarrierRetainsOperationRequestAcrossRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Now().UTC()
	identity := testPreviewCarrierIdentity(1)
	lease, attachment := providerTestLeaseAttachment(t, now, "preview_lazy", "operation_lazy_01", "route_lazy_01", identity, 1)
	var (
		mu       sync.Mutex
		requests []AttachmentRequest
		attempt  int
	)
	allocator := attachmentAllocatorFunc(func(ctx context.Context, request AttachmentRequest) (Attachment, error) {
		if err := ctx.Err(); err != nil {
			return Attachment{}, err
		}
		mu.Lock()
		requests = append(requests, request)
		attempt++
		current := attempt
		mu.Unlock()
		result := attachment
		result.RequestID = request.RequestID
		result.CorrelationID = request.CorrelationID
		var err error
		result.RequestHash, err = request.Hash(result.AccountID)
		if err != nil {
			return Attachment{}, err
		}
		if current == 0 {
			return Attachment{}, errors.New("unreachable")
		}
		return result, nil
	})
	provider := &carrierProviderFunc{newCarrier: func() Carrier {
		return &sessionCarrier{run: func(context.Context, Lease, func(Lease) error) error {
			mu.Lock()
			current := attempt
			mu.Unlock()
			if current == 1 {
				return &RetryableCarrierError{Err: errors.New("edge disconnected")}
			}
			return nil
		}}
	}}
	requestCalls := 0
	carrier, err := NewAttachmentCarrier(AttachmentCarrierConfig{
		Attachments: allocator, Provider: provider,
		RequestID: func() (string, error) {
			requestCalls++
			return "request_lazy_01", nil
		},
		CorrelationID: func() (string, error) { return "correlation_lazy_01", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	err = carrier.Run(ctx, lease, func(Lease) error { return nil })
	var retryable *RetryableCarrierError
	if !errors.As(err, &retryable) {
		t.Fatalf("first run error = %v, want retryable", err)
	}
	if err := carrier.Run(ctx, lease, func(Lease) error { return nil }); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gotRequests := append([]AttachmentRequest(nil), requests...)
	mu.Unlock()
	if len(gotRequests) != 2 || gotRequests[0] != gotRequests[1] {
		t.Fatalf("attachment requests across retry = %#v, want identical operation/body envelope", gotRequests)
	}
	if requestCalls != 1 {
		t.Fatalf("request ID callbacks = %d, want one retained request across retries", requestCalls)
	}
	if err := carrier.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAttachmentCarrierRequiresDurableCreateOperation(t *testing.T) {
	carrier, err := NewAttachmentCarrier(AttachmentCarrierConfig{
		Attachments: attachmentAllocatorFunc(func(context.Context, AttachmentRequest) (Attachment, error) { return Attachment{}, nil }),
		Provider:    carrierProviderFunc{newCarrier: func() Carrier { return &sessionCarrier{} }},
	})
	if err != nil {
		t.Fatal(err)
	}
	lease := Lease{ID: "preview_missing", OwnerDeviceID: "machine_01", OwnerSessionID: "owner_session_01"}
	if err := carrier.Run(context.Background(), lease, func(Lease) error { return nil }); !errors.Is(err, ErrAttachmentBinding) {
		t.Fatalf("missing create operation error = %v, want binding error", err)
	}
	if err := carrier.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAttachmentCarrierRetriesStaleLeaseETag(t *testing.T) {
	err := classifyAttachmentCarrierError(errors.Join(ErrAttachmentLeaseETagStale, &AttachmentHTTPError{StatusCode: 412}))
	var retryable *RetryableCarrierError
	if !errors.As(err, &retryable) || !errors.Is(err, ErrAttachmentLeaseETagStale) {
		t.Fatalf("stale ETag error = %v, want retryable stale precondition", err)
	}
}

func TestAttachmentCarrierAdmitsBeforeProviderAndObservesOriginBeforeLeaseReady(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	identity := testPreviewCarrierIdentity(1)
	lease, base := providerTestLeaseAttachment(t, now, "preview_admit", "operation_admit_01", "route_admit_01", identity, 1)
	pending := base
	pending.State, pending.EdgeReady, pending.OriginReady = "pending", false, false
	admitted := pending
	admitted.State, admitted.AttachmentGeneration = "admitted", 2
	readyAttachment := admitted
	readyAttachment.State, readyAttachment.EdgeReady, readyAttachment.OriginReady = "ready", true, true
	readyAttachment.AttachmentGeneration = 3
	allocator := &recordingAttachmentAllocator{pending: pending, admitted: admitted, ready: readyAttachment}
	carrier, err := NewAttachmentCarrier(AttachmentCarrierConfig{
		Attachments: allocator,
		Provider: carrierProviderFunc{newCarrier: func() Carrier {
			return &sessionCarrier{run: func(_ context.Context, _ Lease, ready func(Lease) error) error {
				allocator.record("provider")
				return ready(sessionReadyLease(lease))
			}}
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	readyCalls := 0
	if err := carrier.Run(ctx, lease, func(Lease) error {
		allocator.record("lease-ready")
		readyCalls++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if readyCalls != 1 {
		t.Fatalf("lease ready calls = %d, want one", readyCalls)
	}
	want := []string{"allocate", "wait-admission", "provider", "observe-origin", "lease-ready"}
	if got := allocator.events(); !equalStrings(got, want) {
		t.Fatalf("attachment lifecycle = %#v, want %#v", got, want)
	}
}

type attachmentAllocatorFunc func(context.Context, AttachmentRequest) (Attachment, error)

func (f attachmentAllocatorFunc) Allocate(ctx context.Context, request AttachmentRequest) (Attachment, error) {
	return f(ctx, request)
}

func (f attachmentAllocatorFunc) WaitForAdmission(_ context.Context, _ AttachmentRequest, initial Attachment) (Attachment, error) {
	return initial, nil
}

func (f attachmentAllocatorFunc) ObserveOrigin(_ context.Context, _ AttachmentRequest, attachment Attachment, _ bool) (Attachment, error) {
	return attachment, nil
}

type carrierProviderFunc struct {
	newCarrier func() Carrier
}

func (p carrierProviderFunc) CarrierForAttachment(context.Context, Lease, Attachment) (Carrier, error) {
	if p.newCarrier == nil {
		return nil, ErrPreviewCarrierProviderUnavailable
	}
	return p.newCarrier(), nil
}

func (carrierProviderFunc) Close(context.Context) error { return nil }

var _ AttachmentAllocator = attachmentAllocatorFunc(nil)
var _ AttachmentAdmissionWaiter = attachmentAllocatorFunc(nil)
var _ AttachmentReadinessObserver = attachmentAllocatorFunc(nil)
var _ PreviewCarrierProvider = carrierProviderFunc{}

type recordingAttachmentAllocator struct {
	mu       sync.Mutex
	pending  Attachment
	admitted Attachment
	ready    Attachment
	eventsV  []string
}

func (a *recordingAttachmentAllocator) Allocate(context.Context, AttachmentRequest) (Attachment, error) {
	a.record("allocate")
	return a.pending, nil
}

func (a *recordingAttachmentAllocator) WaitForAdmission(context.Context, AttachmentRequest, Attachment) (Attachment, error) {
	a.record("wait-admission")
	return a.admitted, nil
}

func (a *recordingAttachmentAllocator) ObserveOrigin(context.Context, AttachmentRequest, Attachment, bool) (Attachment, error) {
	a.record("observe-origin")
	return a.ready, nil
}

func (a *recordingAttachmentAllocator) record(event string) {
	a.mu.Lock()
	a.eventsV = append(a.eventsV, event)
	a.mu.Unlock()
}

func (a *recordingAttachmentAllocator) events() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.eventsV...)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
