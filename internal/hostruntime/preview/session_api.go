package preview

import (
	"context"
	"fmt"

	"github.com/pinksaucepasta/paperboat/internal/api"
)

// APILeaseClient adapts the authenticated Paperboat client to the foreground
// session lifecycle. Carrier credentials remain inside the host connector and
// are never copied into the preview lease model.
type APILeaseClient struct {
	client *api.Client
}

func NewAPILeaseClient(client *api.Client) (*APILeaseClient, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: API client is required", ErrSessionInvalid)
	}
	return &APILeaseClient{client: client}, nil
}

func (c *APILeaseClient) Create(ctx context.Context, request LeaseRequest) (Lease, error) {
	if c == nil || c.client == nil {
		return Lease{}, fmt.Errorf("%w: API client is required", ErrSessionInvalid)
	}
	lease, err := c.client.CreatePreviewLease(ctx, api.PreviewLeaseCreateRequest{
		OwnerDeviceID:  request.OwnerDeviceID,
		OwnerSessionID: request.OwnerSessionID,
		Target: api.PreviewLeaseTarget{
			Scheme: request.Target.Scheme, Address: request.Target.Address,
		},
		AccessMode: request.AccessMode,
		ExpiresAt:  request.UserDeadline,
	}, request.IdempotencyKey)
	if err != nil {
		return Lease{}, err
	}
	return leaseFromAPI(lease), nil
}

func (c *APILeaseClient) Renew(ctx context.Context, lease Lease, idempotencyKey string) (Lease, error) {
	if c == nil || c.client == nil {
		return Lease{}, fmt.Errorf("%w: API client is required", ErrSessionInvalid)
	}
	renewed, err := c.client.RenewPreviewLease(ctx, leaseToAPI(lease), lease.OwnerSessionID, idempotencyKey)
	if err != nil {
		return Lease{}, err
	}
	result := leaseFromAPI(renewed)
	// Renew responses are resource projections and therefore do not repeat
	// the immutable create operation. Preserve it across the in-memory lease
	// update so a later carrier attachment remains bound to that operation.
	result.CreateOperationID = lease.CreateOperationID
	return result, nil
}

func (c *APILeaseClient) Stop(ctx context.Context, lease Lease, idempotencyKey string) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("%w: API client is required", ErrSessionInvalid)
	}
	_, err := c.client.StopPreviewLease(ctx, leaseToAPI(lease), idempotencyKey)
	return err
}

// Get reads the current server-owned lease projection. It is intentionally a
// separate read surface from LeaseClient: foreground CLI observers may use a
// client-session bearer for reads while LeaseClient mutations continue to use
// the renewable machine proof.
func (c *APILeaseClient) Get(ctx context.Context, previewID string) (Lease, error) {
	if c == nil || c.client == nil {
		return Lease{}, fmt.Errorf("%w: API client is required", ErrSessionInvalid)
	}
	lease, err := c.client.GetPreviewLease(ctx, previewID)
	if err != nil {
		return Lease{}, err
	}
	return leaseFromAPI(lease), nil
}

func leaseFromAPI(value api.PreviewLease) Lease {
	lease := Lease{
		Schema: value.Schema, Kind: value.Kind, ID: value.ID, AccountID: value.AccountID, ActorID: value.ActorID,
		OwnerDeviceID: value.OwnerDeviceID, OwnerSessionID: value.OwnerSessionID,
		Target: LeaseTarget{Scheme: value.Target.Scheme, Address: value.Target.Address}, AccessMode: value.AccessMode,
		Persistent: value.Persistent, Endpoint: value.Endpoint, LeaseDeadline: value.LeaseDeadline,
		UserDeadline: value.UserDeadline, State: value.State, AllocationState: value.AllocationState,
		EdgeState: value.EdgeState, OriginState: value.OriginState, CreatedAt: value.CreatedAt,
		LastRenewedAt: value.LastRenewedAt, CreateOperationID: value.CreateOperationID, ETag: value.ETag,
	}
	lease.Generation = leaseGenerationForID(lease.ID, lease.ETag)
	return lease
}

func leaseToAPI(value Lease) api.PreviewLease {
	return api.PreviewLease{
		Schema: value.Schema, Kind: value.Kind, ID: value.ID, AccountID: value.AccountID, ActorID: value.ActorID,
		OwnerDeviceID: value.OwnerDeviceID, OwnerSessionID: value.OwnerSessionID,
		Target: api.PreviewLeaseTarget{Scheme: value.Target.Scheme, Address: value.Target.Address}, AccessMode: value.AccessMode,
		Persistent: value.Persistent, Endpoint: value.Endpoint, LeaseDeadline: value.LeaseDeadline,
		UserDeadline: value.UserDeadline, State: value.State, AllocationState: value.AllocationState,
		EdgeState: value.EdgeState, OriginState: value.OriginState, CreatedAt: value.CreatedAt,
		LastRenewedAt: value.LastRenewedAt, CreateOperationID: value.CreateOperationID, ETag: value.ETag,
	}
}

var _ LeaseClient = (*APILeaseClient)(nil)
var _ LeaseReader = (*APILeaseClient)(nil)
