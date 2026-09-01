//go:build darwin || linux

package hostdproto

import (
	"context"
	"sync"
)

// Candidate is the small lifecycle half run inside a replaceable runtime
// worker. It has no hostd workload API: before Activate, it can only negotiate
// and report readiness; after activation it can only heartbeat on its own
// fenced lease.
type Candidate struct {
	mu     sync.Mutex
	client *Client
	hello  Hello
	lease  Welcome
}

func NewCandidate(client *Client, workerID, version string, apiMin, apiMax uint16) (*Candidate, error) {
	hello := Hello{WorkerID: workerID, Version: version, APIMin: apiMin, APIMax: apiMax}
	if client == nil || hello.validate() != nil {
		return nil, ErrInvalidConfig
	}
	return &Candidate{client: client, hello: hello}, nil
}

func (c *Candidate) Ready(ctx context.Context) (Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lease.Epoch == 0 {
		response, err := c.client.Request(ctx, c.hello)
		if err != nil {
			return Status{}, err
		}
		lease, ok := response.(*Welcome)
		if !ok || lease.validate() != nil || lease.WorkerID != c.hello.WorkerID {
			return Status{}, ErrInvalidFrame
		}
		c.lease = *lease
	}
	response, err := c.client.Request(ctx, readyForCandidate(c.lease))
	if err != nil {
		return Status{}, err
	}
	return candidateStatus(response, StateCandidate, c.lease)
}

func (c *Candidate) Activate(ctx context.Context) (Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lease.Epoch == 0 {
		return Status{}, ErrNotReady
	}
	response, err := c.client.Request(ctx, activateForCandidate(c.lease))
	if err != nil {
		return Status{}, err
	}
	if _, err := candidateStatus(response, StateActive, c.lease); err != nil {
		return Status{}, err
	}
	response, err = c.client.Request(ctx, heartbeatForCandidate(c.lease))
	if err != nil {
		return Status{}, err
	}
	return candidateStatus(response, StateActive, c.lease)
}

func (c *Candidate) Heartbeat(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lease.Epoch == 0 {
		return ErrNotReady
	}
	response, err := c.client.Request(ctx, heartbeatForCandidate(c.lease))
	if err != nil {
		return err
	}
	_, err = candidateStatus(response, StateActive, c.lease)
	return err
}

func readyForCandidate(value Welcome) Ready {
	return Ready(value)
}
func activateForCandidate(value Welcome) Activate {
	return Activate(value)
}
func heartbeatForCandidate(value Welcome) Heartbeat {
	return Heartbeat(value)
}
func candidateStatus(response Message, state State, lease Welcome) (Status, error) {
	status, ok := response.(*Status)
	if !ok || status.State != state || status.WorkerID != lease.WorkerID || status.APIVersion != lease.APIVersion || status.Epoch != lease.Epoch {
		return Status{}, ErrInvalidFrame
	}
	return *status, nil
}
