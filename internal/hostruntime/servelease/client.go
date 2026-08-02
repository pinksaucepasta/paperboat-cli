package servelease

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	endpoint string
	token    string
	client   *http.Client
}

func NewClient(endpoint, token string, client *http.Client) (*Client, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.Path != "/v1/serve-leases" || token == "" {
		return nil, ErrInvalid
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Client{endpoint: parsed.String(), token: token, client: client}, nil
}

func (c *Client) Acquire(ctx context.Context, name string) (Lease, error) {
	return c.call(ctx, request{Schema: ProtocolVersion, Action: "acquire", Name: name})
}

func (c *Client) Renew(ctx context.Context, lease Lease) (Lease, error) {
	return c.call(ctx, request{Schema: ProtocolVersion, Action: "renew", LeaseID: lease.ID, Name: lease.Name})
}

func (c *Client) Release(ctx context.Context, lease Lease) error {
	_, err := c.call(ctx, request{Schema: ProtocolVersion, Action: "release", LeaseID: lease.ID, Name: lease.Name})
	return err
}

func (c *Client) call(ctx context.Context, input request) (Lease, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return Lease{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return Lease{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(req)
	if err != nil {
		return Lease{}, err
	}
	defer response.Body.Close()
	var envelope struct {
		Schema string `json:"schema_version"`
		Lease  Lease  `json:"lease"`
		Error  struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16<<10))
	if decoder.Decode(&envelope) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Lease{}, ErrInvalid
	}
	if response.StatusCode != http.StatusOK {
		switch envelope.Error.Code {
		case "serve_lease_conflict":
			return Lease{}, ErrConflict
		case "serve_lease_lost":
			return Lease{}, ErrLeaseLost
		default:
			return Lease{}, ErrInvalid
		}
	}
	if envelope.Schema != ProtocolVersion || input.Action != "release" && (envelope.Lease.ID == "" || envelope.Lease.Name != input.Name) {
		return Lease{}, ErrInvalid
	}
	return envelope.Lease, nil
}

type Keeper struct {
	Client   *Client
	Lease    Lease
	Interval time.Duration
}

func (k *Keeper) Run(ctx context.Context) error {
	if k.Client == nil || k.Lease.ID == "" || k.Interval <= 0 {
		return ErrInvalid
	}
	ticker := time.NewTicker(k.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			renewCtx, cancel := context.WithTimeout(ctx, k.Interval)
			lease, err := k.Client.Renew(renewCtx, k.Lease)
			cancel()
			if err != nil {
				return errors.Join(ErrLeaseLost, err)
			}
			k.Lease = lease
		}
	}
}

func (k *Keeper) Release(ctx context.Context) error {
	if k.Client == nil || k.Lease.ID == "" {
		return ErrInvalid
	}
	return k.Client.Release(ctx, k.Lease)
}
