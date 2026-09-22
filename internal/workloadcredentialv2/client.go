package workloadcredentialv2

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"time"
)

type ClientConfig struct {
	SocketPath       string
	ExpectedUID      uint32
	ExpectedGID      uint32
	Policy           Policy
	PrivateKey       ed25519.PrivateKey
	OperationTimeout time.Duration
	Now              func() time.Time
	Random           io.Reader
}

type Client struct{ config ClientConfig }

type Lease struct {
	ID         string
	Revision   int64
	IssuedAt   time.Time
	ExpiresAt  time.Time
	Renewable  bool
	Credential []byte
}

func (l *Lease) Destroy() {
	if l != nil {
		clear(l.Credential)
		l.Credential = nil
	}
}

func NewClient(config ClientConfig) (*Client, error) {
	if validateSocket(config.SocketPath, config.ExpectedUID, config.ExpectedGID) != nil || config.Policy.Validate() != nil ||
		len(config.PrivateKey) != ed25519.PrivateKeySize || !config.PrivateKey.Public().(ed25519.PublicKey).Equal(config.Policy.PublicKey) ||
		config.OperationTimeout < time.Second || config.OperationTimeout > time.Minute || config.Now == nil || config.Now().IsZero() || config.Random == nil {
		return nil, ErrUnavailable
	}
	config.PrivateKey = append(ed25519.PrivateKey(nil), config.PrivateKey...)
	return &Client{config: config}, nil
}

func NewProductionClient(config ClientConfig) (*Client, error) {
	if config.Random != nil {
		return nil, ErrUnavailable
	}
	config.Random = rand.Reader
	return NewClient(config)
}

func (c *Client) Issue(ctx context.Context, ttl time.Duration) (Lease, error) {
	return c.execute(ctx, IssueType, Lease{}, ttl)
}

func (c *Client) Renew(ctx context.Context, lease Lease, ttl time.Duration) (Lease, error) {
	return c.execute(ctx, RenewType, lease, ttl)
}

func (c *Client) Revoke(ctx context.Context, lease Lease) error {
	_, err := c.execute(ctx, RevokeType, lease, 0)
	lease.Destroy()
	return err
}

func (c *Client) Status(ctx context.Context, lease Lease) error {
	_, err := c.execute(ctx, StatusType, lease, 0)
	return err
}

func (c *Client) Close() {
	if c != nil {
		clear(c.config.PrivateKey)
		c.config.PrivateKey = nil
	}
}

func (c *Client) execute(ctx context.Context, operation string, lease Lease, ttl time.Duration) (Lease, error) {
	if c == nil || ctx == nil {
		return Lease{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Lease{}, err
	}
	operationContext, cancel := context.WithTimeout(ctx, c.config.OperationTimeout)
	defer cancel()
	deadline, _ := operationContext.Deadline()
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(c.config.Random, nonce); err != nil {
		clear(nonce)
		return Lease{}, ErrUnavailable
	}
	request, err := NewSignedRequest(c.config.Policy, operation, lease.ID, lease.Revision, ttl, deadline,
		base64.RawURLEncoding.EncodeToString(nonce), c.config.PrivateKey, c.config.Now().UTC())
	clear(nonce)
	if err != nil {
		return Lease{}, err
	}
	document, err := EncodeRequest(request, c.config.Policy, c.config.Now().UTC())
	if err != nil {
		return Lease{}, err
	}
	defer clear(document)
	if validateSocket(c.config.SocketPath, c.config.ExpectedUID, c.config.ExpectedGID) != nil {
		return Lease{}, ErrUnavailable
	}
	connectionValue, err := (&net.Dialer{}).DialContext(operationContext, "unix", c.config.SocketPath)
	if err != nil {
		return Lease{}, clientError(err)
	}
	connection, ok := connectionValue.(*net.UnixConn)
	if !ok {
		_ = connectionValue.Close()
		return Lease{}, ErrUnavailable
	}
	defer connection.Close()
	if connection.SetDeadline(deadline) != nil {
		return Lease{}, ErrUnavailable
	}
	identity, err := socketPeer(connection)
	if err != nil || identity.uid != c.config.ExpectedUID || identity.gid != c.config.ExpectedGID {
		return Lease{}, ErrUnavailable
	}
	if writeFrame(connection, document, MaxRequestBytes) != nil {
		return Lease{}, ErrUnavailable
	}
	responseDocument, err := readFrame(connection, MaxResponseBytes)
	if err != nil {
		return Lease{}, clientError(err)
	}
	defer clear(responseDocument)
	response, err := DecodeResponse(responseDocument, request, c.config.Now().UTC())
	if err != nil {
		return Lease{}, err
	}
	defer clear(response.Credential)
	if response.Status != StatusOK {
		return Lease{}, statusError(response.Status)
	}
	if operation == RevokeType || operation == StatusType {
		return Lease{}, nil
	}
	issuedAt, _ := parseTime(response.IssuedAt)
	expiresAt, _ := parseTime(response.ExpiresAt)
	return Lease{ID: response.LeaseID, Revision: response.Revision, IssuedAt: issuedAt, ExpiresAt: expiresAt,
		Renewable: response.Renewable, Credential: append([]byte(nil), response.Credential...)}, nil
}

func clientError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ErrUnavailable
}
