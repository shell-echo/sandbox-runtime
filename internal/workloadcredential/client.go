package workloadcredential

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

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

type ClientConfig struct {
	SocketPath       string
	ExpectedUID      uint32
	ExpectedGID      uint32
	AgentID          string
	Role             secretref.Role
	Purpose          secretref.Purpose
	PolicyID         string
	BindingDigest    string
	BackendID        string
	PrivateKey       ed25519.PrivateKey
	OperationTimeout time.Duration
	Now              func() time.Time
	Random           io.Reader
}

type Client struct {
	config ClientConfig
}

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
	}
}

func NewClient(config ClientConfig) (*Client, error) {
	if validateSocket(config.SocketPath, config.ExpectedUID, config.ExpectedGID) != nil || !identifierPattern.MatchString(config.AgentID) ||
		!validRole(config.Role) || !validPurpose(config.Purpose) || !identifierPattern.MatchString(config.PolicyID) ||
		!validDigest(config.BindingDigest) || !identifierPattern.MatchString(config.BackendID) || len(config.PrivateKey) != ed25519.PrivateKeySize ||
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
	request := Request{Type: operation, AgentID: c.config.AgentID, Role: c.config.Role, Purpose: c.config.Purpose, PolicyID: c.config.PolicyID,
		BindingDigest: c.config.BindingDigest, BackendID: c.config.BackendID, LeaseID: lease.ID, Revision: lease.Revision,
		RequestedTTL: int64(ttl / time.Second), Deadline: deadline.UTC().Format(time.RFC3339Nano), JTI: base64.RawURLEncoding.EncodeToString(nonce)}
	clear(nonce)
	request, err := NewSignedRequest(request, c.config.PrivateKey, c.config.Now().UTC())
	if err != nil {
		return Lease{}, err
	}
	document, err := EncodeSignedRequest(request)
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
