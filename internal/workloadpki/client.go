package workloadpki

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
)

type ClientConfig struct {
	SocketPath       string
	ExpectedUID      uint32
	ExpectedGID      uint32
	DirectoryGID     uint32
	InternalSelf     bool
	Policy           Policy
	AgentPrivateKey  ed25519.PrivateKey
	ControllerKeyID  string
	ControllerPublic ed25519.PublicKey
	OperationTimeout time.Duration
	Now              func() time.Time
	Random           io.Reader
}

type Client struct {
	config ClientConfig
}

func NewClient(config ClientConfig) (*Client, error) {
	if !validClientSocket(config) || config.Policy.Validate() != nil ||
		len(config.AgentPrivateKey) != ed25519.PrivateKeySize || !config.AgentPrivateKey.Public().(ed25519.PublicKey).Equal(config.Policy.PublicKey) ||
		!namePattern.MatchString(config.ControllerKeyID) || len(config.ControllerPublic) != ed25519.PublicKeySize ||
		config.OperationTimeout < time.Second || config.OperationTimeout > time.Minute || config.Now == nil || config.Now().IsZero() || config.Random == nil {
		return nil, ErrUnavailable
	}
	config.AgentPrivateKey = append(ed25519.PrivateKey(nil), config.AgentPrivateKey...)
	config.ControllerPublic = append(ed25519.PublicKey(nil), config.ControllerPublic...)
	config.Policy.PublicKey = append(ed25519.PublicKey(nil), config.Policy.PublicKey...)
	config.Policy.DNSNames = append([]string(nil), config.Policy.DNSNames...)
	config.Policy.Usages = append([]string(nil), config.Policy.Usages...)
	return &Client{config: config}, nil
}

func validClientSocket(config ClientConfig) bool {
	if config.DirectoryGID != uint32(os.Getgid()) {
		return false
	}
	if config.InternalSelf {
		if config.ExpectedUID != uint32(os.Getuid()) || config.ExpectedGID != config.DirectoryGID {
			return false
		}
	} else if config.ExpectedUID == uint32(os.Getuid()) || config.ExpectedGID == config.DirectoryGID {
		return false
	}
	layout := restrictedunix.Layout{DirectoryMode: 0o710, SocketMode: 0o666,
		OwnerUID: config.ExpectedUID, DirectoryGID: config.DirectoryGID}
	if config.InternalSelf {
		layout.DirectoryMode, layout.SocketMode = 0o700, 0o600
	}
	return restrictedunix.ValidateSocket(config.SocketPath, layout)
}

func NewProductionClient(config ClientConfig) (*Client, error) {
	if config.Random != nil {
		return nil, ErrUnavailable
	}
	config.Random = rand.Reader
	return NewClient(config)
}

func (c *Client) Issue(ctx context.Context, csrPEM []byte, ttl time.Duration) (IssuedCertificate, error) {
	request, err := c.newRequest(ctx, IssueType, csrPEM, ttl, "")
	if err != nil {
		return IssuedCertificate{}, err
	}
	response, err := c.execute(ctx, request)
	if err != nil {
		return IssuedCertificate{}, err
	}
	defer response.Destroy()
	return IssuedCertificate{IssuerRevision: response.IssuerRevision, CertificatePEM: append([]byte(nil), response.CertificatePEM...),
		IssuingCAPEM: append([]byte(nil), response.IssuingCAPEM...), CAChainPEM: append([]byte(nil), response.CAChainPEM...),
		Serial: response.Serial, NotBefore: mustParseTime(response.NotBefore), NotAfter: mustParseTime(response.NotAfter)}, nil
}

func (c *Client) Revocations(ctx context.Context) (RevocationSnapshot, error) {
	request, err := c.newRequest(ctx, RevocationsType, nil, 0, "")
	if err != nil {
		return RevocationSnapshot{}, err
	}
	response, err := c.execute(ctx, request)
	if err != nil {
		return RevocationSnapshot{}, err
	}
	defer response.Destroy()
	return RevocationSnapshot{IssuerRevision: response.IssuerRevision, DER: append([]byte(nil), response.CRLDER...),
		ThisUpdate: mustParseTime(response.CRLThisUpdate), NextUpdate: mustParseTime(response.CRLNextUpdate)}, nil
}

func (c *Client) Revoke(ctx context.Context, serial string) error {
	request, err := c.newRequest(ctx, RevokeType, nil, 0, serial)
	if err != nil {
		return err
	}
	response, err := c.execute(ctx, request)
	response.Destroy()
	return err
}

func (c *Client) Close() {
	if c == nil {
		return
	}
	clear(c.config.AgentPrivateKey)
	clear(c.config.ControllerPublic)
	clear(c.config.Policy.PublicKey)
	c.config.AgentPrivateKey, c.config.ControllerPublic, c.config.Policy.PublicKey = nil, nil, nil
}

func (c *Client) newRequest(ctx context.Context, kind string, csrPEM []byte, ttl time.Duration, serial string) (Request, error) {
	if c == nil || ctx == nil {
		return Request{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Request{}, err
	}
	operationContext, cancel := context.WithTimeout(ctx, c.config.OperationTimeout)
	defer cancel()
	deadline, _ := operationContext.Deadline()
	nonce := make([]byte, 32)
	requestID := make([]byte, 16)
	if _, err := io.ReadFull(c.config.Random, nonce); err != nil {
		clear(nonce)
		clear(requestID)
		return Request{}, ErrUnavailable
	}
	if _, err := io.ReadFull(c.config.Random, requestID); err != nil {
		clear(nonce)
		clear(requestID)
		return Request{}, ErrUnavailable
	}
	request := newRequest(c.config.Policy, kind, "certificate-"+hex.EncodeToString(requestID), base64.RawURLEncoding.EncodeToString(nonce), deadline)
	clear(nonce)
	clear(requestID)
	request.CSRPEM = append([]byte(nil), csrPEM...)
	request.RequestedTTLSeconds = int64(ttl / time.Second)
	request.Serial = serial
	return sealRequest(request, c.config.Policy, c.config.AgentPrivateKey, c.config.Now().UTC())
}

func (c *Client) execute(ctx context.Context, request Request) (Response, error) {
	operationContext, cancel := context.WithDeadline(ctx, mustParseTime(request.Deadline))
	defer cancel()
	document, err := EncodeRequest(request, c.config.Policy, c.config.Now().UTC())
	if err != nil {
		return Response{}, err
	}
	defer clear(document)
	if !validClientSocket(c.config) {
		return Response{}, ErrUnavailable
	}
	connectionValue, err := (&net.Dialer{}).DialContext(operationContext, "unix", c.config.SocketPath)
	if err != nil {
		return Response{}, clientError(err)
	}
	connection, ok := connectionValue.(*net.UnixConn)
	if !ok {
		_ = connectionValue.Close()
		return Response{}, ErrUnavailable
	}
	defer connection.Close()
	deadline, _ := operationContext.Deadline()
	if connection.SetDeadline(deadline) != nil {
		return Response{}, ErrUnavailable
	}
	identity, err := socketPeer(connection)
	if err != nil || identity.uid != c.config.ExpectedUID || identity.gid != c.config.ExpectedGID {
		return Response{}, ErrUnavailable
	}
	if writeFrame(connection, document, maxRequestBytes) != nil {
		return Response{}, ErrUnavailable
	}
	responseDocument, err := readFrame(connection, maxResponseBytes)
	if err != nil {
		return Response{}, clientError(err)
	}
	defer clear(responseDocument)
	response, err := DecodeResponse(responseDocument, request, c.config.Policy, c.config.ControllerKeyID, c.config.ControllerPublic, c.config.Now().UTC())
	if err != nil {
		return Response{}, err
	}
	return response, nil
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

func mustParseTime(value string) time.Time {
	parsed, _ := parseTime(value)
	return parsed
}
