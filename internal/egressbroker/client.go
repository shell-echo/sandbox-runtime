package egressbroker

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"time"
)

type ClientConfig struct {
	Address          string
	TLSConfig        *tls.Config
	Policy           Policy
	BrokerURI        string
	BrokerDNSNames   []string
	BrokerUsages     []string
	OperationTimeout time.Duration
	Now              func() time.Time
	Random           io.Reader
}

type Client struct{ config ClientConfig }

func NewClient(config ClientConfig) (*Client, error) {
	if config.Address == "" || config.TLSConfig == nil || config.Policy.Validate() != nil || config.BrokerURI == "" ||
		config.OperationTimeout < time.Second || config.OperationTimeout > time.Minute || config.Now == nil || config.Now().IsZero() ||
		config.Random == nil || validateClientTLS(config.TLSConfig) != nil {
		return nil, ErrInvalid
	}
	config.TLSConfig = config.TLSConfig.Clone()
	config.BrokerDNSNames = append([]string(nil), config.BrokerDNSNames...)
	config.BrokerUsages = append([]string(nil), config.BrokerUsages...)
	parsedUsages, err := parseUsages(config.BrokerUsages)
	if err != nil || !slices.Contains(parsedUsages, x509.ExtKeyUsageServerAuth) {
		return nil, ErrInvalid
	}
	return &Client{config: config}, nil
}

func NewProductionClient(config ClientConfig) (*Client, error) {
	if config.Random != nil {
		return nil, ErrInvalid
	}
	config.Random = rand.Reader
	return NewClient(config)
}

func (c *Client) Dial(ctx context.Context, alias string, lease time.Duration) (net.Conn, error) {
	request, err := c.newOpen(ctx, alias, lease)
	if err != nil {
		return nil, err
	}
	return c.execute(ctx, request)
}

func (c *Client) newOpen(ctx context.Context, alias string, lease time.Duration) (Open, error) {
	if c == nil || ctx == nil {
		return Open{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Open{}, err
	}
	operationContext, cancel := context.WithTimeout(ctx, c.config.OperationTimeout)
	defer cancel()
	deadline, _ := operationContext.Deadline()
	nonce := make([]byte, 32)
	requestID := make([]byte, 16)
	if _, err := io.ReadFull(c.config.Random, nonce); err != nil {
		return Open{}, ErrUnavailable
	}
	defer clear(nonce)
	if _, err := io.ReadFull(c.config.Random, requestID); err != nil {
		return Open{}, ErrUnavailable
	}
	defer clear(requestID)
	request := newOpen(c.config.Policy, "egress_"+hex.EncodeToString(requestID), base64.RawURLEncoding.EncodeToString(nonce), alias, deadline, lease)
	if request.Validate(c.config.Policy, c.config.Now().UTC()) != nil {
		return Open{}, ErrDenied
	}
	return request, nil
}

func (c *Client) execute(ctx context.Context, request Open) (net.Conn, error) {
	deadline, err := parseTime(request.Deadline)
	if err != nil {
		return nil, ErrDenied
	}
	operationContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	dialer := &tls.Dialer{Config: c.config.TLSConfig}
	connectionValue, err := dialer.DialContext(operationContext, "tcp", c.config.Address)
	if err != nil {
		return nil, clientError(err)
	}
	connection, ok := connectionValue.(*tls.Conn)
	if !ok {
		_ = connectionValue.Close()
		return nil, ErrUnavailable
	}
	brokerUsages, _ := parseUsages(c.config.BrokerUsages)
	if validatePeerIdentity(connection.ConnectionState(), c.config.BrokerURI, c.config.BrokerDNSNames, brokerUsages) != nil {
		_ = connection.Close()
		return nil, ErrDenied
	}
	if connection.SetDeadline(deadline) != nil {
		_ = connection.Close()
		return nil, ErrUnavailable
	}
	document, err := encodeOpen(request, c.config.Policy, c.config.Now().UTC())
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	if writeFrame(connection, document, maxRequestBytes) != nil {
		clear(document)
		_ = connection.Close()
		return nil, ErrUnavailable
	}
	clear(document)
	responseDocument, err := readFrame(connection, maxResponseBytes)
	if err != nil {
		_ = connection.Close()
		return nil, clientError(err)
	}
	response, err := decodeAccepted(responseDocument, request, c.config.Policy, c.config.Now().UTC())
	clear(responseDocument)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	expiresAt, _ := parseTime(response.LeaseExpiresAt)
	if connection.SetDeadline(expiresAt) != nil {
		_ = connection.Close()
		return nil, ErrUnavailable
	}
	return connection, nil
}

func validateClientTLS(config *tls.Config) error {
	if config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 || config.RootCAs == nil ||
		config.InsecureSkipVerify || config.ServerName == "" || (len(config.Certificates) == 0 && config.GetClientCertificate == nil) ||
		!slices.Equal(config.NextProtos, []string{ProtocolID}) {
		return ErrInvalid
	}
	return nil
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
