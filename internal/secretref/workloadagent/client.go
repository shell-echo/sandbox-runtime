package workloadagent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

type Config struct {
	SocketPath       string
	ExpectedUID      uint32
	ExpectedGID      uint32
	Role             secretref.Role
	OperationTimeout time.Duration
	Now              func() time.Time
	Random           io.Reader
}

type Client struct {
	socketPath       string
	expectedUID      uint32
	expectedGID      uint32
	role             secretref.Role
	operationTimeout time.Duration
	now              func() time.Time
	random           io.Reader
}

func New(config Config) (*Client, error) {
	if !filepath.IsAbs(config.SocketPath) || filepath.Clean(config.SocketPath) != config.SocketPath || len(config.SocketPath) > 100 ||
		config.OperationTimeout < time.Second || config.OperationTimeout > time.Minute || config.Now == nil || config.Now().IsZero() ||
		config.Random == nil || !validRole(config.Role) {
		return nil, secretref.ErrUnavailable
	}
	if err := validateSocket(config.SocketPath, config.ExpectedUID, config.ExpectedGID); err != nil {
		return nil, secretref.ErrUnavailable
	}
	return &Client{
		socketPath: config.SocketPath, expectedUID: config.ExpectedUID, expectedGID: config.ExpectedGID,
		role: config.Role, operationTimeout: config.OperationTimeout, now: config.Now, random: config.Random,
	}, nil
}

func NewProduction(config Config) (*Client, error) {
	if config.Random != nil {
		return nil, secretref.ErrUnavailable
	}
	config.Random = rand.Reader
	return New(config)
}

func (c *Client) ResolveSecret(ctx context.Context, binding secretref.Binding) (secretref.SecretMaterial, error) {
	if c == nil || ctx == nil || binding.Validate() != nil || binding.Kind != secretref.KindSecret || binding.Role != c.role {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return secretref.SecretMaterial{}, err
	}
	operationContext, cancel := context.WithTimeout(ctx, c.operationTimeout)
	defer cancel()
	nonceValue := make([]byte, nonceSize)
	if _, err := io.ReadFull(c.random, nonceValue); err != nil {
		clear(nonceValue)
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceValue)
	clear(nonceValue)
	deadline, ok := operationContext.Deadline()
	if !ok {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	request, err := NewRequest(binding, nonce, deadline)
	if err != nil {
		return secretref.SecretMaterial{}, err
	}
	requestDocument, err := EncodeRequest(request, c.now())
	if err != nil {
		return secretref.SecretMaterial{}, err
	}
	defer clear(requestDocument)
	if err := validateSocket(c.socketPath, c.expectedUID, c.expectedGID); err != nil {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	connection, err := (&net.Dialer{}).DialContext(operationContext, "unix", c.socketPath)
	if err != nil {
		return secretref.SecretMaterial{}, providerError(err)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	defer unixConnection.Close()
	if err := unixConnection.SetDeadline(deadline); err != nil {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	if err := validateSocket(c.socketPath, c.expectedUID, c.expectedGID); err != nil {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	credentials, err := peerCredentials(unixConnection)
	if err != nil || credentials.UID != c.expectedUID || credentials.GID != c.expectedGID {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	if err := WriteFrame(unixConnection, requestDocument, maxRequestBytes); err != nil {
		return secretref.SecretMaterial{}, providerError(err)
	}
	if err := unixConnection.CloseWrite(); err != nil {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	responseDocument, err := ReadFrame(unixConnection, maxResponseBytes)
	if err != nil {
		return secretref.SecretMaterial{}, providerError(err)
	}
	defer clear(responseDocument)
	response, err := DecodeResponse(responseDocument, request, c.now())
	if err != nil {
		return secretref.SecretMaterial{}, err
	}
	defer clear(response.Material)
	trailing := make([]byte, 1)
	if count, readErr := unixConnection.Read(trailing); count != 0 || !errors.Is(readErr, io.EOF) {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	switch response.Status {
	case StatusOK:
		material, err := response.MaterialFor(binding)
		if err != nil || material.Validate(c.now()) != nil {
			material.Destroy()
			return secretref.SecretMaterial{}, secretref.ErrUnavailable
		}
		return material, nil
	case StatusRevoked:
		return secretref.SecretMaterial{}, secretref.ErrRevoked
	case StatusExpired:
		return secretref.SecretMaterial{}, secretref.ErrExpired
	default:
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
}

type peerIdentity struct {
	UID uint32
	GID uint32
}

func validateSocket(path string, expectedUID, expectedGID uint32) error {
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm() != 0o700 || !ownedBy(parentInfo, expectedUID, expectedGID) {
		return secretref.ErrUnavailable
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || !ownedBy(info, expectedUID, expectedGID) {
		return secretref.ErrUnavailable
	}
	return nil
}

func ownedBy(info os.FileInfo, uid, gid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Gid == gid
}

func validRole(role secretref.Role) bool {
	switch role {
	case secretref.RoleProduct, secretref.RoleProvider, secretref.RoleGateway, secretref.RoleGuest, secretref.RoleBrowser, secretref.RoleDesktop:
		return true
	default:
		return false
	}
}

func providerError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return secretref.ErrUnavailable
}

var _ secretref.SecretProvider = (*Client)(nil)
