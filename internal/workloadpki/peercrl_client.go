package workloadpki

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
)

type PeerCRLBinding struct {
	ProfileDigest        string
	EdgeID               string
	LocalPrincipalDigest string
	Direction            string
	PeerAnchorID         string
	IssuerDigest         string
	SourceID             string
}

// PeerRevocations uses the same restricted, authenticated controller socket
// but a distinct signed v2 document. SourceID must first be resolved from
// the agent's fixed operator mapping, never from a role-supplied path.
func (c *Client) PeerRevocations(ctx context.Context, binding PeerCRLBinding) (PeerCRLResponse, error) {
	if c == nil || ctx == nil {
		return PeerCRLResponse{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return PeerCRLResponse{}, err
	}
	operationContext, cancel := context.WithTimeout(ctx, c.config.OperationTimeout)
	defer cancel()
	deadline, _ := operationContext.Deadline()
	nonce := make([]byte, 32)
	requestID := make([]byte, 16)
	if _, err := io.ReadFull(c.config.Random, nonce); err != nil {
		clear(nonce)
		return PeerCRLResponse{}, ErrUnavailable
	}
	if _, err := io.ReadFull(c.config.Random, requestID); err != nil {
		clear(nonce)
		clear(requestID)
		return PeerCRLResponse{}, ErrUnavailable
	}
	request, err := NewPeerCRLRequest(c.config.Policy, "peer-crl-"+hex.EncodeToString(requestID),
		base64.RawURLEncoding.EncodeToString(nonce), deadline, binding.ProfileDigest, binding.EdgeID,
		binding.LocalPrincipalDigest, binding.Direction, binding.PeerAnchorID, binding.IssuerDigest,
		binding.SourceID, c.config.AgentPrivateKey, c.config.Now().UTC())
	clear(nonce)
	clear(requestID)
	if err != nil {
		return PeerCRLResponse{}, err
	}
	return c.executePeerCRL(operationContext, request)
}

func (c *Client) executePeerCRL(ctx context.Context, request PeerCRLRequest) (PeerCRLResponse, error) {
	document, err := EncodePeerCRLRequest(request, c.config.Policy, c.config.Now().UTC())
	if err != nil || !validClientSocket(c.config) {
		return PeerCRLResponse{}, ErrUnavailable
	}
	defer clear(document)
	connectionValue, err := (&net.Dialer{}).DialContext(ctx, "unix", c.config.SocketPath)
	if err != nil {
		return PeerCRLResponse{}, clientError(err)
	}
	connection, ok := connectionValue.(*net.UnixConn)
	if !ok {
		_ = connectionValue.Close()
		return PeerCRLResponse{}, ErrUnavailable
	}
	defer connection.Close()
	stopWatcher := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-stopWatcher:
		}
	}()
	defer func() { close(stopWatcher); <-watcherDone }()
	deadline, _ := ctx.Deadline()
	if connection.SetDeadline(deadline) != nil {
		return PeerCRLResponse{}, ErrUnavailable
	}
	identity, err := socketPeer(connection)
	if err != nil || identity.uid != c.config.ExpectedUID || identity.gid != c.config.ExpectedGID {
		return PeerCRLResponse{}, ErrUnavailable
	}
	if writeFrame(connection, document, maxRequestBytes) != nil {
		return PeerCRLResponse{}, clientError(ctx.Err())
	}
	responseDocument, err := readFrame(connection, maxResponseBytes)
	if err != nil {
		if ctx.Err() != nil {
			return PeerCRLResponse{}, ctx.Err()
		}
		return PeerCRLResponse{}, clientError(err)
	}
	defer clear(responseDocument)
	return DecodePeerCRLResponse(responseDocument, request, c.config.Policy,
		c.config.ControllerKeyID, c.config.ControllerPublic, c.config.Now().UTC())
}
