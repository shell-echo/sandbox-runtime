package workloadtlsagent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"time"
)

// PeerCRLProvider is implemented only by the role-owned agent's explicitly
// configured, profile-bound controller client. Returned slices belong to the
// caller. It must authorize the request's edge/local principal/direction and
// choose a fixed source; the role never supplies a Vault path or issuer ID.
type PeerCRLProvider interface {
	ReadPeerCRL(context.Context, PeerCRLRequest) (sourceID string, issuerDER, crlDER []byte, collectedAt time.Time, err error)
}

type PeerCRLBinding struct {
	ProfileDigest        string
	SourceMappingDigest  string
	EdgeID               string
	LocalPrincipalDigest string
	Direction            string
	PeerAnchorID         string
}

func (s *Server) handlePeerCRL(parent context.Context, connection *net.UnixConn, document []byte, now time.Time) {
	request, err := DecodePeerCRLRequest(document, now)
	if err != nil {
		return
	}
	deadline, _ := parseProtocolTime(request.Deadline)
	if connection.SetDeadline(deadline) != nil || !s.reserve(request.Nonce, deadline, now) {
		return
	}
	operationContext, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	// A one-request connection has no further client payload. Any additional
	// byte or EOF means the caller abandoned the pull; stop upstream work now.
	watchDone := make(chan struct{})
	go func() {
		var extra [1]byte
		_, _ = connection.Read(extra[:])
		cancel()
		close(watchDone)
	}()
	defer func() {
		_ = connection.SetReadDeadline(time.Now())
		<-watchDone
	}()
	sourceID, issuerDER, crlDER, collectedAt, err := s.peerCRLProvider.ReadPeerCRL(operationContext, request)
	defer clear(issuerDER)
	defer clear(crlDER)
	if err != nil || operationContext.Err() != nil {
		s.writePeerCRLError(connection, request)
		return
	}
	response, err := NewPeerCRLResponse(request, sourceID, issuerDER, crlDER, collectedAt, s.now().UTC())
	if err != nil {
		s.writePeerCRLError(connection, request)
		return
	}
	defer clear(response.IssuerDER)
	defer clear(response.CRLDER)
	encoded, err := EncodePeerCRLResponse(response, request, issuerDER, s.now().UTC())
	if err != nil {
		return
	}
	defer clear(encoded)
	_ = writeFrame(connection, encoded, maxPeerCRLFrame)
}

func (s *Server) writePeerCRLError(connection *net.UnixConn, request PeerCRLRequest) {
	response := PeerCRLResponse{Protocol: PeerCRLProtocolID, Type: PeerCRLErrorType,
		RequestID: request.RequestID, RequestDigest: request.RequestDigest, ProfileDigest: request.ProfileDigest,
		SourceMappingDigest: request.SourceMappingDigest,
		EdgeID:              request.EdgeID, Direction: request.Direction, PeerAnchorID: request.PeerAnchorID,
		IssuerDigest: request.IssuerDigest}
	encoded, err := EncodePeerCRLResponse(response, request, nil, s.now().UTC())
	if err == nil {
		defer clear(encoded)
		_ = writeFrame(connection, encoded, maxPeerCRLFrame)
	}
}

func (c *Client) PeerCRL(ctx context.Context, binding PeerCRLBinding, issuerDER []byte) (PeerCRLResponse, error) {
	if c == nil || ctx == nil || len(issuerDER) == 0 || len(issuerDER) > 64<<10 {
		return PeerCRLResponse{}, ErrUnavailable
	}
	issuerHash := sha256.Sum256(issuerDER)
	return c.peerCRL(ctx, binding, "sha256:"+hex.EncodeToString(issuerHash[:]), issuerDER)
}

// BootstrapPeerCRL is used only with an operator-pinned expected issuer
// digest, before a network peer exists. The response carries the complete
// issuer DER; it does not establish a peer identity or add a trust root.
func (c *Client) BootstrapPeerCRL(ctx context.Context, binding PeerCRLBinding, issuerDigest string) (PeerCRLResponse, error) {
	if c == nil || ctx == nil || !peerCRLDigestPattern.MatchString(issuerDigest) {
		return PeerCRLResponse{}, ErrUnavailable
	}
	return c.peerCRL(ctx, binding, issuerDigest, nil)
}

func (c *Client) peerCRL(ctx context.Context, binding PeerCRLBinding, issuerDigest string, issuerDER []byte) (PeerCRLResponse, error) {
	if err := ctx.Err(); err != nil {
		return PeerCRLResponse{}, err
	}
	operationContext, cancel := context.WithTimeout(ctx, c.config.OperationTimeout)
	defer cancel()
	deadline, _ := operationContext.Deadline()
	nonce, requestID := make([]byte, 32), make([]byte, 16)
	if _, err := io.ReadFull(c.config.Random, nonce); err != nil {
		return PeerCRLResponse{}, ErrUnavailable
	}
	defer clear(nonce)
	if _, err := io.ReadFull(c.config.Random, requestID); err != nil {
		return PeerCRLResponse{}, ErrUnavailable
	}
	defer clear(requestID)
	request, err := NewPeerCRLRequest(PeerCRLRequest{RequestID: "crl_" + hex.EncodeToString(requestID),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), Deadline: deadline.UTC().Format(time.RFC3339Nano),
		ProfileDigest: binding.ProfileDigest, SourceMappingDigest: binding.SourceMappingDigest, EdgeID: binding.EdgeID,
		LocalPrincipalDigest: binding.LocalPrincipalDigest, Direction: binding.Direction,
		PeerAnchorID: binding.PeerAnchorID, IssuerDigest: issuerDigest}, c.config.Now().UTC())
	if err != nil {
		return PeerCRLResponse{}, err
	}
	return c.executePeerCRL(operationContext, request, issuerDER)
}

func (c *Client) executePeerCRL(ctx context.Context, request PeerCRLRequest, issuerDER []byte) (PeerCRLResponse, error) {
	deadline, err := parseProtocolTime(request.Deadline)
	if err != nil {
		return PeerCRLResponse{}, ErrUnavailable
	}
	encoded, err := EncodePeerCRLRequest(request, c.config.Now().UTC())
	if err != nil {
		return PeerCRLResponse{}, err
	}
	defer clear(encoded)
	if validateSocket(c.config.SocketPath, c.config.ExpectedUID, c.config.RoleGID) != nil {
		return PeerCRLResponse{}, ErrUnavailable
	}
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
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-watchDone:
		}
	}()
	defer close(watchDone)
	if connection.SetDeadline(deadline) != nil {
		return PeerCRLResponse{}, ErrUnavailable
	}
	identity, err := socketPeer(connection)
	if err != nil || identity.uid != c.config.ExpectedUID || identity.gid != c.config.ExpectedGID {
		return PeerCRLResponse{}, ErrUnavailable
	}
	if writeFrame(connection, encoded, maxRequestBytes) != nil {
		return PeerCRLResponse{}, ErrUnavailable
	}
	responseDocument, err := readFrame(connection, maxPeerCRLFrame)
	if err != nil {
		if ctx.Err() != nil {
			return PeerCRLResponse{}, ctx.Err()
		}
		return PeerCRLResponse{}, clientError(err)
	}
	defer clear(responseDocument)
	return DecodePeerCRLResponse(responseDocument, request, issuerDER, c.config.Now().UTC())
}
