package workloadpki

import (
	"context"
	"net"
	"time"
)

func (s *Server) handlePeerCRL(parent context.Context, connection *net.UnixConn, document []byte,
	policyID string, peerUID, peerGID uint32) {
	if s.controller.peerCRLProfile == nil {
		return
	}
	policy, known := s.controller.policies[policyID]
	if !known {
		return
	}
	request, err := DecodePeerCRLRequest(document, policy, s.controller.now().UTC())
	if err != nil {
		return
	}
	deadline, err := parseTime(request.Deadline)
	if err != nil || connection.SetDeadline(deadline) != nil {
		return
	}
	operationContext, cancel := context.WithDeadline(parent, deadline)
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		var extra [1]byte
		// Any extra input violates the one-request-per-connection protocol.
		// EOF also means the caller abandoned the operation.
		_, _ = connection.Read(extra[:])
		cancel()
	}()
	defer func() {
		cancel()
		_ = connection.SetReadDeadline(time.Now())
		<-watcherDone
	}()
	response, handleErr := s.controller.HandlePeerCRL(operationContext, request, peerUID, peerGID)
	if handleErr != nil && response.Status == "" {
		return
	}
	defer clear(response.IssuerDER)
	defer clear(response.CRLDER)
	encoded, err := EncodePeerCRLResponse(response, request, s.controller.now().UTC())
	if err != nil {
		return
	}
	defer clear(encoded)
	_ = writeFrame(connection, encoded, maxResponseBytes)
}
