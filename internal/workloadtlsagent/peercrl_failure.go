package workloadtlsagent

import (
	"context"
	"errors"
)

// PeerCRLClientFailure is a local-only, closed diagnostic. It is never placed
// in the agent protocol and never contains a socket path or raw OS error.
type PeerCRLClientFailure string

const (
	PeerCRLRequestBuildFailure PeerCRLClientFailure = "agent-request-build"
	PeerCRLSocketPeerFailure   PeerCRLClientFailure = "agent-socket-peer"
	PeerCRLTransportFailure    PeerCRLClientFailure = "agent-transport"
	PeerCRLResponseFailure     PeerCRLClientFailure = "agent-response"
)

type peerCRLClientError struct {
	category PeerCRLClientFailure
	context  error
}

func (e *peerCRLClientError) Error() string { return ErrUnavailable.Error() }

func (e *peerCRLClientError) Is(target error) bool {
	return target == ErrUnavailable || (e.context != nil && errors.Is(e.context, target))
}

func peerCRLFailure(category PeerCRLClientFailure, ctx context.Context) error {
	var contextErr error
	if ctx != nil {
		contextErr = ctx.Err()
	}
	return &peerCRLClientError{category: category, context: contextErr}
}

func PeerCRLClientFailureOf(err error) (PeerCRLClientFailure, bool) {
	var failure *peerCRLClientError
	if errors.As(err, &failure) {
		return failure.category, true
	}
	return "", false
}
