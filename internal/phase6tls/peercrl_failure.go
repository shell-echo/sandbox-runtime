package phase6tls

import (
	"context"
	"errors"

	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

// PeerCRLFailureClass is an in-process startup diagnostic, never a wire field.
// No class claims the controller rejected a request: an agent error frame is
// indistinguishable from several controller/transport failures at this layer.
type PeerCRLFailureClass string

const (
	PeerCRLLocalGuardFailure       PeerCRLFailureClass = "local-guard"
	PeerCRLParentCanceledFailure   PeerCRLFailureClass = "parent-canceled"
	PeerCRLParentDeadlineFailure   PeerCRLFailureClass = "parent-deadline"
	PeerCRLInternalDeadlineFailure PeerCRLFailureClass = "internal-deadline"
	PeerCRLRequestBuildFailure     PeerCRLFailureClass = "agent-request-build"
	PeerCRLSocketPeerFailure       PeerCRLFailureClass = "agent-socket-peer"
	PeerCRLTransportFailure        PeerCRLFailureClass = "agent-transport"
	PeerCRLAgentResponseFailure    PeerCRLFailureClass = "agent-response"
	PeerCRLBindingFailure          PeerCRLFailureClass = "guard-binding"
	PeerCRLSemanticFailure         PeerCRLFailureClass = "crl-semantic"
	PeerCRLUnknownFailure          PeerCRLFailureClass = "unknown"
)

type peerCRLFailureError struct {
	class   PeerCRLFailureClass
	context error
}

func (e *peerCRLFailureError) Error() string { return ErrPeerCRLUnavailable.Error() }

func (e *peerCRLFailureError) Is(target error) bool {
	return target == ErrPeerCRLUnavailable || (e.context != nil && errors.Is(e.context, target))
}

func newPeerCRLFailure(class PeerCRLFailureClass, contextErr error) error {
	return &peerCRLFailureError{class: class, context: contextErr}
}

func peerCRLContextFailure(parent, operation context.Context) error {
	// Parent cancellation/deadline wins deterministically when both fired.
	if parent != nil {
		switch parent.Err() {
		case context.Canceled:
			return newPeerCRLFailure(PeerCRLParentCanceledFailure, context.Canceled)
		case context.DeadlineExceeded:
			return newPeerCRLFailure(PeerCRLParentDeadlineFailure, context.DeadlineExceeded)
		}
	}
	if operation != nil && operation.Err() != nil {
		return newPeerCRLFailure(PeerCRLInternalDeadlineFailure, context.DeadlineExceeded)
	}
	return nil
}

func PeerCRLFailureOf(err error) PeerCRLFailureClass {
	var local *peerCRLFailureError
	if errors.As(err, &local) {
		return local.class
	}
	return PeerCRLUnknownFailure
}

func peerCRLAgentFailure(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return newPeerCRLFailure(PeerCRLInternalDeadlineFailure, context.DeadlineExceeded)
	}
	if clientClass, ok := workloadtlsagent.PeerCRLClientFailureOf(err); ok {
		switch clientClass {
		case workloadtlsagent.PeerCRLRequestBuildFailure:
			return newPeerCRLFailure(PeerCRLRequestBuildFailure, nil)
		case workloadtlsagent.PeerCRLSocketPeerFailure:
			return newPeerCRLFailure(PeerCRLSocketPeerFailure, nil)
		case workloadtlsagent.PeerCRLTransportFailure:
			return newPeerCRLFailure(PeerCRLTransportFailure, nil)
		case workloadtlsagent.PeerCRLResponseFailure:
			return newPeerCRLFailure(PeerCRLAgentResponseFailure, nil)
		}
	}
	return newPeerCRLFailure(PeerCRLAgentResponseFailure, nil)
}
