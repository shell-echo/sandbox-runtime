package transport

import (
	"errors"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/wire"
)

const (
	MaxObservationTypeBytes        = 32
	MaxObservationResultBytes      = 16
	MaxObservationMessageTypeBytes = 6
)

// ObservationType is a fixed ingress boundary event, never a caller-supplied
// label.
type ObservationType string

const (
	ObservationResolve          ObservationType = "resolve"
	ObservationActivation       ObservationType = "activation"
	ObservationUpstreamDial     ObservationType = "upstream_dial"
	ObservationStreamTerminated ObservationType = "stream_terminated"
	ObservationActionRead       ObservationType = "action_read"
	ObservationActionForwarded  ObservationType = "action_forwarded"
	ObservationActionFailed     ObservationType = "action_failed"
)

// ObservationResult is the bounded outcome vocabulary for an observation.
type ObservationResult string

const (
	ObservationResultReceived    ObservationResult = "received"
	ObservationResultComplete    ObservationResult = "complete"
	ObservationResultSucceeded   ObservationResult = "succeeded"
	ObservationResultInvalid     ObservationResult = "invalid"
	ObservationResultUnavailable ObservationResult = "unavailable"
	ObservationResultFenceLost   ObservationResult = "fence_lost"
)

// ObservationMessageType describes only the WebSocket data-frame class.
type ObservationMessageType string

const (
	ObservationMessageNone   ObservationMessageType = "none"
	ObservationMessageText   ObservationMessageType = "text"
	ObservationMessageBinary ObservationMessageType = "binary"
)

// Observation is the complete allowlisted metadata surface exposed by the
// private ingress. It cannot carry claims, identities, references, endpoints,
// credentials, or CDP payloads.
type Observation struct {
	Type        ObservationType
	Result      ObservationResult
	MessageType ObservationMessageType
	Bytes       uint64
}

// Observer persists one sanitized ingress boundary event synchronously.
type Observer interface {
	Observe(Observation) error
}

// ValidateObservation rejects unknown or inconsistent metadata combinations.
func ValidateObservation(value Observation) error {
	if len(value.Type) < 1 || len(value.Type) > MaxObservationTypeBytes ||
		len(value.Result) < 1 || len(value.Result) > MaxObservationResultBytes ||
		len(value.MessageType) < 1 || len(value.MessageType) > MaxObservationMessageTypeBytes {
		return errors.New("private ingress observation exceeds its metadata bounds")
	}
	switch value.Type {
	case ObservationResolve:
		if !oneOfResult(value.Result, ObservationResultSucceeded, ObservationResultInvalid, ObservationResultUnavailable) ||
			value.MessageType != ObservationMessageNone || value.Bytes > wire.MaxResolutionBytes {
			return errors.New("private ingress resolve observation is invalid")
		}
	case ObservationActivation:
		if !oneOfResult(value.Result, ObservationResultReceived, ObservationResultSucceeded, ObservationResultInvalid,
			ObservationResultUnavailable, ObservationResultFenceLost) || value.Bytes > wire.MaxActivationBytes {
			return errors.New("private ingress activation observation is invalid")
		}
		if value.Result == ObservationResultInvalid {
			if value.MessageType != ObservationMessageNone && value.MessageType != ObservationMessageText {
				return errors.New("private ingress activation message type is invalid")
			}
		} else if value.MessageType != ObservationMessageText {
			return errors.New("private ingress activation message type is invalid")
		}
	case ObservationUpstreamDial:
		if !oneOfResult(value.Result, ObservationResultSucceeded, ObservationResultUnavailable) ||
			value.MessageType != ObservationMessageNone || value.Bytes != 0 {
			return errors.New("private ingress upstream-dial observation is invalid")
		}
	case ObservationStreamTerminated:
		if value.Result != ObservationResultFenceLost || value.MessageType != ObservationMessageNone || value.Bytes != 0 {
			return errors.New("private ingress stream-termination observation is invalid")
		}
	case ObservationActionRead:
		if value.Result != ObservationResultComplete || !dataMessageType(value.MessageType) || value.Bytes > wire.MaxMessageBytes {
			return errors.New("private ingress action-read observation is invalid")
		}
	case ObservationActionForwarded:
		if value.Result != ObservationResultSucceeded || !dataMessageType(value.MessageType) || value.Bytes > wire.MaxMessageBytes {
			return errors.New("private ingress action-forwarded observation is invalid")
		}
	case ObservationActionFailed:
		if !oneOfResult(value.Result, ObservationResultFenceLost, ObservationResultUnavailable) ||
			!dataMessageType(value.MessageType) || value.Bytes > wire.MaxMessageBytes {
			return errors.New("private ingress action-failed observation is invalid")
		}
	default:
		return errors.New("private ingress observation type is invalid")
	}
	return nil
}

func oneOfResult(value ObservationResult, allowed ...ObservationResult) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func dataMessageType(value ObservationMessageType) bool {
	return value == ObservationMessageText || value == ObservationMessageBinary
}
