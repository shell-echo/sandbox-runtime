package phase6guestreceipt

import (
	"bytes"
	"github.com/shell-echo/sandbox-runtime/guestagent"
)

// VerifyV2 checks one complete private stream. It deliberately never accepts
// v1 or guesses a protocol from the record contents. Process/source binding
// and cross-role chronology belong to the outer E-only gate.
func VerifyV2(document []byte, role, profileDigest, configDigest string) ([]Record, error) {
	if (role != "product" && role != "guest") || !validDigest(profileDigest) || !validDigest(configDigest) ||
		len(document) == 0 || len(document) > MaxTotalBytes || document[len(document)-1] != '\n' {
		return nil, ErrUnavailable
	}
	lines := bytes.Split(document[:len(document)-1], []byte{'\n'})
	if len(lines) < 2 || len(lines) > MaxEvents+2 {
		return nil, ErrUnavailable
	}
	records := make([]Record, 0, len(lines))
	attempts := make(map[string]*attemptState)
	previousElapsed := int64(-1)
	for index, line := range lines {
		if len(line) == 0 || len(line) > MaxRecordBytes {
			return nil, ErrUnavailable
		}
		record, err := decodeCanonical(line)
		if err != nil || record.Protocol != ProtocolV2 || record.Role != role ||
			record.Sequence != uint64(index+1) || record.ElapsedNanos < previousElapsed ||
			record.UnixMillis < 1_577_836_800_000 || record.UnixMillis > 4_102_444_800_000 {
			return nil, ErrUnavailable
		}
		previousElapsed = record.ElapsedNanos
		switch {
		case index == 0:
			if record.Event != "begin" || record.ProfileDigest != profileDigest || record.ConfigDigest != configDigest ||
				record.AttemptDigest != "" || record.BindingGeneration != 0 || record.Reason != "" ||
				record.EventCount != 0 || record.Dropped != 0 {
				return nil, ErrUnavailable
			}
		case index == len(lines)-1:
			if record.Event != "seal" || record.EventCount != uint64(len(lines)-2) || record.Dropped != 0 ||
				record.ProfileDigest != "" || record.ConfigDigest != "" || record.AttemptDigest != "" ||
				record.BindingGeneration != 0 || record.Reason != "" {
				return nil, ErrUnavailable
			}
		default:
			if record.ProfileDigest != "" || record.ConfigDigest != "" || record.EventCount != 0 ||
				record.Dropped != 0 || !validDigest(record.AttemptDigest) || record.BindingGeneration < 1 ||
				!validEventV2(role, record.Event, record.Reason) ||
				!validAttemptTransitionV2(attempts, role, record) {
				return nil, ErrUnavailable
			}
		}
		records = append(records, record)
	}
	for _, state := range attempts {
		if role == "product" && state.events[guestagent.ObservationProductAuthAccepted] &&
			!state.events[guestagent.ObservationProductDisconnectResolved] {
			return nil, ErrUnavailable
		}
		if role == "guest" && state.events[guestagent.ObservationGuestWelcomeAccepted] &&
			!state.events[guestagent.ObservationGuestReadTerminated] {
			return nil, ErrUnavailable
		}
	}
	return records, nil
}

func validAttemptTransitionV2(attempts map[string]*attemptState, role string, record Record) bool {
	state := attempts[record.AttemptDigest]
	if state == nil {
		state = &attemptState{generation: record.BindingGeneration, events: make(map[string]bool)}
		attempts[record.AttemptDigest] = state
	}
	if state.generation != record.BindingGeneration || state.events[record.Event] {
		return false
	}
	events := state.events
	if role == "guest" {
		switch record.Event {
		case guestagent.ObservationGuestHelloWritten:
			if len(events) != 0 {
				return false
			}
		case guestagent.ObservationGuestAuthRetry, guestagent.ObservationGuestWelcomeAccepted:
			if !events[guestagent.ObservationGuestHelloWritten] ||
				events[guestagent.ObservationGuestAuthRetry] || events[guestagent.ObservationGuestWelcomeAccepted] {
				return false
			}
		case guestagent.ObservationGuestReadTerminated:
			if !events[guestagent.ObservationGuestWelcomeAccepted] {
				return false
			}
		default:
			return false
		}
	} else {
		switch record.Event {
		case "product_validated_revoked", guestagent.ObservationProductAuthRetryable,
			guestagent.ObservationProductAuthAccepted:
			if len(events) != 0 {
				return false
			}
		case guestagent.ObservationProductWelcomeWritten:
			if !events[guestagent.ObservationProductAuthAccepted] || events[guestagent.ObservationProductDisconnectPending] {
				return false
			}
		case guestagent.ObservationProductPeerInstalled:
			if !events[guestagent.ObservationProductWelcomeWritten] || events[guestagent.ObservationProductDisconnectPending] {
				return false
			}
		case guestagent.ObservationProductAuthorityDependencyLost,
			guestagent.ObservationProductAuthorityStale:
			if !events[guestagent.ObservationProductPeerInstalled] ||
				events[guestagent.ObservationProductDisconnectPending] ||
				events[guestagent.ObservationProductAuthorityDependencyLost] ||
				events[guestagent.ObservationProductAuthorityStale] {
				return false
			}
		case guestagent.ObservationProductDisconnectPending:
			if !events[guestagent.ObservationProductAuthAccepted] || events[guestagent.ObservationProductCloseCompleted] {
				return false
			}
		case guestagent.ObservationProductCloseCompleted:
			if !events[guestagent.ObservationProductDisconnectPending] ||
				!validV2CloseCause(events, record.Reason) {
				return false
			}
		case guestagent.ObservationProductDisconnectResolved:
			if !events[guestagent.ObservationProductCloseCompleted] {
				return false
			}
		default:
			return false
		}
	}
	events[record.Event] = true
	return true
}

func validV2CloseCause(events map[string]bool, reason string) bool {
	switch reason {
	case "dependency_lost":
		return events[guestagent.ObservationProductAuthorityDependencyLost]
	case "authority_stale":
		return events[guestagent.ObservationProductAuthorityStale]
	case "already_connected":
		return events[guestagent.ObservationProductWelcomeWritten] &&
			!events[guestagent.ObservationProductPeerInstalled]
	case "handshake_failure":
		return !events[guestagent.ObservationProductPeerInstalled]
	case "operator_disconnect", "transport_terminated", "invalid_frame", "handler_shutdown":
		return events[guestagent.ObservationProductPeerInstalled]
	default:
		return false
	}
}
