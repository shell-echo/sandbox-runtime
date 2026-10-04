package phase6guestreceipt

import (
	"bytes"

	"github.com/shell-echo/sandbox-runtime/guestagent"
)

// VerifyV2OpenPrefix checks complete canonical lines written by one still-live
// PID1 capture. It deliberately rejects a seal: final acceptance must reread
// the closed raw file with VerifyV2, including its event count and zero drop.
func VerifyV2OpenPrefix(document []byte, role, profileDigest, configDigest string) ([]Record, error) {
	if (role != "product" && role != "guest") || !validDigest(profileDigest) || !validDigest(configDigest) ||
		len(document) < 2 || len(document) > MaxTotalBytes || document[len(document)-1] != '\n' {
		return nil, ErrUnavailable
	}
	lines := bytes.Split(document[:len(document)-1], []byte{'\n'})
	if len(lines) < 1 || len(lines) > MaxEvents+1 {
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
		if index == 0 {
			if record.Event != "begin" || record.ProfileDigest != profileDigest ||
				record.ConfigDigest != configDigest || record.AttemptDigest != "" ||
				record.BindingGeneration != 0 || record.Reason != "" ||
				record.EventCount != 0 || record.Dropped != 0 {
				return nil, ErrUnavailable
			}
		} else if record.Event == "seal" || record.ProfileDigest != "" || record.ConfigDigest != "" ||
			record.EventCount != 0 || record.Dropped != 0 || !validDigest(record.AttemptDigest) ||
			record.BindingGeneration < 1 || !validEventV2(role, record.Event, record.Reason) ||
			!validAttemptTransitionV2(attempts, role, record) {
			return nil, ErrUnavailable
		}
		records = append(records, record)
	}
	return records, nil
}

// VerifyV2InitialClosedPrefix is only a gate trigger for the bounded E
// network-isolation action. It is not a complete receipt, release proof, or
// substitute for the final two-stream VerifyV2RecoveryPair.
func VerifyV2InitialClosedPrefix(productRaw, guestRaw []byte, profileDigest,
	productConfigDigest, guestConfigDigest, initialDigest string, generation int64) error {
	if !validDigest(initialDigest) || generation < 1 {
		return ErrUnavailable
	}
	product, err := VerifyV2OpenPrefix(productRaw, "product", profileDigest, productConfigDigest)
	if err != nil {
		return err
	}
	guest, err := VerifyV2OpenPrefix(guestRaw, "guest", profileDigest, guestConfigDigest)
	if err != nil {
		return err
	}
	productEvents := make(map[string]Record)
	guestEvents := make(map[string]Record)
	for _, record := range product[1:] {
		if record.AttemptDigest == initialDigest {
			if record.BindingGeneration != generation {
				return ErrUnavailable
			}
			productEvents[record.Event] = record
		}
	}
	for _, record := range guest[1:] {
		if record.AttemptDigest == initialDigest {
			if record.BindingGeneration != generation {
				return ErrUnavailable
			}
			guestEvents[record.Event] = record
		}
	}
	if !exactEvents(productEvents, guestagent.ObservationProductAuthAccepted,
		guestagent.ObservationProductWelcomeWritten, guestagent.ObservationProductPeerInstalled,
		guestagent.ObservationProductAuthorityDependencyLost,
		guestagent.ObservationProductDisconnectPending,
		guestagent.ObservationProductCloseCompleted) ||
		productEvents[guestagent.ObservationProductCloseCompleted].Reason != "dependency_lost" ||
		!exactEvents(guestEvents, guestagent.ObservationGuestHelloWritten,
			guestagent.ObservationGuestWelcomeAccepted,
			guestagent.ObservationGuestReadTerminated) {
		return ErrUnavailable
	}
	return nil
}

// VerifyV2RecoveredClosedPrefix proves that a recovered attempt reached an
// actual close and released resolution in a still-open Product PID1 stream.
// Guest must already be independently sealed; neither a final Product seal nor
// an earlier attempt's release can substitute for this live observation.
func VerifyV2RecoveredClosedPrefix(productRaw, sealedGuestRaw []byte, profileDigest,
	productConfigDigest, guestConfigDigest, initialDigest, recoveredDigest string,
	generation int64) error {
	if !validDigest(initialDigest) || !validDigest(recoveredDigest) ||
		initialDigest == recoveredDigest || generation < 1 {
		return ErrUnavailable
	}
	product, err := VerifyV2OpenPrefix(productRaw, "product", profileDigest, productConfigDigest)
	if err != nil {
		return err
	}
	guest, err := VerifyV2(sealedGuestRaw, "guest", profileDigest, guestConfigDigest)
	if err != nil {
		return err
	}
	p, ok := recoveryOpenAttempts(product, generation)
	if !ok {
		return ErrUnavailable
	}
	g, ok := recoveryAttempts(guest, generation)
	if !ok || len(p) != len(g) || len(p) < 2 {
		return ErrUnavailable
	}
	firstP, firstPOk := p[initialDigest]
	freshP, freshPOk := p[recoveredDigest]
	firstG, firstGOk := g[initialDigest]
	freshG, freshGOk := g[recoveredDigest]
	if !firstPOk || !freshPOk || !firstGOk || !freshGOk ||
		!exactEvents(firstP, guestagent.ObservationProductAuthAccepted,
			guestagent.ObservationProductWelcomeWritten, guestagent.ObservationProductPeerInstalled,
			guestagent.ObservationProductAuthorityDependencyLost, guestagent.ObservationProductDisconnectPending,
			guestagent.ObservationProductCloseCompleted, guestagent.ObservationProductDisconnectResolved) ||
		firstP[guestagent.ObservationProductCloseCompleted].Reason != "dependency_lost" ||
		firstP[guestagent.ObservationProductDisconnectResolved].Reason != string(guestagent.RetirementReleased) ||
		!exactEvents(firstG, guestagent.ObservationGuestHelloWritten,
			guestagent.ObservationGuestWelcomeAccepted, guestagent.ObservationGuestReadTerminated) ||
		!exactEvents(freshP, guestagent.ObservationProductAuthAccepted,
			guestagent.ObservationProductWelcomeWritten, guestagent.ObservationProductPeerInstalled,
			guestagent.ObservationProductDisconnectPending, guestagent.ObservationProductCloseCompleted,
			guestagent.ObservationProductDisconnectResolved) ||
		freshP[guestagent.ObservationProductDisconnectResolved].Reason != string(guestagent.RetirementReleased) ||
		!exactEvents(freshG, guestagent.ObservationGuestHelloWritten,
			guestagent.ObservationGuestWelcomeAccepted, guestagent.ObservationGuestReadTerminated) ||
		firstP[guestagent.ObservationProductDisconnectResolved].Sequence >=
			freshP[guestagent.ObservationProductAuthAccepted].Sequence ||
		firstG[guestagent.ObservationGuestReadTerminated].Sequence >=
			freshG[guestagent.ObservationGuestHelloWritten].Sequence {
		return ErrUnavailable
	}
	switch freshP[guestagent.ObservationProductCloseCompleted].Reason {
	case "handler_shutdown", "operator_disconnect", "transport_terminated":
	default:
		return ErrUnavailable
	}
	for digest, events := range p {
		if digest == initialDigest || digest == recoveredDigest {
			continue
		}
		guestEvents, found := g[digest]
		if !found || !exactEvents(events, guestagent.ObservationProductAuthRetryable) ||
			!exactEvents(guestEvents, guestagent.ObservationGuestHelloWritten,
				guestagent.ObservationGuestAuthRetry) ||
			events[guestagent.ObservationProductAuthRetryable].Sequence >=
				freshP[guestagent.ObservationProductAuthAccepted].Sequence ||
			guestEvents[guestagent.ObservationGuestAuthRetry].Sequence >=
				freshG[guestagent.ObservationGuestHelloWritten].Sequence {
			return ErrUnavailable
		}
	}
	return nil
}

func recoveryOpenAttempts(records []Record, generation int64) (map[string]map[string]Record, bool) {
	result := make(map[string]map[string]Record)
	for _, record := range records[1:] {
		if record.BindingGeneration != generation {
			return nil, false
		}
		if result[record.AttemptDigest] == nil {
			result[record.AttemptDigest] = make(map[string]Record)
		}
		result[record.AttemptDigest][record.Event] = record
	}
	return result, true
}
