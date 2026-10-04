package phase6guestreceipt

import "github.com/shell-echo/sandbox-runtime/guestagent"

// VerifyV2RecoveryPair joins two already source/process-bound PID1 captures
// for the Product-alive PostgreSQL-loss component. The caller must separately
// prove the exact network fault/recovery boundary and process identities.
// A later ordered-replacement gate needs its own multi-PID1 binding.
func VerifyV2RecoveryPair(productRaw, guestRaw []byte, profileDigest, productConfigDigest,
	guestConfigDigest, initialDigest, recoveredDigest string, generation int64) error {
	if !validDigest(initialDigest) || !validDigest(recoveredDigest) ||
		initialDigest == recoveredDigest || generation < 1 {
		return ErrUnavailable
	}
	product, err := VerifyV2(productRaw, "product", profileDigest, productConfigDigest)
	if err != nil {
		return err
	}
	guest, err := VerifyV2(guestRaw, "guest", profileDigest, guestConfigDigest)
	if err != nil {
		return err
	}
	p, ok := recoveryAttempts(product, generation)
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

// VerifyV2ReplacementPair checks one fresh Product/Guest process pair after
// the outer gate proves both predecessor PID1 instances stopped, old nonce
// release was read back, and the successor process identities are distinct.
func VerifyV2ReplacementPair(productRaw, guestRaw []byte, profileDigest, productConfigDigest,
	guestConfigDigest, replacementDigest string, generation int64) error {
	if !validDigest(replacementDigest) || generation < 1 {
		return ErrUnavailable
	}
	product, err := VerifyV2(productRaw, "product", profileDigest, productConfigDigest)
	if err != nil {
		return err
	}
	guest, err := VerifyV2(guestRaw, "guest", profileDigest, guestConfigDigest)
	if err != nil {
		return err
	}
	p, ok := recoveryAttempts(product, generation)
	if !ok || len(p) != 1 {
		return ErrUnavailable
	}
	g, ok := recoveryAttempts(guest, generation)
	if !ok || len(g) != 1 {
		return ErrUnavailable
	}
	productEvents, productFound := p[replacementDigest]
	guestEvents, guestFound := g[replacementDigest]
	if !productFound || !guestFound ||
		!exactEvents(productEvents, guestagent.ObservationProductAuthAccepted,
			guestagent.ObservationProductWelcomeWritten, guestagent.ObservationProductPeerInstalled,
			guestagent.ObservationProductDisconnectPending, guestagent.ObservationProductCloseCompleted,
			guestagent.ObservationProductDisconnectResolved) ||
		productEvents[guestagent.ObservationProductDisconnectResolved].Reason != string(guestagent.RetirementReleased) ||
		!exactEvents(guestEvents, guestagent.ObservationGuestHelloWritten,
			guestagent.ObservationGuestWelcomeAccepted, guestagent.ObservationGuestReadTerminated) {
		return ErrUnavailable
	}
	switch productEvents[guestagent.ObservationProductCloseCompleted].Reason {
	case "handler_shutdown", "operator_disconnect", "transport_terminated":
		return nil
	default:
		return ErrUnavailable
	}
}

func recoveryAttempts(records []Record, generation int64) (map[string]map[string]Record, bool) {
	result := make(map[string]map[string]Record)
	for _, record := range records[1 : len(records)-1] {
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

func exactEvents(events map[string]Record, names ...string) bool {
	if len(events) != len(names) {
		return false
	}
	for _, name := range names {
		if _, found := events[name]; !found {
			return false
		}
	}
	return true
}
