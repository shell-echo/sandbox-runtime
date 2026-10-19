package providerpostgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	execrepository "github.com/shell-echo/sandbox-runtime/provider/exec/repository"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

var ErrCodingExecIsolation = errors.New("generic execution is unavailable in Coding intent mode")

type codingExecIsolation struct {
	marker  codingIdentityMarker
	intents codingExecIntentState
	fences  codingExecFenceState
	legacy  []byte
	slots   codingidentity.State
	ledger  lifecyclerepository.State
}

type codingExecRowReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Writers call this only after acquiring control_state FOR UPDATE. Readers
// use one statement snapshot. This is a namespace guard, never an exec permit.
func readCodingExecIsolation(ctx context.Context, reader codingExecRowReader) (*codingExecIsolation, error) {
	var markerRaw, intentsRaw, legacyRaw, ledgerRaw, slotsRaw, fencesRaw []byte
	if err := reader.QueryRow(ctx, `SELECT documents->$1,documents->$2,documents->$3,documents->$4,documents->$5,documents->$6 FROM sandbox_runtime_provider.control_state WHERE singleton`,
		codingIdentityMarkerDocument, codingExecIntentDocument, execDocument, lifecycleDocument, codingIdentityStateDocument, codingExecFenceDocument).
		Scan(&markerRaw, &intentsRaw, &legacyRaw, &ledgerRaw, &slotsRaw, &fencesRaw); err != nil {
		return nil, stateError(ctx, ctx, err)
	}
	return decodeCodingExecIsolation(markerRaw, intentsRaw, legacyRaw, ledgerRaw, slotsRaw, fencesRaw, time.Now().UTC())
}

func decodeCodingExecIsolation(markerRaw, intentsRaw, legacyRaw, ledgerRaw, slotsRaw, fencesRaw []byte, now time.Time) (*codingExecIsolation, error) {
	g := &codingExecIsolation{legacy: legacyRaw}
	raw, exists, err := decodeCodingExecDocument(markerRaw)
	if err != nil || (exists && importCodingIdentityMarker(&g.marker, raw) != nil) {
		return nil, ErrCorrupt
	}
	fenceRaw, hasFences, fenceErr := decodeCodingExecDocument(fencesRaw)
	if fenceErr != nil || (g.marker.ExecFenceMode == "" && hasFences) ||
		(g.marker.ExecFenceMode != "" && (!hasFences || importCodingExecFences(&g.fences, fenceRaw) != nil)) {
		return nil, ErrCorrupt
	}
	raw, exists, err = decodeCodingExecDocument(intentsRaw)
	if err != nil {
		return nil, ErrCorrupt
	}
	if g.marker.ExecIntentMode == "" {
		if exists { // An orphan is not permission to initialize over history.
			return nil, ErrCorrupt
		}
		return g, nil
	}
	if !exists || len(legacyRaw) != 0 || importCodingExecIntents(&g.intents, raw) != nil {
		return nil, ErrCorrupt
	}
	ledger, slots := newLifecycleState(), codingidentity.State{}
	raw, hasLedger, err := decodeCodingExecDocument(ledgerRaw)
	if err != nil || (hasLedger && importLifecycleState(&ledger, raw) != nil) {
		return nil, ErrCorrupt
	}
	raw, exists, err = decodeCodingExecDocument(slotsRaw)
	if err != nil || !exists || importCodingIdentityState(&slots, raw) != nil {
		return nil, ErrCorrupt
	}
	// The existing explicit initializer permits an absent, unused lifecycle
	// document. Once any history exists, absence is corruption, not fresh state.
	if !hasLedger && (len(g.intents.Records) != 0 || len(slots.Reservations) != 0 || len(slots.Retirements) != 0 || len(slots.OriginalCreates) != 0 || len(slots.CreateCompletions) != 0) {
		return nil, ErrCorrupt
	}
	if checkCodingRetirementBarrierWithMarker(g.marker, slots, ledger, ledger, now) != nil ||
		g.intents.validateNamespace(g.marker, ledger, now) != nil {
		return nil, ErrCorrupt
	}
	if g.marker.ExecFenceMode != "" && g.fences.validateNamespace(g.marker, slots, ledger, g.intents, now) != nil {
		return nil, ErrCorrupt
	}
	g.slots, g.ledger = slots, ledger
	return g, nil
}

// Validate persisted identity independently of a runtime plan. The stricter
// frozen-plan/spec/completion validation remains mandatory at intent admission.
func (s codingExecIntentState) validateNamespace(marker codingIdentityMarker, ledger lifecyclerepository.State, now time.Time) error {
	if marker.validate() != nil || marker.ExecIntentMode != codingExecIntentMode || s.PlanDigest != marker.PlanDigest ||
		s.Version != 1 || s.Mode != codingExecIntentMode || s.Records == nil || len(s.Records) > maxCodingExecIntents || now.IsZero() {
		return ErrCorrupt
	}
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, record := range s.Records {
		request := record.Request
		_, _, payload, err := codingExecRequest(request, record.Snapshot.ObservedAt)
		if err != nil || payload != record.PayloadDigest || record.Snapshot.ObservedAt.After(now) || ids[request.OperationID] || keys[request.IdempotencyKey] {
			return ErrCorrupt
		}
		if _, exists := ledger.Operations[request.OperationID]; exists {
			return codingcontrol.ErrExecIntentConflict
		}
		ids[request.OperationID], keys[request.IdempotencyKey] = true, true
	}
	return nil
}

// Check before callbacks as well as before UPDATE: typed replay callbacks may
// return a rollback sentinel that their caller translates into success.
func codingExecWriteGuard(ctx context.Context, tx pgx.Tx, keys ...string) (*codingExecIsolation, error) {
	relevant, genericExec := false, false
	for _, key := range keys {
		if key == codingExecIntentDocument || key == codingExecFenceDocument {
			return nil, ErrCorrupt // Only dedicated transactions own these documents.
		}
		switch key {
		case codingIdentityMarkerDocument, codingIdentityStateDocument, lifecycleDocument, execDocument:
			relevant = true
		}
		genericExec = genericExec || key == execDocument
	}
	if !relevant {
		return nil, nil
	}
	g, err := readCodingExecIsolation(ctx, tx)
	if err != nil {
		return nil, err
	}
	if genericExec && g.marker.ExecIntentMode != "" {
		return nil, ErrCodingExecIsolation
	}
	return g, nil
}

func (g *codingExecIsolation) checkWrites(writes map[string][]byte) error {
	if g == nil {
		return nil
	}
	if _, exists := writes[codingExecFenceDocument]; exists {
		return ErrCorrupt
	}
	if _, exists := writes[codingExecIntentDocument]; exists {
		return ErrCorrupt
	}
	if stored, exists := writes[codingIdentityMarkerDocument]; exists {
		raw, present, err := decodeCodingExecDocument(stored)
		var next codingIdentityMarker
		if err != nil || !present || importCodingIdentityMarker(&next, raw) != nil {
			return ErrCorrupt
		}
		if g.marker.ExecIntentMode != "" && next != g.marker || g.marker.ExecIntentMode == "" && (next.ExecIntentMode != "" || next.ExecFenceMode != "") {
			return ErrCorrupt // Only the explicit initializer may enable this mode.
		}
	}
	if g.marker.ExecIntentMode == "" {
		return nil
	}
	if _, exists := writes[execDocument]; exists {
		return ErrCodingExecIsolation
	}
	ledger, slots := g.ledger, g.slots
	if stored, exists := writes[lifecycleDocument]; exists {
		raw, present, err := decodeCodingExecDocument(stored)
		ledger = newLifecycleState()
		if err != nil || !present || importLifecycleState(&ledger, raw) != nil {
			return ErrCorrupt
		}
	}
	if stored, exists := writes[codingIdentityStateDocument]; exists {
		raw, present, err := decodeCodingExecDocument(stored)
		slots = codingidentity.State{}
		if err != nil || !present || importCodingIdentityState(&slots, raw) != nil {
			return ErrCorrupt
		}
	}
	now := time.Now().UTC()
	if err := g.intents.validateNamespace(g.marker, ledger, now); err != nil {
		return err
	}
	if checkCodingRetirementBarrierWithMarker(g.marker, slots, ledger, ledger, now) != nil {
		return ErrCorrupt
	}
	if g.marker.ExecFenceMode != "" && g.fences.validateNamespace(g.marker, slots, ledger, g.intents, now) != nil {
		return ErrCorrupt
	}
	return nil
}

func readLegacyExecState(ctx context.Context, store *Store) (execrepository.State, error) {
	empty := newExecState()
	if ctx == nil || store == nil || store.pool == nil {
		return empty, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	bounded, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	g, err := readCodingExecIsolation(bounded, store.pool)
	if err != nil {
		if errors.Is(err, ErrCorrupt) {
			return empty, err
		}
		return empty, stateError(ctx, bounded, err)
	}
	if g.marker.ExecIntentMode != "" {
		return empty, ErrCodingExecIsolation
	}
	raw, exists, err := decodeStoredDocument(g.legacy)
	if err != nil || exists && importExecState(&empty, json.RawMessage(raw)) != nil {
		return newExecState(), ErrCorrupt
	}
	return empty, nil
}
