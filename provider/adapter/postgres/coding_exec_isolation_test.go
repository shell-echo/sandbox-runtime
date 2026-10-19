package providerpostgres

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
)

func isolationStored(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := encodeStoredState(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCodingExecIsolationRejectsDamagedOrMixedHistory(t *testing.T) {
	for _, change := range []string{"missing marker", "null marker", "noncanonical marker", "missing intents", "null intents", "noncanonical intents", "payload", "duplicate intent", "plan", "future record", "legacy exec", "null exec", "missing lifecycle", "null lifecycle", "missing slots", "null slots", "historical ID collision"} {
		t.Run(change, func(t *testing.T) {
			f, intents, request := execIntentFixture(t)
			if _, err := reserveIntentFixture(f, &intents, request); err != nil {
				t.Fatal(err)
			}
			marker := isolationStored(t, f.marker)
			var legacy []byte
			ledger, slots := isolationStored(t, f.ledger.Export()), isolationStored(t, f.slots)
			switch change {
			case "missing marker":
				marker = nil
			case "null marker":
				marker = []byte("null")
			case "noncanonical marker":
				raw, _ := json.Marshal(f.marker)
				marker, _ = json.Marshal(base64.StdEncoding.EncodeToString(append([]byte(" "), raw...)))
			case "payload":
				intents.Records[0].Request.Command[1] = "substituted"
			case "duplicate intent":
				intents.Records = append(intents.Records, intents.Records[0])
			case "plan":
				intents.PlanDigest = codingTestDigest("0")
			case "future record":
				intents.Records[0].Snapshot.ObservedAt = f.now.Add(time.Second)
			case "legacy exec":
				legacy = isolationStored(t, newExecState().Export())
			case "null exec":
				legacy = []byte("null")
			case "missing lifecycle":
				ledger = nil
			case "null lifecycle":
				ledger = []byte("null")
			case "missing slots":
				slots = nil
			case "null slots":
				slots = []byte("null")
			case "historical ID collision":
				lease := nextLeaseAdmission(t, f, request.OperationID, f.create.Fence+1)
				if _, err := lease.reserve(t.Context()); err != nil {
					t.Fatal(err)
				}
				ledger = isolationStored(t, lease.ledger.Export())
			}
			raw := isolationStored(t, intents)
			switch change {
			case "missing intents":
				raw = nil
			case "null intents":
				raw = []byte("null")
			case "noncanonical intents":
				document, _ := json.Marshal(intents)
				raw, _ = json.Marshal(base64.StdEncoding.EncodeToString(append(document, ' ')))
			}
			if _, err := decodeCodingExecIsolation(marker, raw, legacy, ledger, slots, nil, f.now); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("unsafe stored state accepted: %v", err)
			}
		})
	}
}

func TestCodingExecIsolationProtectsCandidateAndHistoricalReplay(t *testing.T) {
	f, intents, request := execIntentFixture(t)
	if _, err := reserveIntentFixture(f, &intents, request); err != nil {
		t.Fatal(err)
	}
	g, err := decodeCodingExecIsolation(isolationStored(t, f.marker), isolationStored(t, intents), nil, isolationStored(t, f.ledger.Export()), isolationStored(t, f.slots), nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	before := f.ledger.Export()
	lease := nextLeaseAdmission(t, f, request.OperationID, f.create.Fence+1)
	if _, err := lease.reserve(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := g.checkWrites(map[string][]byte{lifecycleDocument: isolationStored(t, lease.ledger.Export())}); !errors.Is(err, codingcontrol.ErrExecIntentConflict) {
		t.Fatalf("candidate reused intent ID: %v", err)
	}
	f.ledger = lease.ledger
	if got, err := reserveIntentFixture(f, &intents, request); !errors.Is(err, ErrCorrupt) || got != (codingcontrol.ExecIntentReceipt{}) {
		t.Fatalf("collision history replayed: %#v %v", got, err)
	}
	if !reflect.DeepEqual(before, g.ledger.Export()) {
		t.Fatal("candidate validation modified guard snapshot")
	}
	marker := f.marker
	marker.ExecIntentMode = ""
	if err := g.checkWrites(map[string][]byte{codingIdentityMarkerDocument: isolationStored(t, marker)}); !errors.Is(err, ErrCorrupt) {
		t.Fatal("mode downgrade accepted", err)
	}
	if err := g.checkWrites(map[string][]byte{execDocument: isolationStored(t, newExecState().Export())}); !errors.Is(err, ErrCodingExecIsolation) {
		t.Fatal("legacy execution write accepted", err)
	}
	if err := g.checkWrites(map[string][]byte{codingExecIntentDocument: isolationStored(t, intents)}); !errors.Is(err, ErrCorrupt) {
		t.Fatal("generic intent write accepted", err)
	}
	slots := f.slots.Clone()
	delete(slots.OriginalCreates, f.create.AllocationID)
	if err := g.checkWrites(map[string][]byte{codingIdentityStateDocument: isolationStored(t, slots)}); !errors.Is(err, ErrCorrupt) {
		t.Fatal("candidate slot corruption accepted", err)
	}
}

func TestCodingExecIsolationPreservesUnusedBootstrapAndLegacy(t *testing.T) {
	f, intents, _ := execIntentFixture(t)
	slots, err := codingidentity.NewState(f.plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCodingExecIsolation(isolationStored(t, f.marker), isolationStored(t, intents), nil, nil, isolationStored(t, slots), nil, f.now); err != nil {
		t.Fatal("explicit fresh bootstrap rejected", err)
	}
	for _, marker := range []codingIdentityMarker{{}, {Initialized: true, PlanDigest: f.marker.PlanDigest}, {Initialized: true, PlanDigest: f.marker.PlanDigest, AuthorityMode: codingAtomicOriginalMode, ControlPolicyDigest: f.marker.ControlPolicyDigest}} {
		g, err := decodeCodingExecIsolation(isolationStored(t, marker), nil, isolationStored(t, newExecState().Export()), nil, nil, nil, f.now)
		if err != nil || g.marker.ExecIntentMode != "" {
			t.Fatal("legacy mode changed", err)
		}
		if err := g.checkWrites(map[string][]byte{codingIdentityMarkerDocument: isolationStored(t, f.marker)}); !errors.Is(err, ErrCorrupt) {
			t.Fatal("implicit mode initialization accepted", err)
		}
	}
}
