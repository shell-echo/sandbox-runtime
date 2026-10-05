package providerpostgres

import (
	"errors"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

func TestCodingOriginalEnvelopeSurvivesRelease(t *testing.T) {
	fixture, input, now := testCodingReleasePGFixture(t, lifecycle.OperationSucceeded)
	document, err := dockercontrol.EncodeCodingCreateAuthority(input.Create)
	if err != nil {
		t.Fatal(err)
	}
	fixture.slots.OriginalCreates = map[string]codingidentity.OriginalCreateEnvelope{
		input.Create.AllocationID: {Document: string(document), Digest: input.Create.Digest()},
	}
	if err := validateCodingOriginalCreate(fixture.slots, fixture.ledger,
		fixture.plan, input.Create, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := finishCodingCurrentCleanup(t.Context(), &fixture.slots,
		&fixture.ledger, fixture.plan, input, now); err != nil {
		t.Fatal(err)
	}
	if len(fixture.slots.Reservations) != 0 || len(fixture.slots.Retirements) != 0 ||
		fixture.slots.OriginalCreates[input.Create.AllocationID].Digest != input.Create.Digest() ||
		validateCodingOriginalCreate(fixture.slots, fixture.ledger, fixture.plan,
			input.Create, now) != nil {
		t.Fatal("final CAS erased or changed historical original authority")
	}
	bad := fixture.slots.Clone()
	record := bad.OriginalCreates[input.Create.AllocationID]
	record.Digest = codingTestDigest("0")
	bad.OriginalCreates[input.Create.AllocationID] = record
	if err := validateCodingOriginalCreate(bad, fixture.ledger, fixture.plan,
		input.Create, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mutated original digest passed recovery: %v", err)
	}
}
