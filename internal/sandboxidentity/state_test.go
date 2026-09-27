package sandboxidentity

import (
	"errors"
	"strings"
	"testing"
)

func testPlan() Plan {
	return Plan{ProfileDigest: testDigest("a"), OwnerDeployment: "provider-browser-runtime",
		OwnerPrincipalDigest: testDigest("b"), Namespace: "browser-production", ServiceName: "postgres",
		ServiceIdentityDigest: testDigest("c"), TrustEdgeID: "provider-browser-postgres", MaterialBindingID: "browser-provider-runtime-dsn",
		EgressPolicyID: "provider-browser-egress", BrokerDeployment: "egress-broker-provider-browser",
		BrokerRoleEdgeID: "egress-role-provider-browser", BrokerExternalEdgeID: "egress-provider-browser-postgres",
		DatabaseName: "provider_browser", RuntimeRole: "browser_provider_runtime",
		ControllerID: "browser-controller-1", Capacity: 2,
		Template: "browser-sandbox-runtime", TemplateDigest: testDigest("c"),
		Slots: []Slot{
			{ID: "browser-0000", WorkloadUID: 41000, WorkloadGID: 51000, GatewayUID: 43000, GatewayGID: 53000},
			{ID: "browser-0001", WorkloadUID: 41001, WorkloadGID: 51001, GatewayUID: 43001, GatewayGID: 53001},
		}}
}

func testDigest(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }

func testClaim(session string) Claim {
	return Claim{SandboxID: session, SessionID: session, OperationID: "operation-1", AttemptID: "attempt-1",
		RequestDigest: testDigest("d"), Generation: 1, Fence: 1}
}

func testSpecs() map[string]string {
	return map[string]string{"browser-0000": testDigest("e"), "browser-0001": testDigest("f")}
}

func TestFinitePlanAndOwnerBoundary(t *testing.T) {
	plan := testPlan()
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	first, _ := plan.Digest()
	modified := testPlan()
	modified.ControllerID = "browser-controller-2"
	second, _ := modified.Digest()
	if first == second {
		t.Fatal("controller was not bound to plan digest")
	}
	for name, mutate := range map[string]func(*Plan){
		"wrong owner":    func(p *Plan) { p.OwnerDeployment = "browser-executor-backend" },
		"wrong template": func(p *Plan) { p.Template = "desktop-sandbox-runtime" },
		"unsorted":       func(p *Plan) { p.Slots[0], p.Slots[1] = p.Slots[1], p.Slots[0] },
		"UID collision":  func(p *Plan) { p.Slots[1].GatewayUID = p.Slots[0].WorkloadUID },
		"GID collision":  func(p *Plan) { p.Slots[1].WorkloadGID = p.Slots[0].GatewayGID },
		"root":           func(p *Plan) { p.Slots[0].WorkloadUID = 0 },
		"capacity": func(p *Plan) {
			p.Slots = make([]Slot, MaxSlots+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := testPlan()
			mutate(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("invalid owner-local plan accepted")
			}
		})
	}
}

func TestRuntimeProjectionOmitsDatabaseAuthorityAndRejectsSlotDrift(t *testing.T) {
	plan := testPlan()
	authority, err := plan.ProjectRuntimeAuthority()
	if err != nil || authority.Validate() != nil || authority.PlanDigest == "" ||
		authority.OwnerDeployment != plan.OwnerDeployment || authority.Capacity != plan.Capacity {
		t.Fatalf("runtime projection = %#v, %v", authority, err)
	}
	authority.Slots[0].WorkloadUID++
	if authority.Slots[0] == plan.Slots[0] {
		t.Fatal("runtime projection aliases the trusted plan")
	}
	authority.Slots[0].WorkloadUID = plan.Slots[1].WorkloadUID
	if authority.Validate() == nil {
		t.Fatal("runtime projection accepted colliding UID")
	}
}

func TestReservationLifecycleKeepsUnknownAndFencesCleanup(t *testing.T) {
	plan := testPlan()
	var missing State
	if !errors.Is(missing.Validate(plan), ErrUninitialized) {
		t.Fatal("missing ledger became an empty pool")
	}
	state, err := NewState(plan)
	if err != nil {
		t.Fatal(err)
	}
	first, err := state.Reserve(plan, testClaim("sandbox-1"), testSpecs())
	if err != nil || first.Status != Reserved || first.Slot.ID != "browser-0000" {
		t.Fatalf("reserve = %+v, %v", first, err)
	}
	retry, err := state.Reserve(plan, testClaim("sandbox-1"), testSpecs())
	if err != nil || retry != first {
		t.Fatalf("retry = %+v, %v", retry, err)
	}
	changed := testClaim("sandbox-1")
	changed.Generation++
	if _, err := state.Reserve(plan, changed, testSpecs()); !errors.Is(err, ErrConflict) {
		t.Fatalf("generation drift = %v", err)
	}
	changed = testClaim("sandbox-1")
	changed.SessionID = "new-session"
	if _, err := state.Reserve(plan, changed, testSpecs()); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-sandbox second session = %v", err)
	}
	creating, err := state.BeginCreate(plan, first)
	if err != nil || creating.Status != Creating {
		t.Fatalf("create permit = %+v, %v", creating, err)
	}
	if _, err := state.BeginCreate(plan, first); !errors.Is(err, ErrInProgress) {
		t.Fatalf("parallel create = %v", err)
	}
	if _, err := state.BeginCleanup(plan, creating); !errors.Is(err, ErrInProgress) {
		t.Fatalf("unknown create was cleaned = %v", err)
	}
	second, err := state.Reserve(plan, testClaim("sandbox-2"), testSpecs())
	if err != nil || second.Slot.ID != "browser-0001" {
		t.Fatalf("second slot = %+v, %v", second, err)
	}
	if _, err := state.Reserve(plan, testClaim("sandbox-3"), testSpecs()); !errors.Is(err, ErrExhausted) {
		t.Fatalf("unknown slot reused = %v", err)
	}
	active, err := state.CompleteCreate(plan, creating)
	if err != nil || active.Status != Active {
		t.Fatalf("complete create = %+v, %v", active, err)
	}
	cleaning, err := state.BeginCleanup(plan, active)
	if err != nil || cleaning.Status != Cleaning {
		t.Fatalf("cleanup fence = %+v, %v", cleaning, err)
	}
	if _, err := state.BeginCreate(plan, first); !errors.Is(err, ErrConflict) {
		t.Fatalf("late create after cleanup fence = %v", err)
	}
	if retry, err := state.BeginCleanup(plan, active); err != nil || retry != cleaning {
		t.Fatalf("cleanup retry = %+v, %v", retry, err)
	}
	forged := cleaning
	forged.Slot.WorkloadUID++
	if err := state.CompleteCleanup(plan, forged); !errors.Is(err, ErrConflict) {
		t.Fatalf("forged cleanup = %v", err)
	}
	if err := state.CompleteCleanup(plan, cleaning); err != nil {
		t.Fatal(err)
	}
	next, err := state.Reserve(plan, testClaim("sandbox-3"), testSpecs())
	if err != nil || next.Slot.ID != first.Slot.ID {
		t.Fatalf("verified cleanup reuse = %+v, %v", next, err)
	}
	if state.Validate(plan) != nil {
		t.Fatal("valid state became corrupt")
	}
}

func TestReservationStateRejectsPlanAndDocumentDrift(t *testing.T) {
	plan := testPlan()
	state, _ := NewState(plan)
	if _, err := state.Reserve(plan, testClaim("sandbox-1"), testSpecs()); err != nil {
		t.Fatal(err)
	}
	drifted := testPlan()
	drifted.ProfileDigest = testDigest("9")
	if state.Validate(drifted) == nil {
		t.Fatal("profile revision drift accepted")
	}
	corrupt := state.Clone()
	corrupt.Reservations[0].Slot.GatewayGID++
	if corrupt.Validate(plan) == nil {
		t.Fatal("slot identity drift accepted")
	}
	corrupt = state.Clone()
	corrupt.Reservations[0].Status = "unknown"
	if corrupt.Validate(plan) == nil {
		t.Fatal("unknown status accepted")
	}
	corrupt = state.Clone()
	corrupt.Reservations = nil
	if corrupt.Validate(plan) == nil {
		t.Fatal("missing reservation array accepted")
	}
}
