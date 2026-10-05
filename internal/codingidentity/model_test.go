package codingidentity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testDigest(label string) string {
	if label == "" {
		label = "a"
	}
	return "sha256:" + strings.Repeat(label[:1], 64)
}

func testPlan() Plan {
	return Plan{Protocol: Protocol, Version: Version, ProfileDigest: testDigest("a"),
		OwnerDeployment: "provider-runtime", OwnerPrincipalDigest: testDigest("b"),
		Namespace: "provider-coding", ControllerID: "provider-coding-controller",
		Template: "coding-sandbox-runtime", TemplateDigest: testDigest("c"),
		ImageDigest: testDigest("d"), ImageConfigDigest: testDigest("1"), NetworkMode: "none",
		Limits:   Limits{MemoryBytes: 1 << 30, CPUMillis: 1000, PIDs: 64},
		Capacity: LocalCandidateCapacity, Slots: []Slot{
			{ID: "coding-0000", WorkloadUID: 57000, WorkloadGID: 58000,
				InputsVolume: "coding-0000-inputs", WorkspaceVolume: "coding-0000-workspace", OutputsVolume: "coding-0000-outputs"},
			{ID: "coding-0001", WorkloadUID: 57001, WorkloadGID: 58001,
				InputsVolume: "coding-0001-inputs", WorkspaceVolume: "coding-0001-workspace", OutputsVolume: "coding-0001-outputs"},
		}}
}

func testClaim(id string) Claim {
	allocationID, err := DeriveAllocationID("revision-1", "tenant-1", "sandbox-"+id, "operation-"+id)
	if err != nil {
		panic(err)
	}
	return Claim{TenantDigest: testDigest("e"), SandboxID: "sandbox-" + id,
		AllocationID: allocationID, OperationID: "operation-" + id,
		AttemptID: "attempt-" + id, RequestDigest: testDigest("f"), Generation: 1, Fence: 1}
}

func testSpecs(plan Plan) map[string]string {
	result := make(map[string]string, len(plan.Slots))
	for _, slot := range plan.Slots {
		result[slot.ID] = testDigest("d")
	}
	return result
}

func TestLocalCodingPlanIsClosedAndCollisionChecked(t *testing.T) {
	plan := testPlan()
	if err := plan.ValidateLocalCandidate([]uint32{10000, 42000}, []uint32{10001, 52000}); err != nil {
		t.Fatal(err)
	}
	if _, err := plan.Digest(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Plan){
		"v1 protocol":      func(p *Plan) { p.Protocol = "sandbox-runtime.phase6-security-profile.v1" },
		"missing owner":    func(p *Plan) { p.OwnerDeployment = "" },
		"wrong owner":      func(p *Plan) { p.OwnerDeployment = "provider-browser-runtime" },
		"wrong template":   func(p *Plan) { p.Template = "browser-sandbox-runtime" },
		"wrong image":      func(p *Plan) { p.ImageDigest = testDigest("z") + "bad" },
		"missing config":   func(p *Plan) { p.ImageConfigDigest = "" },
		"extra network":    func(p *Plan) { p.NetworkMode = "bridge" },
		"unbounded CPU":    func(p *Plan) { p.Limits.CPUMillis = 0 },
		"third slot":       func(p *Plan) { p.Slots = append(p.Slots, Slot{ID: "coding-0002"}); p.Capacity++ },
		"missing slot":     func(p *Plan) { p.Slots = p.Slots[:1] },
		"reordered slots":  func(p *Plan) { p.Slots[0], p.Slots[1] = p.Slots[1], p.Slots[0] },
		"identity overlap": func(p *Plan) { p.Slots[1].WorkloadUID = p.Slots[0].WorkloadUID },
		"cross volume":     func(p *Plan) { p.Slots[1].InputsVolume = p.Slots[0].InputsVolume },
		"shared directory": func(p *Plan) { p.Slots[0].WorkspaceVolume = "coding-0000/inputs" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := testPlan()
			mutate(&candidate)
			if err := candidate.ValidateLocalCandidate([]uint32{10000}, []uint32{10001}); !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("invalid local plan accepted: %v", err)
			}
		})
	}
	if err := plan.ValidateAgainst([]uint32{57000}, []uint32{10001}); !errors.Is(err, ErrInvalidPlan) {
		t.Fatal("static or Browser/Desktop UID collision accepted")
	}
	if err := plan.ValidateAgainst([]uint32{10000}, []uint32{58001}); !errors.Is(err, ErrInvalidPlan) {
		t.Fatal("static or Browser/Desktop GID collision accepted")
	}
	if err := plan.ValidateAgainst(nil, nil); !errors.Is(err, ErrInvalidPlan) {
		t.Fatal("empty complete inventory accepted")
	}
}

func TestGenerationScopedWholeVolumesCannotAlias(t *testing.T) {
	plan := testPlan()
	slot := plan.Slots[0]
	first := testClaim("one")
	a, b, c, err := plan.EffectiveVolumes(slot.ID, first)
	if err != nil || a == b || a == c || b == c || strings.ContainsAny(a+b+c, "/\\") {
		t.Fatalf("whole volume names = %q/%q/%q, %v", a, b, c, err)
	}
	mounts, err := plan.EffectiveMounts(slot.ID, first)
	if err != nil || len(mounts) != 3 || mounts[0] != (VolumeMount{Name: a, Target: "/inputs", ReadOnly: true}) ||
		mounts[1] != (VolumeMount{Name: b, Target: "/workspace"}) ||
		mounts[2] != (VolumeMount{Name: c, Target: "/outputs"}) {
		t.Fatalf("closed whole-volume mounts = %#v, %v", mounts, err)
	}
	second := first
	second.Generation++
	a2, b2, c2, err := plan.EffectiveVolumes(slot.ID, second)
	if err != nil || a == a2 || b == b2 || c == c2 {
		t.Fatal("new generation reused old volume names")
	}
	third := testClaim("two")
	a3, _, _, err := plan.EffectiveVolumes(slot.ID, third)
	if err != nil || a == a3 {
		t.Fatal("new allocation with same generation reused old volume name")
	}
	otherProfile := plan
	otherProfile.ProfileDigest = testDigest("2")
	a4, _, _, err := otherProfile.EffectiveVolumes(slot.ID, first)
	if err != nil || a == a4 {
		t.Fatal("new Profile reused old volume name")
	}
}

func TestAcceptedCreateDerivesStablePrivateAllocationIdentity(t *testing.T) {
	baseline, err := DeriveAllocationID("revision-1", "tenant-1", "sandbox-1", "operation-1")
	if err != nil || baseline != "codingalloc-498f082afe3e9de18401b37be27fb9afbb0d5a136f2a2eb7a18678a716ac729d" {
		t.Fatalf("derived allocation = %q, %v", baseline, err)
	}
	again, err := DeriveAllocationID("revision-1", "tenant-1", "sandbox-1", "operation-1")
	if err != nil || again != baseline {
		t.Fatal("same accepted create changed allocation identity across recovery")
	}
	for _, fields := range [][4]string{
		{"revision-2", "tenant-1", "sandbox-1", "operation-1"},
		{"revision-1", "tenant-2", "sandbox-1", "operation-1"},
		{"revision-1", "tenant-1", "sandbox-2", "operation-1"},
		{"revision-1", "tenant-1", "sandbox-1", "operation-2"},
	} {
		other, err := DeriveAllocationID(fields[0], fields[1], fields[2], fields[3])
		if err != nil || other == baseline {
			t.Fatalf("cross-scope allocation alias = %q, %v", other, err)
		}
	}
	if _, err := DeriveAllocationID("revision-1", "tenant-1", "bad/sandbox", "operation-1"); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("invalid source identity admitted: %v", err)
	}
	malformed := testClaim("one")
	malformed.AllocationID = "allocation-from-caller"
	if err := malformed.Validate(); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("non-derived allocation shape admitted: %v", err)
	}
	tenant, err := TenantDigestForID("tenant-1")
	if err != nil || tenant != "sha256:9af98ff40e12b466e877f7b4d5692d98a7f0e64899340c420a8bf02af576ff1a" {
		t.Fatalf("tenant digest = %q, %v", tenant, err)
	}
}

func TestUnknownPhysicalOutcomeRetainsBothSlotsAcrossRestart(t *testing.T) {
	plan := testPlan()
	state, err := NewState(plan)
	if err != nil {
		t.Fatal(err)
	}
	specs := testSpecs(plan)
	closedOperations := map[string]bool{}
	authorize := func(claim Claim) error {
		if closedOperations[claim.OperationID] {
			return errors.New("Provider operation already terminal")
		}
		return nil // Offline stand-in, not a Provider PostgreSQL ledger.
	}
	if _, err := state.Reserve(plan, testClaim("one"), specs, nil); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("reservation without Provider ledger authority accepted: %v", err)
	}
	first, err := state.Reserve(plan, testClaim("one"), specs, authorize)
	if err != nil {
		t.Fatal(err)
	}
	first, err = state.BeginCreate(plan, first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := state.Reserve(plan, testClaim("two"), specs, authorize)
	if err != nil {
		t.Fatal(err)
	}
	reservedSecond := second
	second, err = state.BeginCreate(plan, second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Reserve(plan, testClaim("three"), specs, authorize); !errors.Is(err, ErrExhausted) {
		t.Fatalf("third allocation not refused: %v", err)
	}
	for name, mutate := range map[string]func(*Claim){
		"fence":      func(c *Claim) { c.Fence++ },
		"generation": func(c *Claim) { c.Generation++ },
		"request":    func(c *Claim) { c.RequestDigest = testDigest("0") },
		"tenant":     func(c *Claim) { c.TenantDigest = testDigest("1") },
		"operation":  func(c *Claim) { c.OperationID = "other-operation" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := first.Claim
			mutate(&changed)
			if _, err := state.Reserve(plan, changed, specs, authorize); !errors.Is(err, ErrConflict) {
				t.Fatalf("existing allocation authority drift accepted: %v", err)
			}
		})
	}
	operationReplay := testClaim("three")
	operationReplay.OperationID = first.Claim.OperationID
	if _, err := state.Reserve(plan, operationReplay, specs, authorize); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-sandbox operation replay accepted: %v", err)
	}
	if _, err := state.BeginCleanup(plan, first); !errors.Is(err, ErrInProgress) {
		t.Fatalf("unknown create outcome was released: %v", err)
	}
	document, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var recovered State
	if err := json.Unmarshal(document, &recovered); err != nil || recovered.Validate(plan) != nil {
		t.Fatalf("restart state = %#v, %v", recovered, err)
	}
	if _, err := recovered.Reserve(plan, testClaim("three"), specs, authorize); !errors.Is(err, ErrExhausted) {
		t.Fatalf("restart freed unknown outcome: %v", err)
	}
	if _, err := recovered.BeginCreate(plan, first); !errors.Is(err, ErrInProgress) {
		t.Fatalf("restart redispatched create: %v", err)
	}
	second, err = recovered.CompleteCreate(plan, second)
	if err != nil {
		t.Fatal(err)
	}
	second, err = recovered.BeginCleanup(plan, second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ConfirmAbsence(context.Background(), second, func(context.Context, Reservation) error {
		return errors.New("volume still present")
	}); err == nil {
		t.Fatal("failed absence check released slot")
	}
	if err := recovered.CompleteCleanup(plan, second, AbsenceProof{}); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("cleanup without absence proof accepted: %v", err)
	}
	if _, err := recovered.Reserve(plan, testClaim("three"), specs, authorize); !errors.Is(err, ErrExhausted) {
		t.Fatalf("failed cleanup freed slot: %v", err)
	}
	proof, err := ConfirmAbsence(context.Background(), second, func(_ context.Context, ticket Reservation) error {
		if ticket.Claim.AllocationID != second.Claim.AllocationID {
			return errors.New("wrong allocation")
		}
		return nil // Offline stand-in only; no physical evidence is claimed.
	})
	if err != nil {
		t.Fatal(err)
	}
	wrong := second
	wrong.Claim.Fence++
	if err := recovered.CompleteCleanup(plan, wrong, proof); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("stale fence used fresh absence proof: %v", err)
	}
	if err := recovered.CompleteCleanup(plan, second, proof); err != nil {
		t.Fatal(err)
	}
	closedOperations[second.Claim.OperationID] = true
	if _, err := recovered.Reserve(plan, second.Claim, specs, authorize); !errors.Is(err, ErrConflict) {
		t.Fatalf("completed old Claim reopened after cleanup: %v", err)
	}
	if _, err := recovered.BeginCreate(plan, reservedSecond); !errors.Is(err, ErrConflict) {
		t.Fatalf("old Reserved ticket dispatched after cleanup: %v", err)
	}
	third, err := recovered.Reserve(plan, testClaim("three"), specs, authorize)
	if err != nil || third.Slot.ID != second.Slot.ID {
		t.Fatalf("verified cleanup did not free exact slot: %#v, %v", third, err)
	}
	if _, err := recovered.CompleteCreate(plan, second); !errors.Is(err, ErrConflict) {
		t.Fatalf("old receipt applied after reuse: %v", err)
	}
}
