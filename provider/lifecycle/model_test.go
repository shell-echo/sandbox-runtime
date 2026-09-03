package lifecycle

import (
	"errors"
	"testing"
	"time"
)

var lifecycleTestTime = time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

func validCreateRequest() CreateRequest {
	return CreateRequest{
		OperationID:    "operation-create-1",
		AttemptID:      "attempt-create-1",
		FencingToken:   1,
		IdempotencyKey: "create-key-1",
		RequestDigest:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:       lifecycleTestTime.Add(5 * time.Minute),
		Spec: SandboxSpec{
			SandboxID:          "sandbox-1",
			TenantID:           "tenant-1",
			WorkOrderID:        "work-order-1",
			WorkspaceID:        "workspace-1",
			ProviderRevisionID: "provider-revision-1",
			RuntimeProfile:     "profile-1",
			SandboxSlotKey:     "primary-code",
			LeaseExpiresAt:     lifecycleTestTime.Add(time.Hour),
		},
	}
}

func TestStartCreateInitializesProviderLocalState(t *testing.T) {
	sandbox, operation, err := StartCreate(validCreateRequest(), lifecycleTestTime)
	if err != nil {
		t.Fatal(err)
	}
	if sandbox.ObservedState != ObservedRequested || sandbox.DesiredState != DesiredReady || sandbox.Generation != 1 || sandbox.ObservedGeneration != 0 {
		t.Fatalf("sandbox initial state = %#v", sandbox)
	}
	if operation.State != OperationAccepted || operation.Type != OperationCreate || operation.SandboxID != sandbox.ID {
		t.Fatalf("operation initial state = %#v", operation)
	}
	if err := sandbox.Validate(); err != nil {
		t.Fatalf("created sandbox Validate() = %v", err)
	}
	if err := operation.Validate(); err != nil {
		t.Fatalf("created operation Validate() = %v", err)
	}
}

func TestCreateRejectsInvalidBoundsAndTime(t *testing.T) {
	tests := map[string]struct {
		mutate func(*CreateRequest)
		want   error
	}{
		"missing operation": {func(r *CreateRequest) { r.OperationID = "" }, ErrInvalidIdentifier},
		"zero fencing":      {func(r *CreateRequest) { r.FencingToken = 0 }, ErrInvalidSpec},
		"invalid digest":    {func(r *CreateRequest) { r.RequestDigest = "sha256:bad" }, ErrInvalidDigest},
		"expired deadline":  {func(r *CreateRequest) { r.Deadline = lifecycleTestTime }, ErrDeadlineExpired},
		"expired lease":     {func(r *CreateRequest) { r.Spec.LeaseExpiresAt = lifecycleTestTime }, ErrInvalidSpec},
		"bad slot":          {func(r *CreateRequest) { r.Spec.SandboxSlotKey = "Primary" }, ErrInvalidIdentifier},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			request := validCreateRequest()
			test.mutate(&request)
			_, _, err := StartCreate(request, lifecycleTestTime)
			if !errors.Is(err, test.want) {
				t.Fatalf("StartCreate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestBrowserCreateRequiresRestrictedGatewayPolicy(t *testing.T) {
	request := validCreateRequest()
	request.Spec.RuntimeProfile = BrowserRuntimeProfile
	request.Spec.Network = NetworkPolicy{
		Mode: NetworkRestricted, PolicyReference: "browser-egress-policy-1", EgressGatewayRequired: true,
	}
	sandbox, _, err := StartCreate(request, lifecycleTestTime)
	if err != nil {
		t.Fatal(err)
	}
	if sandbox.Network != request.Spec.Network {
		t.Fatalf("network policy = %#v", sandbox.Network)
	}
	for name, mutate := range map[string]func(*CreateRequest){
		"network none":      func(r *CreateRequest) { r.Spec.Network = NetworkPolicy{Mode: NetworkNone} },
		"missing policy":    func(r *CreateRequest) { r.Spec.Network.PolicyReference = "" },
		"missing gateway":   func(r *CreateRequest) { r.Spec.Network.EgressGatewayRequired = false },
		"restricted coding": func(r *CreateRequest) { r.Spec.RuntimeProfile = "profile-1" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := request
			mutate(&invalid)
			if _, _, err := StartCreate(invalid, lifecycleTestTime); !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestObservedTransitionsEnforceGenerationAndStateOrder(t *testing.T) {
	sandbox, _, err := StartCreate(validCreateRequest(), lifecycleTestTime)
	if err != nil {
		t.Fatal(err)
	}
	provisioning, err := ApplyObservedTransition(sandbox, ObservedProvisioning, 1, lifecycleTestTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ready, err := ApplyObservedTransition(provisioning, ObservedReady, 1, lifecycleTestTime.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if ready.ObservedGeneration != 1 {
		t.Fatalf("ready observed generation = %d, want 1", ready.ObservedGeneration)
	}
	if _, err := ApplyObservedTransition(ready, ObservedProvisioning, 1, lifecycleTestTime.Add(3*time.Second)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("backward transition error = %v, want invalid transition", err)
	}
	if _, err := ApplyObservedTransition(ready, ObservedSuspending, 2, lifecycleTestTime.Add(3*time.Second)); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("wrong generation error = %v, want generation conflict", err)
	}
	if repeated, err := ApplyObservedTransition(ready, ObservedReady, 1, lifecycleTestTime.Add(3*time.Second)); err != nil || repeated.ObservedState != ObservedReady {
		t.Fatalf("repeated ready transition = %#v, %v", repeated, err)
	}
}

func TestDesiredStateBumpsGenerationAndRejectsStaleExpectedGeneration(t *testing.T) {
	sandbox, _, err := StartCreate(validCreateRequest(), lifecycleTestTime)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := RequestDesiredState(sandbox, DesiredSuspended, 1, lifecycleTestTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if updated.Generation != 2 || updated.ObservedGeneration != 0 || updated.DesiredState != DesiredSuspended {
		t.Fatalf("desired state update = %#v", updated)
	}
	if _, err := RequestDesiredState(updated, DesiredReady, 1, lifecycleTestTime.Add(2*time.Second)); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("stale desired state error = %v, want generation conflict", err)
	}
	if repeated, err := RequestDesiredState(updated, DesiredSuspended, 2, lifecycleTestTime.Add(2*time.Second)); err != nil || repeated.Generation != updated.Generation {
		t.Fatalf("same desired state update = %#v, %v", repeated, err)
	}
}

func TestLeaseExpiryIsExplicitAndIdempotent(t *testing.T) {
	sandbox, _, err := StartCreate(validCreateRequest(), lifecycleTestTime)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := ApplyObservedTransition(sandbox, ObservedProvisioning, 1, lifecycleTestTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ready, err = ApplyObservedTransition(ready, ObservedReady, 1, lifecycleTestTime.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExpireLease(ready, ready.LeaseExpiresAt.Add(-time.Nanosecond)); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("active lease error = %v, want invalid lease", err)
	}
	expired, err := ExpireLease(ready, ready.LeaseExpiresAt)
	if err != nil || expired.ObservedState != ObservedExpired || expired.Generation != ready.Generation {
		t.Fatalf("expired sandbox = %#v, %v", expired, err)
	}
	if repeated, err := ExpireLease(expired, ready.LeaseExpiresAt.Add(time.Second)); err != nil || repeated.ObservedState != ObservedExpired {
		t.Fatalf("repeated expiry = %#v, %v", repeated, err)
	}
}

func TestFencingRejectsOnlyOlderWork(t *testing.T) {
	if err := CheckFencing(3, 2); !errors.Is(err, ErrStaleFencingToken) {
		t.Fatalf("stale fencing error = %v", err)
	}
	if got, err := AdvanceFencing(3, 3); err != nil || got != 3 {
		t.Fatalf("same fencing token = %d, %v", got, err)
	}
	if got, err := AdvanceFencing(3, 4); err != nil || got != 4 {
		t.Fatalf("new fencing token = %d, %v", got, err)
	}
}

func TestOperationDeadlineCancellationAndUnknownOutcome(t *testing.T) {
	_, operation, err := StartCreate(validCreateRequest(), lifecycleTestTime)
	if err != nil {
		t.Fatal(err)
	}
	running, err := BeginOperation(operation, lifecycleTestTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	requested, err := RequestCancellation(running, lifecycleTestTime.Add(2*time.Second))
	if err != nil || !requested.CancelRequested || requested.State != OperationRunning {
		t.Fatalf("cancellation request = %#v, %v", requested, err)
	}
	cancelled, err := ConfirmCancellation(requested, lifecycleTestTime.Add(3*time.Second))
	if err != nil || cancelled.State != OperationCancelled {
		t.Fatalf("cancellation confirmation = %#v, %v", cancelled, err)
	}
	if _, err := SucceedOperation(cancelled, lifecycleTestTime.Add(4*time.Second)); !errors.Is(err, ErrTerminalOperation) {
		t.Fatalf("terminal operation error = %v", err)
	}

	_, unknownOperation, err := StartCreate(validCreateRequest(), lifecycleTestTime)
	if err != nil {
		t.Fatal(err)
	}
	unknownOperation, err = BeginOperation(unknownOperation, lifecycleTestTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := MarkOutcomeUnknown(unknownOperation, lifecycleTestTime.Add(2*time.Second), Failure{Code: "TIMEOUT", Retryable: true, Outcome: FailureUnknown})
	if err != nil || unknown.State != OperationOutcomeUnknown || unknown.Failure == nil {
		t.Fatalf("unknown outcome = %#v, %v", unknown, err)
	}

	late, lateOperation, err := StartCreate(validCreateRequest(), lifecycleTestTime)
	if err != nil {
		t.Fatal(err)
	}
	_ = late
	if _, err := BeginOperation(lateOperation, lateOperation.Deadline); !errors.Is(err, ErrDeadlineExpired) {
		t.Fatalf("late operation error = %v, want deadline expired", err)
	}
}

func TestOperationFailureRequiresKnownOutcome(t *testing.T) {
	_, operation, err := StartCreate(validCreateRequest(), lifecycleTestTime)
	if err != nil {
		t.Fatal(err)
	}
	operation, err = BeginOperation(operation, lifecycleTestTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FailOperation(operation, lifecycleTestTime.Add(2*time.Second), Failure{Code: "LOST", Outcome: FailureUnknown}); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("unknown failure as failed error = %v", err)
	}
	if _, err := MarkOutcomeUnknown(operation, lifecycleTestTime.Add(2*time.Second), Failure{Code: "FAILED", Outcome: FailureKnown}); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("known failure as unknown error = %v", err)
	}
}
