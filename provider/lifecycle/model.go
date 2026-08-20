// Package lifecycle contains backend-neutral Provider sandbox lifecycle values
// and deterministic state transitions. It deliberately has no transport,
// persistence, or runtime-driver dependencies.
package lifecycle

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	MaxIdentifierLength = 200
	MaxSlotKeyLength    = 128
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	slotKeyPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9/_-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

var (
	ErrInvalidIdentifier    = errors.New("invalid lifecycle identifier")
	ErrInvalidDigest        = errors.New("invalid lifecycle digest")
	ErrInvalidSpec          = errors.New("invalid lifecycle spec")
	ErrInvalidState         = errors.New("invalid lifecycle state")
	ErrInvalidTransition    = errors.New("invalid lifecycle transition")
	ErrGenerationConflict   = errors.New("lifecycle generation conflict")
	ErrStaleFencingToken    = errors.New("stale lifecycle fencing token")
	ErrDeadlineExpired      = errors.New("lifecycle deadline expired")
	ErrInvalidDeadline      = errors.New("invalid lifecycle deadline")
	ErrInvalidLease         = errors.New("invalid lifecycle lease")
	ErrTerminalOperation    = errors.New("lifecycle operation is terminal")
	ErrCancellationRequired = errors.New("lifecycle cancellation was not requested")
)

type DesiredState string

const (
	DesiredReady      DesiredState = "ready"
	DesiredSuspended  DesiredState = "suspended"
	DesiredTerminated DesiredState = "terminated"
)

func (s DesiredState) valid() bool {
	return s == DesiredReady || s == DesiredSuspended || s == DesiredTerminated
}

type ObservedState string

const (
	ObservedRequested    ObservedState = "requested"
	ObservedProvisioning ObservedState = "provisioning"
	ObservedReady        ObservedState = "ready"
	ObservedSuspending   ObservedState = "suspending"
	ObservedSuspended    ObservedState = "suspended"
	ObservedResuming     ObservedState = "resuming"
	ObservedTerminating  ObservedState = "terminating"
	ObservedTerminated   ObservedState = "terminated"
	ObservedExpired      ObservedState = "expired"
	ObservedFailed       ObservedState = "failed"
)

func (s ObservedState) valid() bool {
	switch s {
	case ObservedRequested, ObservedProvisioning, ObservedReady,
		ObservedSuspending, ObservedSuspended, ObservedResuming,
		ObservedTerminating, ObservedTerminated, ObservedExpired, ObservedFailed:
		return true
	default:
		return false
	}
}

func (s ObservedState) terminal() bool {
	return s == ObservedTerminated || s == ObservedExpired
}

type OperationType string

const OperationCreate OperationType = "create"

func (t OperationType) valid() bool { return t == OperationCreate }

type OperationState string

const (
	OperationAccepted       OperationState = "accepted"
	OperationRunning        OperationState = "running"
	OperationSucceeded      OperationState = "succeeded"
	OperationFailed         OperationState = "failed"
	OperationCancelled      OperationState = "cancelled"
	OperationOutcomeUnknown OperationState = "outcome_unknown"
)

func (s OperationState) valid() bool {
	switch s {
	case OperationAccepted, OperationRunning, OperationSucceeded,
		OperationFailed, OperationCancelled, OperationOutcomeUnknown:
		return true
	default:
		return false
	}
}

func (s OperationState) terminal() bool {
	return s == OperationSucceeded || s == OperationFailed ||
		s == OperationCancelled || s == OperationOutcomeUnknown
}

type FailureOutcome string

const (
	FailureKnown   FailureOutcome = "known_failed"
	FailureUnknown FailureOutcome = "outcome_unknown"
)

func (o FailureOutcome) valid() bool { return o == FailureKnown || o == FailureUnknown }

type Failure struct {
	Code      string
	Retryable bool
	Outcome   FailureOutcome
}

type SandboxSpec struct {
	SandboxID          string
	TenantID           string
	WorkOrderID        string
	WorkspaceID        string
	ProviderRevisionID string
	RuntimeProfile     string
	SandboxSlotKey     string
	LeaseExpiresAt     time.Time
}

func (s SandboxSpec) Validate(now time.Time) error {
	if now.IsZero() {
		return fmt.Errorf("%w: current time is required", ErrInvalidSpec)
	}
	for name, value := range map[string]string{
		"sandbox_id":           s.SandboxID,
		"tenant_id":            s.TenantID,
		"work_order_id":        s.WorkOrderID,
		"workspace_id":         s.WorkspaceID,
		"provider_revision_id": s.ProviderRevisionID,
		"runtime_profile":      s.RuntimeProfile,
	} {
		if err := ValidateIdentifier(value); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrInvalidSpec, name, err)
		}
	}
	if err := ValidateSlotKey(s.SandboxSlotKey); err != nil {
		return fmt.Errorf("%w: sandbox_slot_key: %w", ErrInvalidSpec, err)
	}
	if s.LeaseExpiresAt.IsZero() || !s.LeaseExpiresAt.After(now) {
		return fmt.Errorf("%w: lease must be after current time", ErrInvalidSpec)
	}
	return nil
}

type CreateRequest struct {
	OperationID    string
	AttemptID      string
	FencingToken   uint64
	IdempotencyKey string
	RequestDigest  string
	Deadline       time.Time
	Spec           SandboxSpec
}

func (r CreateRequest) Validate(now time.Time) error {
	if err := ValidateIdentifier(r.OperationID); err != nil {
		return fmt.Errorf("%w: operation_id: %w", ErrInvalidSpec, err)
	}
	if err := ValidateIdentifier(r.AttemptID); err != nil {
		return fmt.Errorf("%w: attempt_id: %w", ErrInvalidSpec, err)
	}
	if r.FencingToken == 0 {
		return fmt.Errorf("%w: fencing token must be positive", ErrInvalidSpec)
	}
	if strings.TrimSpace(r.IdempotencyKey) == "" || len(r.IdempotencyKey) > MaxIdentifierLength {
		return fmt.Errorf("%w: idempotency key must contain 1-%d characters", ErrInvalidSpec, MaxIdentifierLength)
	}
	if err := ValidateDigest(r.RequestDigest); err != nil {
		return fmt.Errorf("%w: request_digest: %w", ErrInvalidSpec, err)
	}
	if err := ValidateDeadline(now, r.Deadline); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSpec, err)
	}
	return r.Spec.Validate(now)
}

type Sandbox struct {
	ID                 string
	TenantID           string
	WorkOrderID        string
	WorkspaceID        string
	ProviderRevisionID string
	RuntimeProfile     string
	SandboxSlotKey     string
	DesiredState       DesiredState
	ObservedState      ObservedState
	Generation         uint64
	ObservedGeneration uint64
	LeaseExpiresAt     time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func (s Sandbox) Validate() error {
	for name, value := range map[string]string{
		"sandbox_id":           s.ID,
		"tenant_id":            s.TenantID,
		"work_order_id":        s.WorkOrderID,
		"workspace_id":         s.WorkspaceID,
		"provider_revision_id": s.ProviderRevisionID,
		"runtime_profile":      s.RuntimeProfile,
	} {
		if err := ValidateIdentifier(value); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrInvalidSpec, name, err)
		}
	}
	if err := ValidateSlotKey(s.SandboxSlotKey); err != nil {
		return fmt.Errorf("%w: sandbox_slot_key: %w", ErrInvalidSpec, err)
	}
	if !s.DesiredState.valid() || !s.ObservedState.valid() {
		return ErrInvalidState
	}
	if s.Generation == 0 || s.ObservedGeneration > s.Generation {
		return ErrGenerationConflict
	}
	if s.LeaseExpiresAt.IsZero() || s.CreatedAt.IsZero() || s.UpdatedAt.IsZero() {
		return ErrInvalidSpec
	}
	if s.UpdatedAt.Before(s.CreatedAt) {
		return ErrInvalidSpec
	}
	return nil
}

type Operation struct {
	ID              string
	AttemptID       string
	FencingToken    uint64
	SandboxID       string
	Type            OperationType
	State           OperationState
	Deadline        time.Time
	ObservedAt      time.Time
	CancelRequested bool
	Failure         *Failure
}

func (o Operation) Validate() error {
	if err := ValidateIdentifier(o.ID); err != nil {
		return err
	}
	if err := ValidateIdentifier(o.AttemptID); err != nil {
		return err
	}
	if err := ValidateIdentifier(o.SandboxID); err != nil {
		return err
	}
	if o.FencingToken == 0 || !o.Type.valid() || !o.State.valid() || o.Deadline.IsZero() || o.ObservedAt.IsZero() {
		return ErrInvalidSpec
	}
	if o.State == OperationFailed && (o.Failure == nil || o.Failure.Outcome != FailureKnown) {
		return ErrInvalidSpec
	}
	if o.State == OperationOutcomeUnknown && (o.Failure == nil || o.Failure.Outcome != FailureUnknown) {
		return ErrInvalidSpec
	}
	if o.Failure != nil && (!o.Failure.Outcome.valid() || strings.TrimSpace(o.Failure.Code) == "" || len(o.Failure.Code) > 64) {
		return ErrInvalidSpec
	}
	if o.Failure != nil && o.State != OperationFailed && o.State != OperationOutcomeUnknown {
		return ErrInvalidSpec
	}
	return nil
}

func ValidateIdentifier(value string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("%w: value must match the bounded identifier format", ErrInvalidIdentifier)
	}
	return nil
}

func ValidateSlotKey(value string) error {
	if !slotKeyPattern.MatchString(value) || len(value) > MaxSlotKeyLength {
		return fmt.Errorf("%w: value must match the bounded slot-key format", ErrInvalidIdentifier)
	}
	return nil
}

func ValidateDigest(value string) error {
	if !digestPattern.MatchString(value) {
		return ErrInvalidDigest
	}
	return nil
}

func ValidateDeadline(now, deadline time.Time) error {
	if now.IsZero() || deadline.IsZero() {
		return ErrInvalidDeadline
	}
	if !deadline.After(now) {
		return ErrDeadlineExpired
	}
	return nil
}

func CheckDeadline(now, deadline time.Time) error {
	return ValidateDeadline(now, deadline)
}
