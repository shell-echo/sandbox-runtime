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
	Code      string         `json:"code"`
	Retryable bool           `json:"retryable"`
	Outcome   FailureOutcome `json:"outcome"`
}

type Lease struct {
	SandboxID    string    `json:"sandbox_id"`
	ExpiresAt    time.Time `json:"expires_at"`
	Generation   uint64    `json:"generation"`
	FencingToken uint64    `json:"fencing_token"`
}

func (l Lease) Validate() error {
	if err := ValidateIdentifier(l.SandboxID); err != nil {
		return err
	}
	if l.ExpiresAt.IsZero() || l.Generation == 0 || l.FencingToken == 0 {
		return ErrInvalidLease
	}
	return nil
}

type Event struct {
	ID           string    `json:"id"`
	SandboxID    string    `json:"sandbox_id"`
	OperationID  string    `json:"operation_id"`
	Sequence     uint64    `json:"sequence"`
	Generation   uint64    `json:"generation"`
	FencingToken uint64    `json:"fencing_token"`
	Kind         string    `json:"kind"`
	DataDigest   string    `json:"data_digest,omitempty"`
	OccurredAt   time.Time `json:"occurred_at"`
}

func (e Event) Validate() error {
	if err := ValidateIdentifier(e.ID); err != nil {
		return err
	}
	if err := ValidateIdentifier(e.SandboxID); err != nil {
		return err
	}
	if err := ValidateIdentifier(e.OperationID); err != nil {
		return err
	}
	if err := ValidateIdentifier(e.Kind); err != nil {
		return err
	}
	if e.Generation == 0 || e.FencingToken == 0 || e.OccurredAt.IsZero() {
		return ErrInvalidSpec
	}
	if e.DataDigest != "" {
		if err := ValidateDigest(e.DataDigest); err != nil {
			return err
		}
	}
	return nil
}

type SandboxSpec struct {
	SandboxID          string    `json:"sandbox_id"`
	TenantID           string    `json:"tenant_id"`
	WorkOrderID        string    `json:"work_order_id"`
	WorkspaceID        string    `json:"workspace_id"`
	ProviderRevisionID string    `json:"provider_revision_id"`
	RuntimeProfile     string    `json:"runtime_profile"`
	SandboxSlotKey     string    `json:"sandbox_slot_key"`
	LeaseExpiresAt     time.Time `json:"lease_expires_at"`
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
	OperationID    string      `json:"operation_id"`
	AttemptID      string      `json:"attempt_id"`
	FencingToken   uint64      `json:"fencing_token"`
	IdempotencyKey string      `json:"idempotency_key"`
	RequestDigest  string      `json:"request_digest"`
	Deadline       time.Time   `json:"deadline"`
	Spec           SandboxSpec `json:"spec"`
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
	ID                 string        `json:"sandbox_id"`
	TenantID           string        `json:"tenant_id"`
	WorkOrderID        string        `json:"work_order_id"`
	WorkspaceID        string        `json:"workspace_id"`
	ProviderRevisionID string        `json:"provider_revision_id"`
	RuntimeProfile     string        `json:"runtime_profile"`
	SandboxSlotKey     string        `json:"sandbox_slot_key"`
	DesiredState       DesiredState  `json:"desired_state"`
	ObservedState      ObservedState `json:"observed_state"`
	Generation         uint64        `json:"generation"`
	ObservedGeneration uint64        `json:"observed_generation"`
	LeaseExpiresAt     time.Time     `json:"lease_expires_at"`
	CreatedAt          time.Time     `json:"created_at"`
	UpdatedAt          time.Time     `json:"updated_at"`
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
	ID              string         `json:"operation_id"`
	AttemptID       string         `json:"attempt_id"`
	FencingToken    uint64         `json:"fencing_token"`
	SandboxID       string         `json:"sandbox_id"`
	Type            OperationType  `json:"type"`
	State           OperationState `json:"state"`
	Deadline        time.Time      `json:"deadline"`
	ObservedAt      time.Time      `json:"observed_at"`
	CancelRequested bool           `json:"cancel_requested"`
	Failure         *Failure       `json:"failure,omitempty"`
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
