// Package session contains the backend-neutral Provider-local terminal session
// domain. It does not import transport DTOs, lifecycle repositories, instance
// models, allocators, or runtime drivers.
package session

import (
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

const MaxIdempotencyKeyRunes = 200

var (
	ErrInvalidRequest     = errors.New("invalid Provider terminal session request")
	ErrDeadlineExpired    = errors.New("Provider terminal session deadline has expired")
	ErrInvalidExpiry      = errors.New("invalid Provider terminal session expiry")
	ErrInvalidRecord      = errors.New("invalid Provider terminal session record")
	ErrInvalidHandoff     = errors.New("invalid Provider terminal session handoff")
	ErrInvalidAllocation  = errors.New("invalid Provider terminal session allocation evidence")
	ErrAllocationConflict = errors.New("Provider terminal session allocation evidence conflict")
	ErrInvalidTransition  = errors.New("invalid Provider terminal session transition")
	ErrTerminalOperation  = errors.New("Provider terminal session operation is terminal")
	ErrHandoffUnavailable = errors.New("Provider terminal session handoff is unavailable")
	ErrHandoffExpired     = errors.New("Provider terminal session handoff has expired")

	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	endpointPattern   = regexp.MustCompile(`^ref:session:[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)
	allocationPattern = regexp.MustCompile(`^ref:terminal/[0-9a-f]{32}$`)
)

type RuntimeType string

const RuntimeTerminal RuntimeType = "terminal"

type Protocol string

const ProtocolWebSocket Protocol = "websocket"

// OpenRequest is the provider-local projection of a terminal session request.
// SandboxID and ProviderRevisionID are supplied by admitted path/token context,
// not trusted from additional wire fields.
type OpenRequest struct {
	SandboxID           string      `json:"sandbox_id"`
	ProviderRevisionID  string      `json:"provider_revision_id"`
	OperationID         string      `json:"operation_id"`
	AttemptID           string      `json:"attempt_id"`
	FencingToken        int64       `json:"fencing_token"`
	IdempotencyKey      string      `json:"idempotency_key"`
	RequestDigest       string      `json:"request_digest"`
	Deadline            time.Time   `json:"deadline"`
	ExpectedGeneration  int64       `json:"expected_generation"`
	RuntimeSessionID    string      `json:"runtime_session_id"`
	RuntimeType         RuntimeType `json:"runtime_type"`
	CapabilityProfileID string      `json:"capability_profile_id"`
	ExpiresAt           time.Time   `json:"expires_at"`
}

// Clone returns an immutable value snapshot for authority and application
// boundaries. All fields are value types in this slice.
func (r OpenRequest) Clone() OpenRequest { return r }

// Validate checks local Contract bounds relative to now. Sandbox readiness,
// revision, generation, lease, fencing high-water, and advertised capability
// checks belong to the transactional Authority port.
func (r OpenRequest) Validate(now time.Time) error {
	if now.IsZero() {
		return fmt.Errorf("%w: current time", ErrInvalidRequest)
	}
	if err := r.validateStructure(); err != nil {
		return err
	}
	if !r.Deadline.After(now) {
		return ErrDeadlineExpired
	}
	if !r.ExpiresAt.After(now) || r.ExpiresAt.After(r.Deadline) {
		return ErrInvalidExpiry
	}
	return nil
}

func (r OpenRequest) validateStructure() error {
	for name, value := range map[string]string{
		"sandbox_id":            r.SandboxID,
		"provider_revision_id":  r.ProviderRevisionID,
		"operation_id":          r.OperationID,
		"attempt_id":            r.AttemptID,
		"runtime_session_id":    r.RuntimeSessionID,
		"capability_profile_id": r.CapabilityProfileID,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%w: %s", ErrInvalidRequest, name)
		}
	}
	if !validBoundedString(r.IdempotencyKey, 1, MaxIdempotencyKeyRunes) {
		return fmt.Errorf("%w: idempotency_key", ErrInvalidRequest)
	}
	if r.FencingToken < 1 || r.ExpectedGeneration < 1 {
		return fmt.Errorf("%w: fencing token and expected generation must be positive", ErrInvalidRequest)
	}
	if !digestPattern.MatchString(r.RequestDigest) {
		return fmt.Errorf("%w: request digest", ErrInvalidRequest)
	}
	if r.Deadline.IsZero() {
		return fmt.Errorf("%w: deadline is required", ErrInvalidRequest)
	}
	if r.ExpiresAt.IsZero() {
		return ErrInvalidExpiry
	}
	if r.RuntimeType != RuntimeTerminal {
		return fmt.Errorf("%w: runtime type", ErrInvalidRequest)
	}
	return nil
}

type Status string

const (
	StatusAccepted       Status = "accepted"
	StatusRunning        Status = "running"
	StatusSucceeded      Status = "succeeded"
	StatusFailed         Status = "failed"
	StatusCancelled      Status = "cancelled"
	StatusOutcomeUnknown Status = "outcome_unknown"
)

func (s Status) valid() bool {
	switch s {
	case StatusAccepted, StatusRunning, StatusSucceeded, StatusFailed, StatusCancelled, StatusOutcomeUnknown:
		return true
	default:
		return false
	}
}

func (s Status) terminal() bool {
	return s == StatusSucceeded || s == StatusFailed || s == StatusCancelled || s == StatusOutcomeUnknown
}

// EndpointEvidence is trusted provider-local success evidence. Its reference
// is an opaque control-plane handle, never a URL, address, credential, backend
// identifier, or public bearer token.
type EndpointEvidence struct {
	InternalEndpointReference string `json:"internal_endpoint_reference"`
	ConnectionGeneration      int64  `json:"connection_generation"`
}

func (e EndpointEvidence) validate() error {
	if !endpointPattern.MatchString(e.InternalEndpointReference) || e.ConnectionGeneration < 1 {
		return ErrInvalidHandoff
	}
	return nil
}

// Handoff is immutable provider-local terminal connection evidence. The
// transport layer may project it only after a successful open operation.
type Handoff struct {
	OperationID               string      `json:"operation_id"`
	AttemptID                 string      `json:"attempt_id"`
	FencingToken              int64       `json:"fencing_token"`
	SandboxID                 string      `json:"sandbox_id"`
	RuntimeSessionID          string      `json:"runtime_session_id"`
	RuntimeType               RuntimeType `json:"runtime_type"`
	CapabilityProfileID       string      `json:"capability_profile_id"`
	Protocol                  Protocol    `json:"protocol"`
	InternalEndpointReference string      `json:"internal_endpoint_reference"`
	ConnectionGeneration      int64       `json:"connection_generation"`
	ExpiresAt                 time.Time   `json:"expires_at"`
}

// AllocationReceipt is the durable, provider-neutral identity returned by the
// terminal runtime. It deliberately excludes backend container, process,
// socket, endpoint, and credential data. It is not a Contract-visible handoff.
type AllocationReceipt struct {
	Reference            string    `json:"reference"`
	SandboxID            string    `json:"sandbox_id"`
	RuntimeSessionID     string    `json:"runtime_session_id"`
	OperationID          string    `json:"operation_id"`
	AttemptID            string    `json:"attempt_id"`
	FencingToken         int64     `json:"fencing_token"`
	ExpectedGeneration   int64     `json:"expected_generation"`
	ConnectionGeneration int64     `json:"connection_generation"`
	AllocatedAt          time.Time `json:"allocated_at"`
	ExpiresAt            time.Time `json:"expires_at"`
}

func (r AllocationReceipt) Validate() error {
	if !allocationPattern.MatchString(r.Reference) {
		return ErrInvalidAllocation
	}
	for _, value := range []string{r.SandboxID, r.RuntimeSessionID, r.OperationID, r.AttemptID} {
		if !identifierPattern.MatchString(value) {
			return ErrInvalidAllocation
		}
	}
	if r.FencingToken < 1 || r.ExpectedGeneration < 1 || r.ConnectionGeneration < 1 ||
		r.AllocatedAt.IsZero() || r.ExpiresAt.IsZero() || !r.ExpiresAt.After(r.AllocatedAt) {
		return ErrInvalidAllocation
	}
	return nil
}

func (r AllocationReceipt) matchesRequest(request OpenRequest) bool {
	return r.SandboxID == request.SandboxID &&
		r.RuntimeSessionID == request.RuntimeSessionID &&
		r.OperationID == request.OperationID &&
		r.AttemptID == request.AttemptID &&
		r.FencingToken == request.FencingToken &&
		r.ExpectedGeneration == request.ExpectedGeneration &&
		r.ExpiresAt.Equal(request.ExpiresAt)
}

type AllocationState string

const (
	AllocationRunning        AllocationState = "running"
	AllocationAbsent         AllocationState = "absent"
	AllocationExpired        AllocationState = "expired"
	AllocationOutcomeUnknown AllocationState = "outcome_unknown"
)

func (s AllocationState) valid() bool {
	switch s {
	case AllocationRunning, AllocationAbsent, AllocationExpired, AllocationOutcomeUnknown:
		return true
	default:
		return false
	}
}

// AllocationEvidence stores the latest bounded observation for one immutable
// allocation receipt. The receipt remains unchanged across observations.
type AllocationEvidence struct {
	Receipt    AllocationReceipt `json:"receipt"`
	State      AllocationState   `json:"state"`
	ObservedAt time.Time         `json:"observed_at"`
}

func (e AllocationEvidence) Validate(request OpenRequest) error {
	if err := e.Receipt.Validate(); err != nil || !e.Receipt.matchesRequest(request) ||
		!e.State.valid() || e.ObservedAt.IsZero() || e.ObservedAt.Before(e.Receipt.AllocatedAt) {
		return ErrInvalidAllocation
	}
	return nil
}

func (e AllocationEvidence) Clone() AllocationEvidence { return e }

func (h Handoff) Validate() error {
	for _, value := range []string{h.OperationID, h.AttemptID, h.SandboxID, h.RuntimeSessionID, h.CapabilityProfileID} {
		if !identifierPattern.MatchString(value) {
			return ErrInvalidHandoff
		}
	}
	if h.FencingToken < 1 || h.RuntimeType != RuntimeTerminal || h.Protocol != ProtocolWebSocket || h.ExpiresAt.IsZero() {
		return ErrInvalidHandoff
	}
	return EndpointEvidence{InternalEndpointReference: h.InternalEndpointReference, ConnectionGeneration: h.ConnectionGeneration}.validate()
}

// Record is the immutable provider-local state of one open operation. A
// Handoff is present if and only if the operation succeeded.
type Record struct {
	Request    OpenRequest         `json:"request"`
	Status     Status              `json:"status"`
	AcceptedAt time.Time           `json:"accepted_at"`
	ObservedAt time.Time           `json:"observed_at"`
	Allocation *AllocationEvidence `json:"allocation,omitempty"`
	Handoff    *Handoff            `json:"handoff,omitempty"`
}

// SandboxAuthority is the provider-local, transactionally checked snapshot
// required before accepting or completing a terminal session. It is not a
// public Provider DTO and carries no backend or caller-owned implementation
// detail.
type SandboxAuthority struct {
	SandboxID           string    `json:"sandbox_id"`
	ProviderRevisionID  string    `json:"provider_revision_id"`
	Ready               bool      `json:"ready"`
	Generation          int64     `json:"generation"`
	LeaseExpiresAt      time.Time `json:"lease_expires_at"`
	FencingToken        int64     `json:"fencing_token"`
	CapabilityProfileID string    `json:"capability_profile_id"`
}

// Validate checks the structural bounds of a persisted authority snapshot.
// Lease freshness is checked transactionally against the operation request.
func (a SandboxAuthority) Validate() error {
	for name, value := range map[string]string{
		"sandbox_id":           a.SandboxID,
		"provider_revision_id": a.ProviderRevisionID,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%w: authority %s", ErrInvalidRecord, name)
		}
	}
	if a.Generation < 1 || a.FencingToken < 1 || a.LeaseExpiresAt.IsZero() {
		return fmt.Errorf("%w: authority bounds", ErrInvalidRecord)
	}
	if a.Ready && !identifierPattern.MatchString(a.CapabilityProfileID) {
		return fmt.Errorf("%w: authority capability profile", ErrInvalidRecord)
	}
	return nil
}

func (a SandboxAuthority) Clone() SandboxAuthority { return a }

type Reservation struct {
	Record   Record
	Replayed bool
}

func NewRecord(request OpenRequest, acceptedAt time.Time) (Record, error) {
	acceptedAt = acceptedAt.UTC()
	if err := request.Validate(acceptedAt); err != nil {
		return Record{}, err
	}
	return Record{
		Request:    request.Clone(),
		Status:     StatusAccepted,
		AcceptedAt: acceptedAt,
		ObservedAt: acceptedAt,
	}, nil
}

func (r Record) Clone() Record {
	clone := r
	clone.Request = r.Request.Clone()
	if r.Allocation != nil {
		allocation := r.Allocation.Clone()
		clone.Allocation = &allocation
	}
	if r.Handoff != nil {
		handoff := *r.Handoff
		clone.Handoff = &handoff
	}
	return clone
}

func (r Reservation) Clone() Reservation {
	r.Record = r.Record.Clone()
	return r
}

func (r Record) Validate() error {
	if r.AcceptedAt.IsZero() || r.ObservedAt.IsZero() || r.ObservedAt.Before(r.AcceptedAt) || !r.Status.valid() {
		return ErrInvalidRecord
	}
	if err := r.Request.Validate(r.AcceptedAt); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRecord, err)
	}
	if r.Allocation != nil {
		if err := r.Allocation.Validate(r.Request); err != nil || r.Allocation.ObservedAt.After(r.ObservedAt) {
			return ErrInvalidRecord
		}
	}
	if r.Status != StatusSucceeded {
		if r.Handoff != nil {
			return ErrInvalidRecord
		}
		return nil
	}
	if r.Handoff == nil || !r.ObservedAt.Before(r.Request.ExpiresAt) {
		return ErrInvalidRecord
	}
	if err := r.Handoff.Validate(); err != nil || !handoffMatchesRequest(*r.Handoff, r.Request) {
		return ErrInvalidRecord
	}
	return nil
}

// AttachAllocation binds a terminal receipt to an accepted operation and
// advances it to running. A replay with the exact receipt is immutable.
func AttachAllocation(record Record, receipt AllocationReceipt) (Record, error) {
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	if err := receipt.Validate(); err != nil || !receipt.matchesRequest(record.Request) ||
		receipt.AllocatedAt.Before(record.AcceptedAt) || !receipt.AllocatedAt.Before(record.Request.Deadline) {
		return Record{}, ErrInvalidAllocation
	}
	if record.Allocation != nil {
		if sameAllocationReceipt(record.Allocation.Receipt, receipt) {
			return record.Clone(), nil
		}
		return Record{}, ErrAllocationConflict
	}
	if record.Status != StatusAccepted {
		return Record{}, ErrTerminalOperation
	}
	updated, err := Transition(record, StatusRunning, receipt.AllocatedAt, nil)
	if err != nil {
		return Record{}, err
	}
	updated.Allocation = &AllocationEvidence{Receipt: receipt, State: AllocationRunning, ObservedAt: receipt.AllocatedAt.UTC()}
	if err := updated.Validate(); err != nil {
		return Record{}, err
	}
	return updated, nil
}

// ObserveAllocation records bounded runtime evidence without starting a
// replacement resource. Absent and expired observations are known failures;
// uncertain evidence is permanently outcome_unknown.
func ObserveAllocation(record Record, observation AllocationEvidence) (Record, error) {
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	if record.Allocation == nil || record.Status != StatusRunning {
		return Record{}, ErrTerminalOperation
	}
	if err := observation.Validate(record.Request); err != nil ||
		!sameAllocationReceipt(record.Allocation.Receipt, observation.Receipt) ||
		observation.ObservedAt.Before(record.Allocation.ObservedAt) {
		return Record{}, ErrAllocationConflict
	}
	updated := record.Clone()
	updated.Allocation = &observation
	updated.ObservedAt = observation.ObservedAt.UTC()
	switch observation.State {
	case AllocationRunning:
		updated.Status = StatusRunning
	case AllocationAbsent, AllocationExpired:
		updated.Status = StatusFailed
	case AllocationOutcomeUnknown:
		updated.Status = StatusOutcomeUnknown
	default:
		return Record{}, ErrInvalidAllocation
	}
	if err := updated.Validate(); err != nil {
		return Record{}, err
	}
	return updated, nil
}

func sameAllocationReceipt(left, right AllocationReceipt) bool {
	return left.Reference == right.Reference &&
		left.SandboxID == right.SandboxID &&
		left.RuntimeSessionID == right.RuntimeSessionID &&
		left.OperationID == right.OperationID &&
		left.AttemptID == right.AttemptID &&
		left.FencingToken == right.FencingToken &&
		left.ExpectedGeneration == right.ExpectedGeneration &&
		left.ConnectionGeneration == right.ConnectionGeneration &&
		left.AllocatedAt.Equal(right.AllocatedAt) &&
		left.ExpiresAt.Equal(right.ExpiresAt)
}

var transitions = map[Status]map[Status]bool{
	StatusAccepted: {
		StatusRunning: true, StatusFailed: true, StatusCancelled: true, StatusOutcomeUnknown: true,
	},
	StatusRunning: {
		StatusSucceeded: true, StatusFailed: true, StatusCancelled: true, StatusOutcomeUnknown: true,
	},
}

// Transition returns a new immutable snapshot. Only running operations may
// succeed and mint a handoff. Failed, cancelled, and outcome-unknown records
// are terminal and can never create or reopen one.
func Transition(record Record, next Status, observedAt time.Time, evidence *EndpointEvidence) (Record, error) {
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	if !next.valid() || observedAt.IsZero() || observedAt.Before(record.ObservedAt) {
		return Record{}, ErrInvalidTransition
	}
	if record.Status == next {
		if evidence != nil {
			return Record{}, ErrTerminalOperation
		}
		return record.Clone(), nil
	}
	if record.Status.terminal() {
		return Record{}, ErrTerminalOperation
	}
	if !transitions[record.Status][next] {
		return Record{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, record.Status, next)
	}
	if next == StatusRunning && !record.Request.Deadline.After(observedAt) {
		return Record{}, ErrDeadlineExpired
	}
	if next != StatusSucceeded && evidence != nil {
		return Record{}, ErrHandoffUnavailable
	}

	updated := record.Clone()
	updated.Status = next
	updated.ObservedAt = observedAt.UTC()
	if next != StatusSucceeded {
		updated.Handoff = nil
		return updated, nil
	}
	if evidence == nil || !observedAt.Before(record.Request.ExpiresAt) || !observedAt.Before(record.Request.Deadline) {
		return Record{}, ErrHandoffUnavailable
	}
	if err := evidence.validate(); err != nil {
		return Record{}, err
	}
	updated.Handoff = &Handoff{
		OperationID:               record.Request.OperationID,
		AttemptID:                 record.Request.AttemptID,
		FencingToken:              record.Request.FencingToken,
		SandboxID:                 record.Request.SandboxID,
		RuntimeSessionID:          record.Request.RuntimeSessionID,
		RuntimeType:               RuntimeTerminal,
		CapabilityProfileID:       record.Request.CapabilityProfileID,
		Protocol:                  ProtocolWebSocket,
		InternalEndpointReference: evidence.InternalEndpointReference,
		ConnectionGeneration:      evidence.ConnectionGeneration,
		ExpiresAt:                 record.Request.ExpiresAt.UTC(),
	}
	if err := updated.Validate(); err != nil {
		return Record{}, err
	}
	return updated, nil
}

func handoffMatchesRequest(handoff Handoff, request OpenRequest) bool {
	return handoff.OperationID == request.OperationID &&
		handoff.AttemptID == request.AttemptID &&
		handoff.FencingToken == request.FencingToken &&
		handoff.SandboxID == request.SandboxID &&
		handoff.RuntimeSessionID == request.RuntimeSessionID &&
		handoff.RuntimeType == request.RuntimeType &&
		handoff.CapabilityProfileID == request.CapabilityProfileID &&
		handoff.ExpiresAt.Equal(request.ExpiresAt)
}

func validBoundedString(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	count := utf8.RuneCountInString(value)
	return count >= minimum && count <= maximum
}
