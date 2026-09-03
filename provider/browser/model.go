// Package browser contains the backend-neutral Provider-local browser session
// domain. It deliberately does not import transport DTOs, terminal-session
// types, lifecycle repositories, or runtime-driver implementations.
package browser

import (
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

const MaxIdempotencyKeyRunes = 200

var (
	ErrInvalidRequest           = errors.New("invalid Provider browser session request")
	ErrDeadlineExpired          = errors.New("Provider browser session deadline has expired")
	ErrInvalidExpiry            = errors.New("invalid Provider browser session expiry")
	ErrInvalidRecord            = errors.New("invalid Provider browser session record")
	ErrInvalidHandoff           = errors.New("invalid Provider browser session handoff")
	ErrInvalidAllocation        = errors.New("invalid Provider browser session allocation evidence")
	ErrAllocationConflict       = errors.New("Provider browser session allocation evidence conflict")
	ErrInvalidTransition        = errors.New("invalid Provider browser session transition")
	ErrOperationTerminal        = errors.New("Provider browser session operation is terminal")
	ErrHandoffUnavailable       = errors.New("Provider browser session handoff is unavailable")
	ErrHandoffExpired           = errors.New("Provider browser session handoff has expired")
	ErrSandboxNotReady          = errors.New("Provider browser session sandbox is not ready")
	ErrProviderRevisionConflict = errors.New("Provider browser session provider revision conflict")
	ErrGenerationConflict       = errors.New("Provider browser session sandbox generation conflict")
	ErrLeaseExpired             = errors.New("Provider browser session sandbox lease has expired")
	ErrStaleFencingToken        = errors.New("Provider browser session fencing token is stale")
	ErrCapabilityUnsupported    = errors.New("Provider browser session capability profile is unsupported")

	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	endpointPattern   = regexp.MustCompile(`^ref:browser-session:[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)
	allocationPattern = regexp.MustCompile(`^ref:browser/[0-9a-f]{32}$`)
)

const CapabilityProfileID = "browser-v1"

type Protocol string

const ProtocolWebSocket Protocol = "websocket"

// OpenRequest is the provider-local projection of a browser session request.
// SandboxID and ProviderRevisionID are supplied by admitted path/token context.
type OpenRequest struct {
	SandboxID           string    `json:"sandbox_id"`
	ProviderRevisionID  string    `json:"provider_revision_id"`
	OperationID         string    `json:"operation_id"`
	AttemptID           string    `json:"attempt_id"`
	FencingToken        int64     `json:"fencing_token"`
	IdempotencyKey      string    `json:"idempotency_key"`
	RequestDigest       string    `json:"request_digest"`
	Deadline            time.Time `json:"deadline"`
	ExpectedGeneration  int64     `json:"expected_generation"`
	BrowserSessionID    string    `json:"browser_session_id"`
	CapabilityProfileID string    `json:"capability_profile_id"`
	ExpiresAt           time.Time `json:"expires_at"`
}

func (r OpenRequest) Clone() OpenRequest { return r }

func (r OpenRequest) Validate(now time.Time) error {
	if now.IsZero() {
		return fmt.Errorf("%w: current time", ErrInvalidRequest)
	}
	for name, value := range map[string]string{
		"sandbox_id": r.SandboxID, "provider_revision_id": r.ProviderRevisionID,
		"operation_id": r.OperationID, "attempt_id": r.AttemptID,
		"browser_session_id": r.BrowserSessionID,
	} {
		if !identifierPattern.MatchString(value) {
			return fmt.Errorf("%w: %s", ErrInvalidRequest, name)
		}
	}
	if r.CapabilityProfileID != CapabilityProfileID {
		return fmt.Errorf("%w: capability profile", ErrInvalidRequest)
	}
	if !validBoundedString(r.IdempotencyKey, 1, MaxIdempotencyKeyRunes) {
		return fmt.Errorf("%w: idempotency_key", ErrInvalidRequest)
	}
	if r.FencingToken < 1 || r.ExpectedGeneration < 1 {
		return fmt.Errorf("%w: fencing token and expected generation", ErrInvalidRequest)
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
	if !r.Deadline.After(now) {
		return ErrDeadlineExpired
	}
	if !r.ExpiresAt.After(now) || r.ExpiresAt.After(r.Deadline) {
		return ErrInvalidExpiry
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

type Handoff struct {
	OperationID               string    `json:"operation_id"`
	AttemptID                 string    `json:"attempt_id"`
	FencingToken              int64     `json:"fencing_token"`
	SandboxID                 string    `json:"sandbox_id"`
	BrowserSessionID          string    `json:"browser_session_id"`
	CapabilityProfileID       string    `json:"capability_profile_id"`
	Protocol                  Protocol  `json:"protocol"`
	InternalEndpointReference string    `json:"internal_endpoint_reference"`
	ConnectionGeneration      int64     `json:"connection_generation"`
	ExpiresAt                 time.Time `json:"expires_at"`
}

type AllocationReceipt struct {
	Reference            string    `json:"reference"`
	SandboxID            string    `json:"sandbox_id"`
	BrowserSessionID     string    `json:"browser_session_id"`
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
	for _, value := range []string{r.SandboxID, r.BrowserSessionID, r.OperationID, r.AttemptID} {
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
	return r.SandboxID == request.SandboxID && r.BrowserSessionID == request.BrowserSessionID &&
		r.OperationID == request.OperationID && r.AttemptID == request.AttemptID &&
		r.FencingToken == request.FencingToken && r.ExpectedGeneration == request.ExpectedGeneration &&
		r.ExpiresAt.Equal(request.ExpiresAt)
}

// Matches binds a runtime receipt to the exact immutable allocation identity.
func (r AllocationReceipt) Matches(request AllocationRequest) bool {
	return r.SandboxID == request.SandboxID && r.BrowserSessionID == request.BrowserSessionID &&
		r.OperationID == request.OperationID && r.AttemptID == request.AttemptID &&
		r.FencingToken == request.FencingToken && r.ExpectedGeneration == request.ExpectedGeneration &&
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
	for _, value := range []string{h.OperationID, h.AttemptID, h.SandboxID, h.BrowserSessionID} {
		if !identifierPattern.MatchString(value) {
			return ErrInvalidHandoff
		}
	}
	if h.FencingToken < 1 || h.CapabilityProfileID != CapabilityProfileID || h.Protocol != ProtocolWebSocket || h.ExpiresAt.IsZero() {
		return ErrInvalidHandoff
	}
	return EndpointEvidence{InternalEndpointReference: h.InternalEndpointReference, ConnectionGeneration: h.ConnectionGeneration}.validate()
}

type Record struct {
	Request         OpenRequest         `json:"request"`
	Status          Status              `json:"status"`
	AcceptedAt      time.Time           `json:"accepted_at"`
	ObservedAt      time.Time           `json:"observed_at"`
	CancelRequested bool                `json:"cancel_requested"`
	Allocation      *AllocationEvidence `json:"allocation,omitempty"`
	Handoff         *Handoff            `json:"handoff,omitempty"`
}

type SandboxAuthority struct {
	SandboxID           string    `json:"sandbox_id"`
	ProviderRevisionID  string    `json:"provider_revision_id"`
	Ready               bool      `json:"ready"`
	Generation          int64     `json:"generation"`
	LeaseExpiresAt      time.Time `json:"lease_expires_at"`
	FencingToken        int64     `json:"fencing_token"`
	CapabilityProfileID string    `json:"capability_profile_id"`
}

func (a SandboxAuthority) Validate() error {
	if !identifierPattern.MatchString(a.SandboxID) || !identifierPattern.MatchString(a.ProviderRevisionID) ||
		a.Generation < 1 || a.FencingToken < 1 || a.LeaseExpiresAt.IsZero() || a.CapabilityProfileID != CapabilityProfileID {
		return fmt.Errorf("%w: sandbox authority", ErrInvalidRecord)
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
	return Record{Request: request.Clone(), Status: StatusAccepted, AcceptedAt: acceptedAt, ObservedAt: acceptedAt}, nil
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

func (r Reservation) Clone() Reservation { r.Record = r.Record.Clone(); return r }

func (r Record) Validate() error {
	if r.AcceptedAt.IsZero() || r.ObservedAt.IsZero() || r.ObservedAt.Before(r.AcceptedAt) || !r.Status.valid() {
		return ErrInvalidRecord
	}
	if err := r.Request.Validate(r.AcceptedAt); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRecord, err)
	}
	if r.Status == StatusCancelled && !r.CancelRequested {
		return ErrInvalidRecord
	}
	if r.Status == StatusAccepted && r.Allocation != nil {
		return ErrInvalidRecord
	}
	if r.Status == StatusRunning || r.Status == StatusSucceeded {
		if r.Allocation == nil || r.Allocation.State != AllocationRunning {
			return ErrInvalidRecord
		}
	}
	if r.Status == StatusSucceeded && r.CancelRequested {
		return ErrInvalidRecord
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
	if err := r.Handoff.Validate(); err != nil || !handoffMatchesRequest(*r.Handoff, r.Request) ||
		r.Handoff.ConnectionGeneration != r.Allocation.Receipt.ConnectionGeneration {
		return ErrInvalidRecord
	}
	return nil
}

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
		return Record{}, ErrOperationTerminal
	}
	updated := record.Clone()
	updated.Status = StatusRunning
	updated.ObservedAt = receipt.AllocatedAt.UTC()
	updated.Allocation = &AllocationEvidence{Receipt: receipt, State: AllocationRunning, ObservedAt: receipt.AllocatedAt.UTC()}
	if err := updated.Validate(); err != nil {
		return Record{}, err
	}
	return updated, nil
}

func ObserveAllocation(record Record, observation AllocationEvidence) (Record, error) {
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	if record.Allocation == nil || record.Status != StatusRunning {
		return Record{}, ErrOperationTerminal
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
	}
	if err := updated.Validate(); err != nil {
		return Record{}, err
	}
	return updated, nil
}

var transitions = map[Status]map[Status]bool{
	StatusAccepted: {StatusFailed: true, StatusCancelled: true, StatusOutcomeUnknown: true},
	StatusRunning:  {StatusSucceeded: true, StatusFailed: true, StatusCancelled: true, StatusOutcomeUnknown: true},
}

// RequestCancellation durably records intent without claiming the runtime has
// stopped. A coordinator must confirm cleanup before transitioning to
// cancelled, or record outcome_unknown when cleanup may have taken effect.
func RequestCancellation(record Record, observedAt time.Time) (Record, error) {
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	if record.Status.terminal() {
		return Record{}, ErrOperationTerminal
	}
	if observedAt.IsZero() || observedAt.Before(record.ObservedAt) {
		return Record{}, ErrInvalidTransition
	}
	if record.CancelRequested {
		return record.Clone(), nil
	}
	updated := record.Clone()
	updated.CancelRequested = true
	updated.ObservedAt = observedAt.UTC()
	if err := updated.Validate(); err != nil {
		return Record{}, err
	}
	return updated, nil
}

func Transition(record Record, next Status, observedAt time.Time, evidence *EndpointEvidence) (Record, error) {
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	if !next.valid() || observedAt.IsZero() || observedAt.Before(record.ObservedAt) {
		return Record{}, ErrInvalidTransition
	}
	if record.Status == next {
		if evidence != nil {
			return Record{}, ErrOperationTerminal
		}
		return record.Clone(), nil
	}
	if record.Status.terminal() {
		return Record{}, ErrOperationTerminal
	}
	if !transitions[record.Status][next] {
		return Record{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, record.Status, next)
	}
	if next == StatusCancelled && !record.CancelRequested {
		return Record{}, ErrInvalidTransition
	}
	if next == StatusSucceeded && record.CancelRequested {
		return Record{}, ErrInvalidTransition
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
		OperationID: record.Request.OperationID, AttemptID: record.Request.AttemptID,
		FencingToken: record.Request.FencingToken, SandboxID: record.Request.SandboxID,
		BrowserSessionID: record.Request.BrowserSessionID, CapabilityProfileID: CapabilityProfileID,
		Protocol: ProtocolWebSocket, InternalEndpointReference: evidence.InternalEndpointReference,
		ConnectionGeneration: evidence.ConnectionGeneration, ExpiresAt: record.Request.ExpiresAt.UTC(),
	}
	if err := updated.Validate(); err != nil {
		return Record{}, err
	}
	return updated, nil
}

func handoffMatchesRequest(handoff Handoff, request OpenRequest) bool {
	return handoff.OperationID == request.OperationID && handoff.AttemptID == request.AttemptID &&
		handoff.FencingToken == request.FencingToken && handoff.SandboxID == request.SandboxID &&
		handoff.BrowserSessionID == request.BrowserSessionID && handoff.CapabilityProfileID == request.CapabilityProfileID &&
		handoff.ExpiresAt.Equal(request.ExpiresAt)
}

func sameAllocationReceipt(left, right AllocationReceipt) bool {
	return left.Reference == right.Reference && left.SandboxID == right.SandboxID &&
		left.BrowserSessionID == right.BrowserSessionID && left.OperationID == right.OperationID &&
		left.AttemptID == right.AttemptID && left.FencingToken == right.FencingToken &&
		left.ExpectedGeneration == right.ExpectedGeneration && left.ConnectionGeneration == right.ConnectionGeneration &&
		left.AllocatedAt.Equal(right.AllocatedAt) && left.ExpiresAt.Equal(right.ExpiresAt)
}

func validBoundedString(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	count := utf8.RuneCountInString(value)
	return count >= minimum && count <= maximum
}
