package desktop

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
)

var (
	allocationIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	allocationDigestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type AllocationRequest struct {
	SandboxID              string
	DesktopSessionID       string
	OperationID            string
	AttemptID              string
	FencingToken           int64
	ExpectedGeneration     int64
	RequestDigest          string
	NetworkPolicyReference string
	ExpiresAt              time.Time
}

func (r AllocationRequest) Validate(now time.Time) error {
	if now.IsZero() {
		return fmt.Errorf("%w: current time", ErrInvalidRequest)
	}
	for name, value := range map[string]string{
		"sandbox_id": r.SandboxID, "desktop_session_id": r.DesktopSessionID,
		"operation_id": r.OperationID, "attempt_id": r.AttemptID,
		"network_policy_reference": r.NetworkPolicyReference,
	} {
		if !allocationIdentifierPattern.MatchString(value) {
			return fmt.Errorf("%w: %s", ErrInvalidRequest, name)
		}
	}
	if r.FencingToken < 1 || r.ExpectedGeneration < 1 || !allocationDigestPattern.MatchString(r.RequestDigest) {
		return fmt.Errorf("%w: identity", ErrInvalidRequest)
	}
	if r.ExpiresAt.IsZero() || !r.ExpiresAt.After(now) {
		return fmt.Errorf("%w: expiry", ErrInvalidRequest)
	}
	return nil
}

type Allocation struct {
	Request     AllocationRequest
	AllocatedAt time.Time
}

func (a Allocation) Validate() error {
	if a.AllocatedAt.IsZero() {
		return ErrInvalidRequest
	}
	return a.Request.Validate(a.AllocatedAt)
}

type Allocator interface {
	Allocate(context.Context, Allocation) (AllocationReceipt, error)
}
type Observer interface {
	// Observe reconciles an immutable allocation identity without creating or
	// replacing a runtime resource.
	Observe(context.Context, Allocation) (AllocationObservation, error)
}
type Cleaner interface {
	Cleanup(context.Context, AllocationReceipt) error
}

// Attachment is the bounded Provider-private description returned by a fresh
// runtime attach. It deliberately carries no container identity, network
// coordinate, host path, socket path, credential, or public signaling data.
// Public media and input are composed by later Product/Gateway layers.
type Attachment struct {
	DesktopSessionID     string
	ConnectionGeneration int64
	MediaProfileID       string
	ControlProfileID     string
	DisplayReference     string
	Width                int
	Height               int
	Depth                int
	AudioOutput          bool
	PrivateInputModes    []string
	AttachedAt           time.Time
}

func (a Attachment) Validate(receipt AllocationReceipt) error {
	if err := receipt.Validate(); err != nil || a.DesktopSessionID != receipt.DesktopSessionID ||
		a.ConnectionGeneration != receipt.ConnectionGeneration || a.MediaProfileID != MediaProfileID ||
		a.ControlProfileID != ControlProfileID || a.DisplayReference != "ref:desktop-display:primary" ||
		a.Width != 1280 || a.Height != 720 || a.Depth != 24 || a.AudioOutput || a.AttachedAt.IsZero() ||
		a.AttachedAt.Before(receipt.AllocatedAt) || !a.AttachedAt.Before(receipt.ExpiresAt) ||
		len(a.PrivateInputModes) != 2 || a.PrivateInputModes[0] != "keyboard" || a.PrivateInputModes[1] != "pointer" {
		return ErrInvalidAllocation
	}
	return nil
}

func (a Attachment) Clone() Attachment {
	a.PrivateInputModes = append([]string(nil), a.PrivateInputModes...)
	return a
}

type Attacher interface {
	// Attach creates a fresh Provider-private observation after the caller has
	// revalidated the durable opaque handoff authority.
	Attach(context.Context, AllocationReceipt) (Attachment, error)
}

// MediaAuthority is the exact opaque authority for one Provider-private
// Desktop media/input session. It contains no backend coordinate.
type MediaAuthority struct {
	TenantBindingDigest    string
	ProviderRevisionID     string
	SandboxID              string
	DesktopSessionID       string
	HandoffReference       string
	HandoffReferenceDigest string
	AllocationReference    string
	ConnectionGeneration   int64
	ConnectionEpoch        string
	ControllerFence        string
	MediaProfileID         string
	ControlProfileID       string
	AuthorityDigest        string
	RequestDigest          string
	AuthorityExpiresAt     time.Time
	HandoffExpiresAt       time.Time
}

type MediaSession interface {
	ReadVideoRTP(context.Context) ([]byte, error)
	ReadAudioRTP(context.Context) ([]byte, error)
	HandleInput(context.Context, desktopmedia.Input) (desktopmedia.InputResult, error)
	UpdateStream(context.Context, desktopmedia.DisplayPolicy, string) error
	Resynchronize(context.Context) error
	RequestKeyframe(context.Context) error
	Close() error
}

// MediaRuntime is optional and deliberately separate from Runtime so drivers
// without a real broker session cannot claim Desktop media support.
type MediaRuntime interface {
	OpenMedia(context.Context, MediaAuthority, Attachment, desktopmedia.MediaPolicy) (MediaSession, error)
}

type Runtime interface {
	Allocator
	Observer
	Cleaner
}

type Authority interface {
	ReserveOpen(context.Context, OpenRequest, time.Time) (Reservation, error)
	GetOpen(context.Context, string) (Record, error)
	UpdateOpen(context.Context, Record, Status) error
}

type CoordinationAuthority interface {
	Authority
	SynchronizeSandboxAuthority(context.Context, SandboxAuthority) error
	GetSandboxAuthority(context.Context, string) (SandboxAuthority, error)
	AttachAllocation(context.Context, AllocationReceipt) (Reservation, error)
	ObserveAllocation(context.Context, string, AllocationEvidence) (Record, error)
	ListOpen(context.Context) ([]Record, error)
	ReserveClose(context.Context, CloseRequest, time.Time, bool) (CloseReservation, error)
	GetClose(context.Context, string) (CloseRecord, error)
	UpdateClose(context.Context, CloseRecord, Status, Record) error
	ResolveUnknownClose(context.Context, string, time.Time) (Record, error)
	ListClose(context.Context) ([]CloseRecord, error)
}

type AllocationObservation struct {
	Request    AllocationRequest
	Receipt    *AllocationReceipt
	State      AllocationState
	ObservedAt time.Time
}

func (o AllocationObservation) Validate(allocation Allocation) error {
	if err := allocation.Validate(); err != nil || o.Request != allocation.Request || o.ObservedAt.IsZero() ||
		o.ObservedAt.Before(allocation.AllocatedAt) || !o.State.valid() {
		return ErrInvalidAllocation
	}
	if o.State == AllocationRunning {
		if o.Receipt == nil || o.Receipt.Validate() != nil || !o.Receipt.Matches(allocation.Request) ||
			!o.Receipt.AllocatedAt.Equal(allocation.AllocatedAt) {
			return ErrInvalidAllocation
		}
	} else if o.Receipt != nil {
		return ErrInvalidAllocation
	}
	return nil
}

var ErrAllocationUnknown = errors.New("Provider desktop allocation outcome is unknown")
