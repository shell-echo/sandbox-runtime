package product

import (
	"errors"
	"regexp"
	"time"
	"unicode/utf8"
)

const (
	PrimarySlotKey = "primary-code"

	CreateWorkspaceMethod = "POST"
	CreateWorkspacePath   = "/api/v1/workspaces"
)

var (
	ErrInvalid               = errors.New("invalid product request")
	ErrCapabilityUnsupported = errors.New("product capability is unsupported")
	ErrIdempotencyConflict   = errors.New("product idempotency conflict")
	ErrStoreUnavailable      = errors.New("product store is unavailable")
	ErrStoreOutcomeUnknown   = errors.New("product store outcome is unknown")
	ErrNotFound              = errors.New("product resource not found")
	ErrForbidden             = errors.New("product action is forbidden")

	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	versionPattern    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

type ActorType string

const (
	ActorHuman   ActorType = "human"
	ActorAgent   ActorType = "agent"
	ActorService ActorType = "service"
)

type ActorRef struct {
	Type ActorType
	ID   string
}

func (a ActorRef) Validate() error {
	if a.Type != ActorHuman && a.Type != ActorAgent && a.Type != ActorService {
		return ErrInvalid
	}
	if !validIdentifier(a.ID) {
		return ErrInvalid
	}
	return nil
}

type CapabilityRequirement struct {
	CapabilityID string `json:"capability_id"`
	Version      string `json:"version"`
	ProfileID    string `json:"profile_id"`
}

func (r CapabilityRequirement) validate() error {
	if !validIdentifier(r.CapabilityID) || !versionPattern.MatchString(r.Version) ||
		len(r.Version) > 32 || !validIdentifier(r.ProfileID) {
		return ErrInvalid
	}
	return nil
}

type SlotSpec struct {
	SlotKey              string                  `json:"slot_key"`
	Kind                 string                  `json:"kind"`
	ProfileID            string                  `json:"profile_id"`
	RequiredCapabilities []CapabilityRequirement `json:"required_capabilities"`
	DesiredState         string                  `json:"desired_state"`
}

func (s SlotSpec) validatePrimary() error {
	if s.SlotKey != PrimarySlotKey || s.Kind != "code" || s.DesiredState != "ready" ||
		!validIdentifier(s.ProfileID) || len(s.RequiredCapabilities) < 1 || len(s.RequiredCapabilities) > 32 {
		return ErrInvalid
	}
	for _, capability := range s.RequiredCapabilities {
		if err := capability.validate(); err != nil {
			return err
		}
	}
	return nil
}

type CreateWorkspaceRequest struct {
	DisplayName     string
	LifetimeSeconds int64
	PrimarySlot     SlotSpec
}

func (r CreateWorkspaceRequest) validate() error {
	if !utf8.ValidString(r.DisplayName) || utf8.RuneCountInString(r.DisplayName) < 1 ||
		utf8.RuneCountInString(r.DisplayName) > 128 || r.LifetimeSeconds < 60 ||
		r.LifetimeSeconds > 604800 {
		return ErrInvalid
	}
	return r.PrimarySlot.validatePrimary()
}

type Operation struct {
	ID                   string
	Type                 string
	WorkspaceID          string
	SubmittedBy          ActorRef
	State                string
	ReconciliationStatus string
	Version              int64
	AcceptedAt           time.Time
	UpdatedAt            time.Time
}

type WorkspaceSlot struct {
	SlotKey              string
	Kind                 string
	ProfileID            string
	RequiredCapabilities []CapabilityRequirement
	DesiredState         string
	ObservedState        string
	Generation           int64
	ObservedGeneration   int64
	Version              int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type Workspace struct {
	ID             string
	TenantID       string
	Owner          ActorRef
	DisplayName    string
	PrimarySlotKey string
	DesiredState   string
	ObservedState  string
	Version        int64
	LeaseExpiresAt time.Time
	Slots          []WorkspaceSlot
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type CreateWorkspaceResult struct {
	Operation Operation
	Replay    bool
}

func validIdentifier(value string) bool {
	return utf8.ValidString(value) && identifierPattern.MatchString(value)
}
