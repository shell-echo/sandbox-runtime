// Package migration contains provider-independent migration readiness
// primitives. It binds runs to immutable ProviderRevisions without owning
// caller WorkOrder, Artifact, event, usage, or Gateway truth.
package migration

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
)

var (
	ErrInvalidRevision = errors.New("invalid ProviderRevision")
	ErrInvalidRun      = errors.New("invalid migration run identity")
	ErrInvalidPolicy   = errors.New("invalid migration canary policy")
	ErrRunNotFound     = errors.New("migration run binding not found")
	ErrRunConflict     = errors.New("migration run binding conflict")
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Revision is the immutable identity selected for a run. Capability and
// security fields are included so a canary cannot silently change profile.
type Revision struct {
	ID                   string
	CapabilityProfileID  string
	RuntimeProfileID     string
	ContractNamespace    string
	ContractVersion      string
	ImageDigest          string
	SecurityPolicyDigest string
}

func (r Revision) Validate() error {
	for name, value := range map[string]string{
		"id": r.ID, "capability_profile_id": r.CapabilityProfileID, "runtime_profile_id": r.RuntimeProfileID,
		"contract_namespace": r.ContractNamespace, "contract_version": r.ContractVersion,
	} {
		if !identifierPattern.MatchString(value) && name != "contract_namespace" {
			return fmt.Errorf("%w: %s", ErrInvalidRevision, name)
		}
		if name == "contract_namespace" && (value == "" || len(value) > 200) {
			return fmt.Errorf("%w: %s", ErrInvalidRevision, name)
		}
	}
	if !digestPattern.MatchString(r.ImageDigest) || !digestPattern.MatchString(r.SecurityPolicyDigest) {
		return fmt.Errorf("%w: revision digest", ErrInvalidRevision)
	}
	return nil
}

type RunState string

const (
	RunActive    RunState = "active"
	RunDraining  RunState = "draining"
	RunCompleted RunState = "completed"
)

type Binding struct {
	RunID            string
	ProviderRevision Revision
	State            RunState
	BoundAt          time.Time
	StateChangedAt   time.Time
}

func (b Binding) Validate(now time.Time) error {
	if !identifierPattern.MatchString(b.RunID) || b.State == "" || b.BoundAt.IsZero() || b.StateChangedAt.IsZero() || b.StateChangedAt.Before(b.BoundAt) {
		return ErrInvalidRun
	}
	if b.State != RunActive && b.State != RunDraining && b.State != RunCompleted {
		return ErrInvalidRun
	}
	if err := b.ProviderRevision.Validate(); err != nil {
		return err
	}
	if now.IsZero() {
		return ErrInvalidRun
	}
	return nil
}

type Policy struct {
	Stable        Revision
	Canary        *Revision
	CanaryPercent uint8
}

func (p Policy) Validate() error {
	if err := p.Stable.Validate(); err != nil {
		return err
	}
	if p.CanaryPercent > 100 {
		return ErrInvalidPolicy
	}
	if p.Canary == nil {
		if p.CanaryPercent != 0 {
			return ErrInvalidPolicy
		}
		return nil
	}
	if err := p.Canary.Validate(); err != nil || p.Canary.ID == p.Stable.ID || p.Canary.CapabilityProfileID != p.Stable.CapabilityProfileID || p.Canary.RuntimeProfileID != p.Stable.RuntimeProfileID || p.Canary.ContractNamespace != p.Stable.ContractNamespace || p.Canary.ContractVersion != p.Stable.ContractVersion {
		return ErrInvalidPolicy
	}
	return nil
}

type Router struct {
	mu       sync.RWMutex
	clock    func() time.Time
	policy   Policy
	bindings map[string]Binding
}

func NewRouter(policy Policy, now func() time.Time) (*Router, error) {
	if err := policy.Validate(); err != nil || now == nil {
		return nil, ErrInvalidPolicy
	}
	return &Router{clock: now, policy: policy, bindings: make(map[string]Binding)}, nil
}

// Bind returns the original revision for an existing run. Canary selection is
// deterministic for new runs so retries cannot move a run across revisions.
func (r *Router) Bind(runID string) (Binding, error) {
	if r == nil || !identifierPattern.MatchString(runID) {
		return Binding{}, ErrInvalidRun
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock().UTC()
	if previous, ok := r.bindings[runID]; ok {
		return previous, nil
	}
	revision := r.policy.Stable
	if r.policy.Canary != nil && canaryBucket(runID) < r.policy.CanaryPercent {
		revision = *r.policy.Canary
	}
	binding := Binding{RunID: runID, ProviderRevision: revision, State: RunActive, BoundAt: now, StateChangedAt: now}
	r.bindings[runID] = binding
	return binding, nil
}

// Rollback changes only the revision selected for future bindings. Existing
// runs keep their immutable identity and may be marked draining separately.
func (r *Router) Rollback(stable Revision) error {
	if r == nil || stable.Validate() != nil {
		return ErrInvalidPolicy
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if stable.CapabilityProfileID != r.policy.Stable.CapabilityProfileID || stable.RuntimeProfileID != r.policy.Stable.RuntimeProfileID || stable.ContractNamespace != r.policy.Stable.ContractNamespace || stable.ContractVersion != r.policy.Stable.ContractVersion {
		return ErrInvalidPolicy
	}
	r.policy.Stable = stable
	r.policy.Canary = nil
	r.policy.CanaryPercent = 0
	return nil
}

func (r *Router) SetState(runID string, state RunState) error {
	if r == nil || !identifierPattern.MatchString(runID) {
		return ErrInvalidRun
	}
	if state != RunDraining && state != RunCompleted && state != RunActive {
		return ErrInvalidRun
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	binding, ok := r.bindings[runID]
	if !ok {
		return ErrRunNotFound
	}
	if binding.State == RunCompleted && state != RunCompleted {
		return ErrRunConflict
	}
	binding.State = state
	binding.StateChangedAt = r.clock().UTC()
	r.bindings[runID] = binding
	return nil
}

func (r *Router) Get(runID string) (Binding, error) {
	if r == nil || !identifierPattern.MatchString(runID) {
		return Binding{}, ErrInvalidRun
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	binding, ok := r.bindings[runID]
	if !ok {
		return Binding{}, ErrRunNotFound
	}
	return binding, nil
}

func canaryBucket(runID string) uint8 {
	sum := sha256.Sum256([]byte(runID))
	return sum[0] % 100
}
