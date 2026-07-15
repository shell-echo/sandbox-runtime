// Package instance defines runtime instances and their lifecycle independently
// of any concrete isolation backend.
package instance

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxNameLength       = 128
	DefaultMaxInstances = 1000
)

// WorkloadType identifies the kind of remote workload hosted by an instance.
type WorkloadType string

const (
	WorkloadShell WorkloadType = "shell"
)

// Validate reports whether the workload type is supported by the core model.
func (w WorkloadType) Validate() error {
	switch w {
	case WorkloadShell:
		return nil
	default:
		return fmt.Errorf("%w: unsupported workload %q", ErrInvalidSpec, w)
	}
}

// State is the lifecycle state of a runtime instance.
type State string

const (
	StateCreating State = "creating"
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateStopping State = "stopping"
	StateRemoving State = "removing"
	StateFailed   State = "failed"
)

// CanTransition reports whether moving from the current state to next is a
// valid lifecycle transition.
func (s State) CanTransition(next State) bool {
	switch s {
	case StateCreating:
		return next == StateStopped || next == StateFailed
	case StateStopped:
		return next == StateStarting || next == StateRemoving
	case StateStarting:
		return next == StateRunning || next == StateStopped || next == StateFailed
	case StateRunning:
		return next == StateStopping || next == StateFailed
	case StateStopping:
		return next == StateStopped || next == StateRunning || next == StateFailed
	case StateFailed:
		return next == StateRemoving
	default:
		return false
	}
}

// Instance is a runtime environment managed by a Driver.
type Instance struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Workload  WorkloadType `json:"workload"`
	State     State        `json:"state"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// Spec contains the backend-independent inputs used to create an instance.
type Spec struct {
	Name     string       `json:"name"`
	Workload WorkloadType `json:"workload"`
}

// Validate checks the backend-independent instance creation rules.
func (s Spec) Validate() error {
	trimmed := strings.TrimSpace(s.Name)
	if trimmed == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidSpec)
	}
	if trimmed != s.Name {
		return fmt.Errorf("%w: name must not have surrounding whitespace", ErrInvalidSpec)
	}
	if utf8.RuneCountInString(s.Name) > MaxNameLength {
		return fmt.Errorf("%w: name must not exceed %d characters", ErrInvalidSpec, MaxNameLength)
	}
	if err := s.Workload.Validate(); err != nil {
		return err
	}
	return nil
}

var (
	ErrInvalidSpec       = errors.New("invalid instance spec")
	ErrNotFound          = errors.New("instance not found")
	ErrAlreadyExists     = errors.New("instance already exists")
	ErrInvalidTransition = errors.New("invalid instance state transition")
	ErrLimitExceeded     = errors.New("instance limit exceeded")
	ErrInvalidRuntime    = errors.New("invalid runtime state")
)
