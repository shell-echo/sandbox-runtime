// Package repository provides adapter-independent durable state for opaque
// terminal handoff references.
package repository

import (
	"fmt"
	"sort"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session/reference"
)

const snapshotVersion = 1

type State struct {
	References map[string]reference.Record
}

type PersistedState struct {
	Version    int                `json:"version"`
	References []reference.Record `json:"references"`
}

func NewState() State { return State{References: make(map[string]reference.Record)} }

func (s *State) ensureMap() {
	if s.References == nil {
		s.References = make(map[string]reference.Record)
	}
}

func (s *State) Create(record reference.Record) error {
	s.ensureMap()
	if err := record.Validate(); err != nil {
		return err
	}
	if _, exists := s.References[record.Reference]; exists {
		return reference.ErrAlreadyExists
	}
	s.References[record.Reference] = record.Clone()
	return nil
}

func (s *State) Get(value string) (reference.Record, error) {
	s.ensureMap()
	record, ok := s.References[value]
	if !ok {
		return reference.Record{}, fmt.Errorf("%w: %s", reference.ErrNotFound, value)
	}
	if err := record.Validate(); err != nil {
		return reference.Record{}, fmt.Errorf("%w: %v", reference.ErrUnavailable, err)
	}
	return record.Clone(), nil
}

// Revoke marks a record durably unavailable instead of deleting it. Keeping a
// tombstone makes an in-flight resolver fail closed after it rechecks at Dial.
func (s *State) Revoke(value string, revokedAt time.Time) error {
	s.ensureMap()
	revokedAt = revokedAt.UTC()
	if revokedAt.IsZero() {
		return reference.ErrInvalidRecord
	}
	record, ok := s.References[value]
	if !ok {
		return fmt.Errorf("%w: %s", reference.ErrNotFound, value)
	}
	if record.RevokedAt != nil {
		return nil
	}
	record.RevokedAt = &revokedAt
	if err := record.Validate(); err != nil {
		return err
	}
	s.References[value] = record.Clone()
	return nil
}

func (s State) Export() PersistedState {
	result := PersistedState{Version: snapshotVersion, References: make([]reference.Record, 0, len(s.References))}
	for _, record := range s.References {
		result.References = append(result.References, record.Clone())
	}
	sort.Slice(result.References, func(i, j int) bool { return result.References[i].Reference < result.References[j].Reference })
	return result
}

func (s *State) Import(snapshot PersistedState) error {
	if snapshot.Version != snapshotVersion {
		return fmt.Errorf("%w: unsupported state version %d", reference.ErrUnavailable, snapshot.Version)
	}
	loaded := NewState()
	for _, record := range snapshot.References {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("%w: %v", reference.ErrUnavailable, err)
		}
		if _, exists := loaded.References[record.Reference]; exists {
			return fmt.Errorf("%w: duplicate reference %q", reference.ErrUnavailable, record.Reference)
		}
		loaded.References[record.Reference] = record.Clone()
	}
	*s = loaded
	return nil
}
