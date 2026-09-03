// Package repository provides adapter-independent state for browser handoff
// references.
package repository

import (
	"fmt"
	"sort"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

const snapshotVersion = 1

type State struct{ References map[string]reference.Record }
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
	if _, ok := s.References[record.Reference]; ok {
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
func (s *State) FindRunning(source browser.Record) (reference.Record, error) {
	s.ensureMap()
	if err := source.Validate(); err != nil || source.Status != browser.StatusRunning || source.Allocation == nil || source.Allocation.State != browser.AllocationRunning {
		return reference.Record{}, reference.ErrInvalidRecord
	}
	var found *reference.Record
	for _, record := range s.References {
		if record.OperationID != source.Request.OperationID {
			continue
		}
		if err := record.Validate(); err != nil || record.RevokedAt != nil || record.BrowserSessionID != source.Request.BrowserSessionID || record.AttemptID != source.Request.AttemptID || record.FencingToken != source.Request.FencingToken || record.SandboxID != source.Request.SandboxID || record.ProviderRevisionID != source.Request.ProviderRevisionID || record.ConnectionGeneration != source.Allocation.Receipt.ConnectionGeneration {
			return reference.Record{}, reference.ErrConflict
		}
		clone := record.Clone()
		if found != nil {
			return reference.Record{}, reference.ErrConflict
		}
		found = &clone
	}
	if found == nil {
		return reference.Record{}, reference.ErrNotFound
	}
	return found.Clone(), nil
}
func (s *State) Revoke(value string, revokedAt time.Time) error {
	s.ensureMap()
	record, ok := s.References[value]
	if !ok {
		return reference.ErrNotFound
	}
	if record.RevokedAt != nil {
		return nil
	}
	revokedAt = revokedAt.UTC()
	if revokedAt.IsZero() {
		return reference.ErrInvalidRecord
	}
	record.RevokedAt = &revokedAt
	if err := record.Validate(); err != nil {
		return err
	}
	s.References[value] = record.Clone()
	return nil
}
func (s State) Export() PersistedState {
	result := PersistedState{Version: snapshotVersion}
	for _, record := range s.References {
		result.References = append(result.References, record.Clone())
	}
	sort.Slice(result.References, func(i, j int) bool { return result.References[i].Reference < result.References[j].Reference })
	return result
}
func (s *State) Import(snapshot PersistedState) error {
	if snapshot.Version != snapshotVersion {
		return fmt.Errorf("%w: unsupported state version", reference.ErrUnavailable)
	}
	loaded := NewState()
	for _, record := range snapshot.References {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("%w: invalid reference", reference.ErrUnavailable)
		}
		if err := loaded.Create(record); err != nil {
			return fmt.Errorf("%w: duplicate reference", reference.ErrUnavailable)
		}
	}
	*s = loaded
	return nil
}
