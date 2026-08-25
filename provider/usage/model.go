// Package usage contains bounded provider-local usage evidence. It is not a
// billing ledger and does not own tenant or pricing truth.
package usage

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

const MaxEntries = 16

var (
	ErrInvalidEvidence     = errors.New("invalid Provider usage evidence")
	ErrEvidenceNotFound    = errors.New("Provider usage evidence not found")
	ErrEvidenceUnavailable = errors.New("Provider usage evidence is unavailable")
	ErrEvidenceExpired     = errors.New("Provider usage evidence has expired")
	identifierPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	referencePattern       = regexp.MustCompile(`^ref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,399}$`)
	digestPattern          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Meter string

const (
	MeterWallTime       Meter = "sandbox.wall_time_milliseconds"
	MeterCPU            Meter = "sandbox.cpu_nanoseconds"
	MeterMemory         Meter = "sandbox.memory_byte_milliseconds"
	MeterNetworkIngress Meter = "sandbox.network_ingress_bytes"
	MeterNetworkEgress  Meter = "sandbox.network_egress_bytes"
	MeterStorageRead    Meter = "sandbox.storage_read_bytes"
	MeterStorageWrite   Meter = "sandbox.storage_write_bytes"
	MeterWorkspacePeak  Meter = "sandbox.workspace_peak_bytes"
	MeterExecCount      Meter = "sandbox.exec_count"
)

type Source string

const (
	SourcePlatform   Source = "platform_metered"
	SourceRuntime    Source = "runtime_metered"
	SourceReconciled Source = "reconciled"
)

type ReconciliationStatus string

const (
	ReconciliationComplete ReconciliationStatus = "complete"
	ReconciliationPartial  ReconciliationStatus = "partial"
	ReconciliationUnknown  ReconciliationStatus = "unknown"
)

type Entry struct {
	EntryID           string
	SandboxID         string
	OperationID       string
	Meter             Meter
	Quantity          int64
	Unit              string
	MeterSource       Source
	EvidenceReference string
	OccurredAt        time.Time
}

func (e Entry) Validate() error {
	if !identifierPattern.MatchString(e.EntryID) || !identifierPattern.MatchString(e.SandboxID) || (e.OperationID != "" && !identifierPattern.MatchString(e.OperationID)) || e.Quantity < 0 || !referencePattern.MatchString(e.EvidenceReference) || e.OccurredAt.IsZero() {
		return ErrInvalidEvidence
	}
	if e.MeterSource != SourcePlatform && e.MeterSource != SourceRuntime && e.MeterSource != SourceReconciled {
		return ErrInvalidEvidence
	}
	wantUnit, ok := meterUnit(e.Meter)
	if !ok || e.Unit != wantUnit {
		return ErrInvalidEvidence
	}
	return nil
}

func meterUnit(meter Meter) (string, bool) {
	switch meter {
	case MeterWallTime:
		return "milliseconds", true
	case MeterCPU:
		return "nanoseconds", true
	case MeterMemory:
		return "byte-milliseconds", true
	case MeterNetworkIngress, MeterNetworkEgress, MeterStorageRead, MeterStorageWrite, MeterWorkspacePeak:
		return "bytes", true
	case MeterExecCount:
		return "count", true
	default:
		return "", false
	}
}

type Evidence struct {
	EvidenceID           string
	SandboxID            string
	OperationID          string
	AttemptID            string
	FencingToken         int64
	Entries              []Entry
	ReconciliationStatus ReconciliationStatus
	ObservedAt           time.Time
	RetainedUntil        time.Time
	EvidenceDigest       string
}

func (e Evidence) Validate(now time.Time) error {
	if !identifierPattern.MatchString(e.EvidenceID) || !identifierPattern.MatchString(e.SandboxID) || !identifierPattern.MatchString(e.OperationID) || !identifierPattern.MatchString(e.AttemptID) || e.FencingToken < 1 || len(e.Entries) == 0 || len(e.Entries) > MaxEntries || !digestPattern.MatchString(e.EvidenceDigest) || e.ObservedAt.IsZero() || e.RetainedUntil.IsZero() || !e.RetainedUntil.After(e.ObservedAt) {
		return ErrInvalidEvidence
	}
	if e.ReconciliationStatus != ReconciliationComplete && e.ReconciliationStatus != ReconciliationPartial && e.ReconciliationStatus != ReconciliationUnknown {
		return ErrInvalidEvidence
	}
	for _, entry := range e.Entries {
		if err := entry.Validate(); err != nil || entry.SandboxID != e.SandboxID || (entry.OperationID != "" && entry.OperationID != e.OperationID) {
			return fmt.Errorf("%w: entry correlation", ErrInvalidEvidence)
		}
	}
	if !now.Before(e.RetainedUntil) {
		return ErrEvidenceExpired
	}
	return nil
}

func (e Evidence) Clone() Evidence {
	e.Entries = append([]Entry(nil), e.Entries...)
	return e
}
