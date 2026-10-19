// Package controlstorage implements the held Coding candidate's private file
// boundary. It grants no execution, cleanup, receipt or Profile authority.
package controlstorage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
)

const Protocol = "sandbox-runtime.control-storage-namespace.v1"

var (
	ErrInvalid   = errors.New("invalid private Control storage")
	ErrCapacity  = errors.New("private Control storage capacity exhausted")
	ErrUncertain = errors.New("private Control storage write uncertain; owner closed to writes")
	identifier   = regexp.MustCompile(`^[a-f0-9]{32}$`)
	hashPattern  = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

// Layout leaves other scopes UNALLOCATED and unavailable. It is not a complete
// Profile allocation, a physical filesystem quota or Browser/Desktop capacity.
type Layout struct {
	Protocol                    string                          `json:"protocol"`
	Coding                      codingidentity.ExecutionStorage `json:"coding"`
	OtherScopesUnallocatedBytes int64                           `json:"other_scopes_unallocated_bytes"`
}

func NewLayout() Layout {
	return Layout{Protocol: Protocol, Coding: codingidentity.NewExecutionStorage(), OtherScopesUnallocatedBytes: 512 << 20}
}

func (p Layout) Validate() error {
	if p != NewLayout() {
		return ErrInvalid
	}
	return nil
}

// Binding must come from a future frozen Profile. A syntactically valid digest
// here is NOT validation/admission of that Profile or its execution template.
// Namespace and StorageID require a fresh dedicated empty physical namespace;
// this library cannot identify a Docker volume from a host path alone.
type Binding struct {
	Layout                 Layout `json:"layout"`
	Namespace              string `json:"namespace"`
	StorageID              string `json:"storage_id"`
	ProfileDigest          string `json:"profile_digest"`
	TemplateDigest         string `json:"template_digest"`
	ControlPrincipalDigest string `json:"control_principal_digest"`
	UID                    uint32 `json:"uid"`
	GID                    uint32 `json:"gid"`
}

func (b Binding) Validate() error {
	if b.Layout.Validate() != nil || !identifier.MatchString(b.Namespace) || b.StorageID != "control-execution-"+b.Namespace ||
		!hashPattern.MatchString(b.ProfileDigest) || !hashPattern.MatchString(b.TemplateDigest) || !hashPattern.MatchString(b.ControlPrincipalDigest) {
		return ErrInvalid
	}
	return nil
}

type Class string

const (
	Output             Class = "output"
	AllocationEvidence Class = "allocation"
	ExecutionEvidence  Class = "execution"
	State              Class = "state"
	Closure            Class = "closure"
)

type limit struct {
	bytes, file int64
	objects     int
}

func (p Layout) limit(c Class) (limit, bool) {
	s := p.Coding
	switch c {
	case Output:
		return limit{s.OutputPeakBytes, s.PerStreamBytes, 4 * s.MaxExecutionRecords}, true
	case AllocationEvidence:
		return limit{int64(2*s.MaxAllocationRecords) * s.EvidenceDocumentBytes, s.EvidenceDocumentBytes, 2 * s.MaxAllocationRecords}, true
	case ExecutionEvidence:
		return limit{int64(s.MaxExecutionRecords) * s.EvidenceDocumentBytes, s.EvidenceDocumentBytes, s.MaxExecutionRecords}, true
	case State:
		return limit{2 * s.LedgerBytes, s.LedgerBytes, 2}, true
	case Closure:
		return limit{s.ClosureReserveBytes, s.EvidenceDocumentBytes, s.MaxExecutionRecords}, true
	default:
		return limit{}, false
	}
}

func sum(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func (b Binding) Digest() (string, error) {
	if b.Validate() != nil {
		return "", ErrInvalid
	}
	d, _ := json.Marshal(b)
	return sum(append([]byte(Protocol+"\x00"), d...)), nil
}

func rounded(n int64) int64 {
	u := codingidentity.NewExecutionStorage().AllocationUnitBytes
	return (n + u - 1) / u * u
}
