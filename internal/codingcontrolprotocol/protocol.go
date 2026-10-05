// Package codingcontrolprotocol defines a repository-private, closed message
// envelope. It is not the Provider Contract and does not itself authenticate
// a peer, open Docker, or construct trusted PG evidence. Production callers
// must bind it to the frozen Profile-v2 mTLS/CRL edge and current PG state.
package codingcontrolprotocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
)

const (
	ProtocolID      = "sandbox-runtime.coding-control-wire.v1"
	ScopeCoding     = "coding"
	ActionCreate    = "create"
	ActionCleanup   = "cleanup"
	ActionStatus    = "status"
	StatusNotFound  = "not_found"
	StatusUnknown   = "unknown"
	StatusCompleted = "completed"
	// CleanupPending means the original create is Completed and the exact
	// cleanup intent is durable, but physical absence is not confirmed.
	StatusCleanupPending = "cleanup_pending"
	StatusReleased       = "released"
	MaxRequestBytes      = 10 << 10
	MaxResponseBytes     = 4 << 10
)

var (
	ErrInvalidWire = errors.New("invalid private Coding control wire")
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Request contains only Provider-issued typed authorities. A status request
// uses the same original effect/authority key and may include the original
// cleanup authority to bind a Released readback. Expired historical
// authorities are valid for read-only status, never physical dispatch.
type Request struct {
	Protocol string                                `json:"protocol"`
	Scope    string                                `json:"scope"`
	Action   string                                `json:"action"`
	Create   dockercontrol.CodingCreateAuthority   `json:"create"`
	Cleanup  *dockercontrol.CodingCleanupAuthority `json:"cleanup,omitempty"`
}

func (r Request) Validate(now time.Time, authenticatedPeerDigest string) error {
	if r.Protocol != ProtocolID || r.Scope != ScopeCoding || now.IsZero() ||
		!digestPattern.MatchString(authenticatedPeerDigest) ||
		r.Create.PeerPrincipalDigest != authenticatedPeerDigest ||
		r.Create.IssuedAt.After(now) ||
		r.Create.Validate(r.Create.IssuedAt) != nil {
		return ErrInvalidWire
	}
	switch r.Action {
	case ActionCreate:
		if r.Cleanup != nil || r.Create.Validate(now) != nil {
			return ErrInvalidWire
		}
	case ActionCleanup:
		if r.Cleanup == nil || r.Cleanup.IssuedAt.Before(r.Create.IssuedAt) ||
			r.Cleanup.Validate(now) != nil ||
			!cleanupMatchesCreate(*r.Cleanup, r.Create) {
			return ErrInvalidWire
		}
	case ActionStatus:
		if r.Cleanup != nil &&
			(r.Cleanup.IssuedAt.After(now) || r.Cleanup.IssuedAt.Before(r.Create.IssuedAt) ||
				r.Cleanup.Validate(r.Cleanup.IssuedAt) != nil ||
				!cleanupMatchesCreate(*r.Cleanup, r.Create)) {
			return ErrInvalidWire
		}
	default:
		return ErrInvalidWire
	}
	return nil
}

func cleanupMatchesCreate(cleanup dockercontrol.CodingCleanupAuthority,
	create dockercontrol.CodingCreateAuthority) bool {
	return cleanup.OriginalAuthorityDigest == create.Digest() &&
		cleanup.EffectID == create.EffectID && cleanup.ProfileDigest == create.ProfileDigest &&
		cleanup.ControlPolicyDigest == create.ControlPolicyDigest &&
		cleanup.PeerDeployment == create.PeerDeployment &&
		cleanup.PeerPrincipalDigest == create.PeerPrincipalDigest &&
		cleanup.ProviderRevisionID == create.ProviderRevisionID &&
		cleanup.TenantDigest == create.TenantDigest &&
		cleanup.AllocationID == create.AllocationID && cleanup.SandboxID == create.SandboxID &&
		cleanup.PlanDigest == create.PlanDigest && cleanup.SlotID == create.SlotID &&
		cleanup.BirthGeneration == create.CreationGeneration &&
		cleanup.BirthFence == create.Fence
}

func EncodeRequest(request Request) ([]byte, error) {
	document, err := json.Marshal(request)
	if err != nil || len(document) == 0 || len(document) > MaxRequestBytes {
		return nil, ErrInvalidWire
	}
	return document, nil
}

func DecodeRequest(document []byte, now time.Time, authenticatedPeerDigest string) (Request, error) {
	var request Request
	if decodeCanonical(document, MaxRequestBytes, &request) != nil ||
		request.Validate(now, authenticatedPeerDigest) != nil {
		return Request{}, ErrInvalidWire
	}
	return request, nil
}

// Response is a bounded receipt projection, not the Control-private proof
// file or a caller-supplied absence assertion. A TLS client must validate
// this against its own request and authenticated Control peer before the PG
// adapter may consider it. No Docker/container/volume ID or path is present.
type Response struct {
	Protocol                 string    `json:"protocol"`
	Scope                    string    `json:"scope"`
	Action                   string    `json:"action"`
	Status                   string    `json:"status"`
	CreateAuthorityDigest    string    `json:"create_authority_digest"`
	EffectID                 string    `json:"effect_id"`
	CleanupAuthorityDigest   string    `json:"cleanup_authority_digest,omitempty"`
	ControlRevision          uint64    `json:"control_revision"`
	ControlStateDigest       string    `json:"control_state_digest,omitempty"`
	CompletionDigest         string    `json:"completion_digest,omitempty"`
	CompletionEvidenceDigest string    `json:"completion_evidence_digest,omitempty"`
	AbsenceDigest            string    `json:"absence_digest,omitempty"`
	AbsenceEvidenceDigest    string    `json:"absence_evidence_digest,omitempty"`
	UpdatedAt                time.Time `json:"updated_at,omitempty"`
}

func (r Response) Validate(request Request) error {
	validationTime := request.Create.IssuedAt
	if request.Cleanup != nil && request.Cleanup.IssuedAt.After(validationTime) {
		validationTime = request.Cleanup.IssuedAt
	}
	if request.Validate(validationTime, request.Create.PeerPrincipalDigest) != nil ||
		r.Protocol != ProtocolID || r.Scope != ScopeCoding || r.Action != request.Action ||
		r.CreateAuthorityDigest != request.Create.Digest() || r.EffectID != request.Create.EffectID {
		return ErrInvalidWire
	}
	if request.Cleanup != nil && r.CleanupAuthorityDigest != "" &&
		r.CleanupAuthorityDigest != request.Cleanup.Digest() {
		return ErrInvalidWire
	}
	if r.CleanupAuthorityDigest != "" && !digestPattern.MatchString(r.CleanupAuthorityDigest) {
		return ErrInvalidWire
	}
	if r.Status == StatusNotFound {
		if request.Action != ActionStatus || r.ControlRevision != 0 ||
			r.ControlStateDigest != "" || r.CompletionDigest != "" ||
			r.CompletionEvidenceDigest != "" || r.AbsenceDigest != "" ||
			r.AbsenceEvidenceDigest != "" || !r.UpdatedAt.IsZero() ||
			r.CleanupAuthorityDigest != "" {
			return ErrInvalidWire
		}
		return nil
	}
	if r.ControlRevision == 0 || !digestPattern.MatchString(r.ControlStateDigest) ||
		r.UpdatedAt.IsZero() || r.UpdatedAt.Before(request.Create.IssuedAt) {
		return ErrInvalidWire
	}
	if request.Cleanup != nil && r.CleanupAuthorityDigest != "" &&
		r.UpdatedAt.Before(request.Cleanup.IssuedAt) {
		return ErrInvalidWire
	}
	switch r.Status {
	case StatusUnknown:
		if request.Action == ActionCleanup || r.CleanupAuthorityDigest != "" ||
			r.CompletionDigest != "" || r.CompletionEvidenceDigest != "" ||
			r.AbsenceDigest != "" || r.AbsenceEvidenceDigest != "" {
			return ErrInvalidWire
		}
	case StatusCompleted:
		if !digestPattern.MatchString(r.CompletionDigest) ||
			!digestPattern.MatchString(r.CompletionEvidenceDigest) ||
			r.CleanupAuthorityDigest != "" ||
			r.AbsenceDigest != "" || r.AbsenceEvidenceDigest != "" {
			return ErrInvalidWire
		}
	case StatusCleanupPending:
		if !digestPattern.MatchString(r.CleanupAuthorityDigest) ||
			!digestPattern.MatchString(r.CompletionDigest) ||
			!digestPattern.MatchString(r.CompletionEvidenceDigest) ||
			r.AbsenceDigest != "" || r.AbsenceEvidenceDigest != "" {
			return ErrInvalidWire
		}
	case StatusReleased:
		if !digestPattern.MatchString(r.CleanupAuthorityDigest) ||
			!digestPattern.MatchString(r.CompletionDigest) ||
			!digestPattern.MatchString(r.CompletionEvidenceDigest) ||
			!digestPattern.MatchString(r.AbsenceDigest) ||
			!digestPattern.MatchString(r.AbsenceEvidenceDigest) ||
			request.Cleanup != nil && !r.UpdatedAt.Before(request.Cleanup.ExpiresAt) {
			return ErrInvalidWire
		}
	default:
		return ErrInvalidWire
	}
	if request.Action == ActionCleanup && r.CleanupAuthorityDigest != request.Cleanup.Digest() {
		return ErrInvalidWire
	}
	if request.Action == ActionCleanup && r.Status != StatusCleanupPending &&
		r.Status != StatusReleased {
		return ErrInvalidWire
	}
	return nil
}

// ValidateReleaseObservation is only a read-side freshness gate. It cannot
// construct a trusted PG release snapshot. The dedicated transport verifies
// the actual mTLS peer; the application supplies a repository-read floor and
// the PG adapter later rechecks the current tuple under its own row lock.
func (r Response) ValidateReleaseObservation(request Request, now time.Time,
	minimumControlRevision uint64, previousStateDigest string) error {
	if request.Cleanup == nil || r.Status != StatusReleased ||
		r.Validate(request) != nil || now.IsZero() || r.UpdatedAt.After(now) ||
		minimumControlRevision == 0 || !digestPattern.MatchString(previousStateDigest) ||
		r.ControlRevision <= minimumControlRevision ||
		r.ControlStateDigest == previousStateDigest {
		return ErrInvalidWire
	}
	return nil
}

// ProjectReceipt exposes only the closed logical receipt fields. A durable
// cleanup intent without an absence seal is pending, never successful.
func ProjectReceipt(request Request, receipt dockercontrol.CodingReceipt,
	controlRevision uint64, controlStateDigest string) (Response, error) {
	if receipt.Authority != request.Create ||
		receipt.AuthorityDigest != request.Create.Digest() ||
		controlRevision == 0 || !digestPattern.MatchString(controlStateDigest) {
		return Response{}, ErrInvalidWire
	}
	response := Response{Protocol: ProtocolID, Scope: ScopeCoding, Action: request.Action,
		CreateAuthorityDigest: receipt.AuthorityDigest, EffectID: request.Create.EffectID,
		ControlRevision: controlRevision, ControlStateDigest: controlStateDigest,
		UpdatedAt: receipt.UpdatedAt}
	switch receipt.Status {
	case dockercontrol.ReceiptUnknown:
		response.Status = StatusUnknown
	case dockercontrol.ReceiptCompleted:
		response.Status = StatusCompleted
		if receipt.CleanupAuthority != (dockercontrol.CodingCleanupAuthority{}) {
			response.Status = StatusCleanupPending
			response.CleanupAuthorityDigest = receipt.CleanupAuthority.Digest()
		}
	case dockercontrol.ReceiptReleased:
		response.Status = StatusReleased
		response.CleanupAuthorityDigest = receipt.CleanupAuthority.Digest()
		response.AbsenceDigest = receipt.AbsenceDigest
		response.AbsenceEvidenceDigest = receipt.AbsenceEvidenceDigest
	default:
		return Response{}, ErrInvalidWire
	}
	response.CompletionDigest = receipt.CompletionDigest
	response.CompletionEvidenceDigest = receipt.CompletionEvidenceDigest
	if response.CleanupAuthorityDigest != "" &&
		(receipt.CleanupAuthority.Validate(receipt.CleanupAuthority.IssuedAt) != nil ||
			!cleanupMatchesCreate(receipt.CleanupAuthority, request.Create)) {
		return Response{}, ErrInvalidWire
	}
	if response.Validate(request) != nil {
		return Response{}, ErrInvalidWire
	}
	return response, nil
}

func EncodeResponse(response Response) ([]byte, error) {
	document, err := json.Marshal(response)
	if err != nil || len(document) == 0 || len(document) > MaxResponseBytes {
		return nil, ErrInvalidWire
	}
	return document, nil
}

func DecodeResponse(document []byte, request Request) (Response, error) {
	var response Response
	if decodeCanonical(document, MaxResponseBytes, &response) != nil ||
		response.Validate(request) != nil {
		return Response{}, ErrInvalidWire
	}
	return response, nil
}

func decodeCanonical(document []byte, limit int, target any) error {
	if len(document) == 0 || len(document) > limit {
		return ErrInvalidWire
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		return ErrInvalidWire
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(document, canonical) {
		return ErrInvalidWire
	}
	return nil
}
