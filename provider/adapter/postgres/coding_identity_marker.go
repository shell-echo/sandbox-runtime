package providerpostgres

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

const codingAtomicOriginalMode = "atomic-original-envelope"

// codingIdentityMarker is a Coding-only persistent execution-mode lock. The
// Browser/Desktop identityMarker intentionally remains unchanged. An old
// initialized marker with no mode stays legacy; it cannot be upgraded in
// place to v3 or used to mint a v3 first permit.
type codingIdentityMarker struct {
	Initialized         bool   `json:"initialized"`
	PlanDigest          string `json:"plan_digest"`
	AuthorityMode       string `json:"authority_mode,omitempty"`
	ControlPolicyDigest string `json:"control_policy_digest,omitempty"`
}

func (m codingIdentityMarker) validate() error {
	if !m.Initialized {
		if m.PlanDigest != "" || m.AuthorityMode != "" || m.ControlPolicyDigest != "" {
			return ErrCorrupt
		}
		return nil
	}
	if lifecycle.ValidateDigest(m.PlanDigest) != nil {
		return ErrCorrupt
	}
	switch m.AuthorityMode {
	case "":
		if m.ControlPolicyDigest != "" {
			return ErrCorrupt
		}
	case codingAtomicOriginalMode:
		if lifecycle.ValidateDigest(m.ControlPolicyDigest) != nil {
			return ErrCorrupt
		}
	default:
		return ErrCorrupt
	}
	return nil
}

func (m codingIdentityMarker) matchesAtomic(planDigest, controlPolicyDigest string) bool {
	return m.validate() == nil && m.Initialized && m.PlanDigest == planDigest &&
		m.AuthorityMode == codingAtomicOriginalMode && m.ControlPolicyDigest == controlPolicyDigest
}

func importCodingIdentityMarker(target *codingIdentityMarker, document json.RawMessage) error {
	var decoded codingIdentityMarker
	if decodePersisted(&decoded, document) != nil || decoded.validate() != nil {
		return ErrCorrupt
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(canonical, document) {
		return ErrCorrupt
	}
	*target = decoded
	return nil
}

func (r *CodingBoundCreateRepository) readAtomicMarker(ctx context.Context) error {
	if r == nil || ctx == nil || lifecycle.ValidateDigest(r.controlPolicyDigest) != nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	marker, err := r.readCodingMarker(ctx)
	if err != nil {
		return err
	}
	if !marker.matchesAtomic(r.digest, r.controlPolicyDigest) {
		return ErrCorrupt
	}
	return ctx.Err()
}

func (r *CodingBoundCreateRepository) readCodingMarker(ctx context.Context) (codingIdentityMarker, error) {
	if r == nil || ctx == nil {
		return codingIdentityMarker{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return codingIdentityMarker{}, err
	}
	marker, err := readState(ctx, r.store, codingIdentityMarkerDocument,
		func() codingIdentityMarker { return codingIdentityMarker{} }, importCodingIdentityMarker)
	if err != nil {
		return codingIdentityMarker{}, err
	}
	if marker.validate() != nil {
		return codingIdentityMarker{}, ErrCorrupt
	}
	return marker, nil
}
