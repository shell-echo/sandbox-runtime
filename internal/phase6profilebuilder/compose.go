package phase6profilebuilder

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrInvalidComposition = errors.New("invalid Phase 6 Slice 6 profile composition")

// CompositionInputs names original operator and source artifacts, never
// operator-authored profile fields or observations. This is a configuration
// freeze only; live dependency and scenario evidence remains a separate gate.
type CompositionInputs struct {
	Images          ImageDraftInputs
	TrustAnchors    map[string]string
	ExternalImages  ExternalImageInputs
	EgressKeys      map[string]string
	CertificateKeys map[string]string
}

// ComposeSlice6CandidateProfile reopens every original input through the
// complete reviewed builder chain before freezing the final static profile.
// It cannot establish CA issuer ownership, private-key possession by live
// roles, Docker enforcement, or any of the 16 live Slice 6 scenarios.
func ComposeSlice6CandidateProfile(ctx context.Context, input CompositionInputs, now time.Time) (CandidateProfile, error) {
	if ctx == nil || ctx.Err() != nil || now.IsZero() ||
		input.Images.SourceRoot != input.ExternalImages.SourceRoot {
		return CandidateProfile{}, compositionError("input")
	}
	resource, err := BuildSlice6ResourceDraft(ctx, input.Images)
	if err != nil {
		return CandidateProfile{}, compositionError("source images and resource policy")
	}
	anchors, err := LoadSlice6TrustAnchorSupply(input.TrustAnchors, now)
	if err != nil {
		return CandidateProfile{}, compositionError("operator trust anchors")
	}
	trusted, err := BindSlice6TrustAnchorDraft(resource, anchors, now)
	if err != nil {
		return CandidateProfile{}, compositionError("trust-anchor bindings")
	}
	external, err := LoadExternalImageSupply(ctx, input.ExternalImages)
	if err != nil {
		return CandidateProfile{}, compositionError("external image archives")
	}
	topology, err := BindSlice6FinalTopologyDraft(ctx, trusted, external, now)
	if err != nil {
		return CandidateProfile{}, compositionError("reviewed topology")
	}
	egressKeys, err := LoadSlice6EgressKeySupply(input.EgressKeys)
	if err != nil {
		return CandidateProfile{}, compositionError("egress key sources")
	}
	egress, err := BindSlice6EgressDraft(ctx, topology, egressKeys, now)
	if err != nil {
		return CandidateProfile{}, compositionError("egress authority bindings")
	}
	certificateKeys, err := LoadSlice6CertificateKeySupply(input.CertificateKeys)
	if err != nil {
		return CandidateProfile{}, compositionError("certificate key sources")
	}
	certificate, err := BindSlice6CertificateDraft(ctx, egress, certificateKeys, now)
	if err != nil {
		return CandidateProfile{}, compositionError("certificate authority bindings")
	}
	static, err := BindSlice6StaticDraft(ctx, certificate, now)
	if err != nil {
		return CandidateProfile{}, compositionError("static profile fields")
	}
	candidate, err := FreezeSlice6CandidateProfile(ctx, static, now)
	if err != nil || candidate.VerifySources(ctx, now) != nil {
		return CandidateProfile{}, compositionError("final source freeze")
	}
	return candidate, nil
}

func compositionError(stage string) error {
	return fmt.Errorf("%w: %s", ErrInvalidComposition, stage)
}
