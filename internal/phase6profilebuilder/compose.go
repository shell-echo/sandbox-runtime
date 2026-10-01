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
	DNSClientCA     DNSClientCAInput
	EgressKeys      map[string]string
	CertificateKeys map[string]string
}

type compositionTraceKey struct{}

type compositionTrace struct {
	imageSupplyLoads int
	externalPasses   int
	stages           []CompositionStage
}

func recordCompositionExternalPass(ctx context.Context) {
	if ctx != nil {
		if trace, ok := ctx.Value(compositionTraceKey{}).(*compositionTrace); ok {
			trace.externalPasses++
		}
	}
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
	trace := &compositionTrace{}
	ctx = context.WithValue(ctx, compositionTraceKey{}, trace)
	started := time.Now()
	mark := func(name string) {
		trace.stages = append(trace.stages, CompositionStage{Name: name, Duration: time.Since(started)})
		started = time.Now()
	}
	resource, err := BuildSlice6ResourceDraft(ctx, input.Images)
	if err != nil {
		return CandidateProfile{}, compositionError("source images and resource policy")
	}
	mark("source_images_resource")
	anchors, err := LoadSlice6TrustAnchorSupply(input.TrustAnchors, now)
	if err != nil {
		return CandidateProfile{}, compositionError("operator trust anchors")
	}
	trusted, err := BindSlice6TrustAnchorDraft(resource, anchors, now)
	if err != nil {
		return CandidateProfile{}, compositionError("trust-anchor bindings")
	}
	mark("trust_anchors")
	external, err := LoadExternalImageSupply(ctx, input.ExternalImages)
	if err != nil {
		return CandidateProfile{}, compositionError("external image archives")
	}
	mark("external_archives")
	dns, err := LoadSlice6DNSClientCASupply(input.DNSClientCA, now)
	if err != nil {
		return CandidateProfile{}, compositionError("DNS broker-client CA")
	}
	// The inputs above were each opened and checked. Intermediate binds are
	// pure derivations; recursively reopening every compressed OCI layer at
	// every layer adds no new authority. The final VerifySources below reopens
	// every original input independently before this candidate is returned.
	topology, err := bindSlice6FinalTopologyDraftWithDNSClientCA(trusted, external, dns)
	if err != nil {
		return CandidateProfile{}, compositionError("reviewed topology")
	}
	mark("reviewed_topology")
	egressKeys, err := LoadSlice6EgressKeySupply(input.EgressKeys)
	if err != nil {
		return CandidateProfile{}, compositionError("egress key sources")
	}
	egress, err := bindSlice6EgressDraft(topology, egressKeys)
	if err != nil {
		return CandidateProfile{}, compositionError("egress authority bindings")
	}
	mark("egress_bindings")
	certificateKeys, err := LoadSlice6CertificateKeySupply(input.CertificateKeys)
	if err != nil {
		return CandidateProfile{}, compositionError("certificate key sources")
	}
	certificate, err := bindSlice6CertificateDraft(egress, certificateKeys)
	if err != nil {
		return CandidateProfile{}, compositionError("certificate authority bindings")
	}
	mark("certificate_bindings")
	static, err := bindSlice6StaticDraft(certificate)
	if err != nil {
		return CandidateProfile{}, compositionError("static profile fields")
	}
	mark("static_fields")
	profile, err := buildSlice6CandidateProfile(static)
	if err != nil {
		return CandidateProfile{}, compositionError("static profile fields")
	}
	mark("profile_derivation")
	candidate := CandidateProfile{Profile: profile, source: static}
	if candidate.VerifySources(ctx, time.Now().UTC()) != nil {
		return CandidateProfile{}, compositionError("final source freeze")
	}
	mark("final_source_reopen")
	candidate.metrics = CompositionMetrics{ImageSupplyLoads: trace.imageSupplyLoads,
		ExternalArchivePasses: trace.externalPasses, Stages: trace.stages}
	return candidate, nil
}

func compositionError(stage string) error {
	return fmt.Errorf("%w: %s", ErrInvalidComposition, stage)
}
