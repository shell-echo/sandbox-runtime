package phase6profilebuilder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidCandidateProfile = errors.New("invalid Phase 6 Slice 6 candidate profile")

// CandidateProfile is desired, source-bound configuration only. It is not a
// launch receipt and cannot satisfy any of the 16 live scenarios by itself.
type CandidateProfile struct {
	Profile phase6security.Profile
	source  KeyedStaticDraft
	metrics CompositionMetrics
}

// CompositionMetrics is local diagnostic timing, never profile or release
// evidence. Counts reflect actual full source loaders in this Compose call.
type CompositionMetrics struct {
	ImageSupplyLoads      int
	ExternalArchivePasses int
	Stages                []CompositionStage
}

type CompositionStage struct {
	Name     string
	Duration time.Duration
}

func (c CandidateProfile) Diagnostics() CompositionMetrics {
	result := c.metrics
	result.Stages = append([]CompositionStage(nil), result.Stages...)
	return result
}

// FreezeSlice6CandidateProfile reopens every original source through the
// draft chain, then reads the selected Desktop image's effective broker bytes
// before validating the complete final-gate Profile. No digest, key or
// external identity is accepted from an operator-authored Profile document.
func FreezeSlice6CandidateProfile(ctx context.Context, draft KeyedStaticDraft, now time.Time) (CandidateProfile, error) {
	if draft.VerifySources(ctx, now) != nil {
		return CandidateProfile{}, ErrInvalidCandidateProfile
	}
	profile, err := buildSlice6CandidateProfile(draft)
	if err != nil {
		return CandidateProfile{}, ErrInvalidCandidateProfile
	}
	return CandidateProfile{Profile: profile, source: draft}, nil
}

func (c CandidateProfile) VerifySources(ctx context.Context, now time.Time) error {
	if c.source.VerifySources(ctx, now) != nil {
		return ErrInvalidCandidateProfile
	}
	want, err := buildSlice6CandidateProfile(c.source)
	if err != nil || !reflect.DeepEqual(c.Profile, want) {
		return ErrInvalidCandidateProfile
	}
	return nil
}

func buildSlice6CandidateProfile(draft KeyedStaticDraft) (phase6security.Profile, error) {
	if phase6security.VerifySlice6BreakGlassKeyAuthority(draft.BreakGlassKeyAuthority) != nil {
		return phase6security.Profile{}, ErrInvalidCandidateProfile
	}
	if draft.BreakGlassExecutableArtifact.ID != "break-glass-operator" ||
		draft.BreakGlassExecutableArtifact.SourceRevision != draft.ImageSupply.RuntimeRevision ||
		draft.BreakGlassExecutableArtifact.SourceTreeDigest != draft.ImageSupply.RuntimeTreeDigest ||
		draft.BreakGlassExecutableArtifact.Platform != draft.ImageSupply.Platform ||
		verifySlice6OperatorBinarySource(draft.operatorBinaryPath, draft.BreakGlassExecutableArtifact) != nil {
		return phase6security.Profile{}, ErrInvalidCandidateProfile
	}
	if verifySlice6CandidateIssuerBundles(draft.AnchorSupply, draft.DNSClientCA) != nil {
		return phase6security.Profile{}, ErrInvalidCandidateProfile
	}
	image := draft.ImageSupply.DesktopCandidate
	if image.ValidateCurrent() != nil || image.SourceRevision != draft.ImageSupply.RuntimeRevision ||
		image.SourceTreeDigest != draft.ImageSupply.RuntimeTreeDigest || image.Platform != draft.ImageSupply.Platform ||
		!cleanAbsolute(draft.ImageSupply.desktopCandidatePath) {
		return phase6security.Profile{}, ErrInvalidCandidateProfile
	}
	archive := draft.ImageSupply.desktopCandidatePath + ".oci.tar"
	if !cleanAbsolute(archive) || !privateFileParent(archive) ||
		filepath.Dir(archive) != filepath.Dir(draft.ImageSupply.desktopCandidatePath) {
		return phase6security.Profile{}, ErrInvalidCandidateProfile
	}
	documents, err := phase6security.ReadOCIArchiveDocuments(archive, image.ImageIdentityKind,
		image.ImageDigest, image.SelectedManifestDigest, image.ConfigDigest)
	if err != nil {
		return phase6security.Profile{}, ErrInvalidCandidateProfile
	}
	broker, err := phase6security.ReadVerifiedOCIArchiveDesktopBroker(archive, documents.Manifest, documents.Config)
	if err != nil {
		return phase6security.Profile{}, ErrInvalidCandidateProfile
	}
	brokerHash := sha256.Sum256(broker)
	clear(broker)
	component := phase6security.Component{Name: "desktop-broker", ParentDeployment: "desktop-sandbox-runtime",
		Executable:       "/usr/local/libexec/sandbox-runtime/desktop-broker",
		ExecutableDigest: "sha256:" + hex.EncodeToString(brokerHash[:]),
		Argv:             []string{"/usr/local/libexec/sandbox-runtime/desktop-broker", "serve"},
		Socket:           "/tmp/sandbox-runtime-desktop-broker.sock", BrokerProtocol: "sandbox.runtime/desktop-broker/v1",
		SessionProtocol: "sandbox.runtime/desktop-session.v2"}
	if len(draft.Principals) == 0 || draft.Principals[0].AuthorizationPrincipal == nil ||
		len(draft.ImageSupply.RuntimeRevision) != 40 {
		return phase6security.Profile{}, ErrInvalidCandidateProfile
	}
	identity := draft.Principals[0].AuthorizationPrincipal
	principals, err := phase6security.AttachSlice6ControllerLedgerMounts(draft.Principals)
	if err != nil {
		return phase6security.Profile{}, ErrInvalidCandidateProfile
	}
	principals, err = phase6security.AttachSlice6PrivateConfigMounts(principals)
	if err != nil {
		return phase6security.Profile{}, ErrInvalidCandidateProfile
	}
	principals, materialSockets, err := phase6security.AttachSlice6MaterialSocketBindings(principals)
	if err != nil {
		return phase6security.Profile{}, ErrInvalidCandidateProfile
	}
	principals, breakGlassSockets, breakGlassTasks, err := phase6security.AttachSlice6BreakGlassBoundaries(principals)
	if err != nil {
		return phase6security.Profile{}, ErrInvalidCandidateProfile
	}
	profile := phase6security.Profile{Protocol: phase6security.ProtocolID, Version: phase6security.Version,
		Revision:          "slice6-" + draft.ImageSupply.RuntimeRevision,
		EnvironmentDigest: identity.EnvironmentDigest, PrincipalProfileDigest: identity.ProfileDigest,
		Principals: principals, SandboxIdentitySlots: draft.SandboxIdentitySlots,
		ProviderDatabases: draft.ProviderDatabases, PostgresServerAuth: draft.PostgresServerAuth,
		Components: []phase6security.Component{component}, Networks: draft.Networks,
		External: draft.External, TrustEdges: draft.TrustEdges, TrustAnchors: draft.TrustAnchors,
		PublicListeners: draft.PublicListeners, IngressBindings: draft.IngressBindings,
		CertificateController: draft.CertificateController, CredentialIssuerSockets: draft.CredentialIssuerSockets,
		MaterialSockets: materialSockets, BreakGlassSockets: breakGlassSockets,
		BreakGlassOperatorTasks:      breakGlassTasks,
		BreakGlassKeyAuthority:       draft.BreakGlassKeyAuthority,
		BreakGlassExecutableArtifact: draft.BreakGlassExecutableArtifact,
		TLSAgentBindings:             draft.TLSAgentBindings, PostgresClientAgents: draft.PostgresClientAgents,
		EgressPolicies: draft.EgressPolicies, CleanupClasses: draft.CleanupClasses}
	profile.ProfileDigest = profile.Digest()
	if profile.Validate() != nil || phase6security.VerifySlice6FinalGateProfile(profile) != nil {
		return phase6security.Profile{}, ErrInvalidCandidateProfile
	}
	return profile, nil
}
