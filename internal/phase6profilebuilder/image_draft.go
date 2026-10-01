package phase6profilebuilder

import (
	"context"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// ImageDraftInputs names only private, source-bound artifacts. A caller cannot
// supply a deployment-to-image map to this builder. The clean checkout and
// original OCI archive/candidate bytes are reopened by LoadImageSupply.
type ImageDraftInputs struct {
	RunID                  string
	EnvironmentDigest      string
	PrincipalProfileDigest string
	SourceRoot             string
	SourceRevision         string
	RoleCandidateDirectory string
	DesktopCandidatePath   string
	BrowserArchivePath     string
}

// BuildSlice6ImageDraft composes the reviewed 78-principal identity,
// placement and credential-issuer draft with verified image identities.
// Its output remains non-launchable: resource/seccomp policy, full mounts,
// TLS/external artifacts, trust edges and the final profile are still absent.
// Final admission must reopen source and candidate bytes after profile freeze.
func BuildSlice6ImageDraft(ctx context.Context, input ImageDraftInputs) (PrincipalDraft, error) {
	supply, err := LoadImageSupply(ctx, input.SourceRoot, input.SourceRevision,
		input.RoleCandidateDirectory, input.DesktopCandidatePath, input.BrowserArchivePath)
	if err != nil {
		return PrincipalDraft{}, err
	}
	draft, err := BuildSlice6PrincipalDraft(input.RunID, input.EnvironmentDigest, input.PrincipalProfileDigest)
	if err != nil {
		return PrincipalDraft{}, err
	}
	return bindPrincipalDraftImages(draft, supply)
}

func bindPrincipalDraftImages(draft PrincipalDraft, supply ImageSupply) (PrincipalDraft, error) {
	for _, principal := range draft.Principals {
		if principal.ImageReference != "" || principal.ImageDigest != "" || principal.ImageLocation != "" ||
			principal.ImageIdentityKind != "" || principal.ImagePlatform != "" ||
			principal.ImageSelectedManifestDigest != "" || principal.ImageConfigDigest != "" {
			return PrincipalDraft{}, ErrInvalidImageSupply
		}
	}
	bound, err := supply.bindPrincipalImages(draft.Principals)
	if err != nil {
		return PrincipalDraft{}, err
	}
	return PrincipalDraft{Principals: bound, Networks: append([]phase6security.Network(nil), draft.Networks...),
		CredentialIssuerSockets: append([]phase6security.CredentialIssuerSocketBinding(nil), draft.CredentialIssuerSockets...),
		ImageSupply:             supply}, nil
}
