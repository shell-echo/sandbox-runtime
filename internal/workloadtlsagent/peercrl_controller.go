package workloadtlsagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

type PeerCRLControllerClient interface {
	PeerRevocations(context.Context, workloadpki.PeerCRLBinding) (workloadpki.PeerCRLResponse, error)
}

// ControllerPeerCRLProvider is the only production v2 adapter from the
// role-owned agent to the certificate controller. The role can name an edge,
// never a Vault source; this adapter selects the source from a pinned profile.
type ControllerPeerCRLProvider struct {
	profile       phase6security.Profile
	sources       phase6security.PeerCRLSources
	subjectDigest string
	client        PeerCRLControllerClient
	now           func() time.Time
}

func NewControllerPeerCRLProvider(profile phase6security.Profile, sources phase6security.PeerCRLSources,
	subjectDigest string, client PeerCRLControllerClient, now func() time.Time) (*ControllerPeerCRLProvider, error) {
	if client == nil || now == nil || now().IsZero() || sources.Validate(profile) != nil {
		return nil, ErrUnavailable
	}
	found := false
	for _, binding := range profile.TLSAgentBindings {
		if binding.SubjectPrincipalDigest == subjectDigest {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrUnavailable
	}
	profileDocument, err := json.Marshal(profile)
	if err != nil {
		return nil, ErrUnavailable
	}
	copyProfile, err := phase6security.Decode(profileDocument)
	clear(profileDocument)
	if err != nil {
		return nil, ErrUnavailable
	}
	sourcesDocument, err := json.Marshal(sources)
	if err != nil {
		return nil, ErrUnavailable
	}
	copySources, err := phase6security.DecodePeerCRLSources(sourcesDocument, copyProfile)
	clear(sourcesDocument)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &ControllerPeerCRLProvider{profile: copyProfile, sources: copySources,
		subjectDigest: subjectDigest, client: client, now: now}, nil
}

func (p *ControllerPeerCRLProvider) ReadPeerCRL(ctx context.Context, request PeerCRLRequest) (string, []byte, []byte, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || request.Validate(p.now().UTC()) != nil ||
		request.ProfileDigest != p.profile.ProfileDigest || request.LocalPrincipalDigest != p.subjectDigest {
		return "", nil, nil, ErrUnavailable
	}
	sourceID, err := p.sources.AuthorizedSourceID(p.profile, request.EdgeID, request.LocalPrincipalDigest,
		request.Direction, request.PeerAnchorID, request.IssuerDigest)
	if err != nil {
		return "", nil, nil, ErrUnavailable
	}
	response, err := p.client.PeerRevocations(ctx, workloadpki.PeerCRLBinding{
		ProfileDigest: request.ProfileDigest, EdgeID: request.EdgeID,
		LocalPrincipalDigest: request.LocalPrincipalDigest, Direction: request.Direction,
		PeerAnchorID: request.PeerAnchorID, IssuerDigest: request.IssuerDigest, SourceID: sourceID})
	if err != nil || ctx.Err() != nil || response.Status != workloadpki.StatusOK || response.SourceID != sourceID ||
		response.ProfileDigest != request.ProfileDigest || response.EdgeID != request.EdgeID ||
		response.Direction != request.Direction || response.PeerAnchorID != request.PeerAnchorID ||
		response.IssuerDigest != request.IssuerDigest {
		clear(response.IssuerDER)
		clear(response.CRLDER)
		return "", nil, nil, ErrUnavailable
	}
	defer clear(response.IssuerDER)
	issuerHash := sha256.Sum256(response.IssuerDER)
	if "sha256:"+hex.EncodeToString(issuerHash[:]) != request.IssuerDigest {
		clear(response.CRLDER)
		return "", nil, nil, ErrUnavailable
	}
	thisUpdate, firstErr := time.Parse(time.RFC3339Nano, response.ThisUpdate)
	nextUpdate, secondErr := time.Parse(time.RFC3339Nano, response.NextUpdate)
	if firstErr != nil || secondErr != nil || thisUpdate.UTC().Format(time.RFC3339Nano) != response.ThisUpdate ||
		nextUpdate.UTC().Format(time.RFC3339Nano) != response.NextUpdate {
		clear(response.CRLDER)
		return "", nil, nil, ErrUnavailable
	}
	snapshot := workloadpki.RevocationSnapshot{DER: response.CRLDER, ThisUpdate: thisUpdate, NextUpdate: nextUpdate}
	if _, err := workloadpki.VerifyCRLForIssuer(snapshot, response.IssuerDER, p.now().UTC()); err != nil {
		clear(response.CRLDER)
		return "", nil, nil, ErrUnavailable
	}
	return sourceID, append([]byte(nil), response.IssuerDER...), response.CRLDER, nil
}
