package phase6tls

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

// NewPeerCRLGuardV2 requires both independent operator pins. A role document
// may not nominate its own mapping or replace the expected role digest.
func NewPeerCRLGuardV2(profile phase6security.ProfileV2, role phase6security.PeerCRLRoleDocument,
	expectedMappingDigest, expectedRoleDigest, edgeID, localPrincipalDigest, direction string,
	client PeerCRLClient, timeout time.Duration, now func() time.Time) (*PeerCRLGuard, error) {
	if profile.Validate() != nil || role.Digest() != expectedRoleDigest ||
		role.ValidateV2(profile, expectedMappingDigest, localPrincipalDigest) != nil {
		return nil, ErrPeerCRLUnavailable
	}
	return newPeerCRLGuardV2Bound(profile, role, edgeID, localPrincipalDigest, direction, client, timeout, now)
}

// NewPostgresPeerCRLGuardV2 is a low-level guard, like NewPeerCRLGuardV2.
// A production composition must separately bind the dedicated signer socket,
// process UID/GID and supplementary groups before providing its agent client.
func NewPostgresPeerCRLGuardV2(profile phase6security.ProfileV2, role phase6security.PeerCRLRoleDocument,
	expectedMappingDigest, expectedRoleDigest, owner, localPrincipalDigest string,
	client PeerCRLClient, timeout time.Duration, now func() time.Time) (*PeerCRLGuard, error) {
	if profile.Validate() != nil || role.Digest() != expectedRoleDigest ||
		role.ValidatePostgresV2(profile, expectedMappingDigest, owner, localPrincipalDigest) != nil {
		return nil, ErrPeerCRLUnavailable
	}
	return newPeerCRLGuardV2Bound(profile, role, role.Edges[0].EdgeID, localPrincipalDigest, "outbound", client, timeout, now)
}

// Only admitted documents reach this construction path; all refresh, verified
// handshake, monotonic CRL and deadline/drain behavior is shared with v1.
func newPeerCRLGuardV2Bound(profile phase6security.ProfileV2, role phase6security.PeerCRLRoleDocument,
	edgeID, localPrincipalDigest, direction string,
	client PeerCRLClient, timeout time.Duration, now func() time.Time) (*PeerCRLGuard, error) {
	bound, err := role.Binding(edgeID, direction)
	if err != nil || client == nil || now == nil || now().IsZero() || !validPeerCRLDigest(bound.IssuerDigest) {
		return nil, ErrPeerCRLUnavailable
	}
	for _, edge := range profile.TrustEdges {
		if edge.ID != edgeID || edge.Authentication != "mtls" {
			continue
		}
		localName, localDigest, anchorID := edge.From, edge.FromPrincipalDigest, edge.ServerAnchorID
		if direction == "inbound" {
			localName, localDigest, anchorID = edge.To, edge.ToPrincipalDigest, edge.ClientAnchorID
		} else if direction != "outbound" {
			return nil, ErrPeerCRLUnavailable
		}
		if localDigest != localPrincipalDigest || anchorID == "" || bound.PeerAnchorID != anchorID {
			return nil, ErrPeerCRLUnavailable
		}
		for _, principal := range profile.Principals {
			if principal.Name != localName || principal.PrincipalDigest != localPrincipalDigest || principal.TLS == nil {
				continue
			}
			staleness := time.Duration(principal.TLS.RevocationMaxStalenessSeconds) * time.Second
			drain := time.Duration(principal.TLS.ConnectionDrainSeconds) * time.Second
			budget, err := derivePeerCRLBudget(staleness, drain, timeout)
			if err != nil {
				return nil, ErrPeerCRLUnavailable
			}
			return &PeerCRLGuard{binding: workloadtlsagent.PeerCRLBinding{ProfileDigest: profile.ProfileDigest,
				SourceMappingDigest: role.SourceMappingDigest, EdgeID: edgeID, LocalPrincipalDigest: localPrincipalDigest,
				Direction: direction, PeerAnchorID: anchorID}, expectedIssuerDigest: bound.IssuerDigest,
				client: client, pullPermit: make(chan struct{}, 1), timeout: budget.timeout,
				pollInterval: budget.interval, closeBudget: budget.close, maxStaleness: staleness, now: now,
				observedRevoked: make(map[string]revokedPeerObservation), active: make(map[net.Conn]tls.ConnectionState)}, nil
		}
	}
	return nil, ErrPeerCRLUnavailable
}
