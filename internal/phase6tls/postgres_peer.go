package phase6tls

import (
	"errors"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

type PostgresPeerAuthority struct {
	Owner            string
	PeerCRLRole      phase6security.PeerCRLRoleDocument
	AgentSocket      string
	AgentUID         uint32
	AgentGID         uint32
	OperationTimeout time.Duration
}

// PostgresPeerGuard resolves only the dedicated PostgreSQL-purpose signer
// and the logical caller's inner TLS edge. It cannot borrow the ordinary
// role signer or treat the Browser/Desktop broker's physical edge as caller.
func PostgresPeerGuard(profile phase6security.Profile, authority PostgresPeerAuthority) (*PeerCRLGuard, error) {
	target, err := profile.ResolveSlice6FinalPostgresAuthority(authority.Owner)
	if err != nil || authority.OperationTimeout < time.Second || authority.OperationTimeout > 30*time.Second ||
		authority.PeerCRLRole.ValidateForPrincipal(profile, authority.PeerCRLRole.SourceMappingDigest,
			profilePrincipalDigest(profile, authority.Owner)) != nil || len(authority.PeerCRLRole.Edges) != 1 ||
		authority.PeerCRLRole.Edges[0].EdgeID != target.PeerEdgeID ||
		authority.PeerCRLRole.Edges[0].Direction != "outbound" ||
		authority.PeerCRLRole.Edges[0].PeerAnchorID != target.ServerAnchor.ID {
		return nil, errors.New("PostgreSQL peer revocation authority does not match profile")
	}
	binding, _, agent, subject, _, err := profile.PostgresClientSignerForOwner(authority.Owner)
	if err != nil || binding.SocketPath != authority.AgentSocket || binding.AgentUID != authority.AgentUID ||
		binding.AgentGID != authority.AgentGID || agent.UID != authority.AgentUID || agent.GID != authority.AgentGID ||
		subject.PrincipalDigest == "" || uint32(os.Getuid()) != subject.UID || uint32(os.Getgid()) != subject.GID ||
		authority.AgentSocket == "" {
		return nil, errors.New("PostgreSQL peer revocation signer does not match profile")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, errors.New("PostgreSQL peer revocation process groups unavailable")
	}
	for _, group := range groups {
		if uint32(group) != subject.GID {
			return nil, errors.New("PostgreSQL peer revocation has supplementary group authority")
		}
	}
	client, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: authority.AgentSocket, ExpectedUID: authority.AgentUID, ExpectedGID: authority.AgentGID,
		RoleGID: subject.GID, OperationTimeout: authority.OperationTimeout, Now: time.Now})
	if err != nil {
		return nil, errors.New("PostgreSQL peer revocation signer unavailable")
	}
	guard, err := NewPeerCRLGuard(profile, authority.PeerCRLRole, target.PeerEdgeID,
		subject.PrincipalDigest, "outbound", client, authority.OperationTimeout, time.Now)
	if err != nil {
		return nil, errors.New("PostgreSQL peer revocation guard unavailable")
	}
	return guard, nil
}

func profilePrincipalDigest(profile phase6security.Profile, owner string) string {
	for _, principal := range profile.Principals {
		if principal.Name == owner {
			return principal.PrincipalDigest
		}
	}
	return ""
}
