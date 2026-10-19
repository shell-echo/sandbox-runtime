package phase6tls

import (
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

type PostgresPeerAuthorityV2 struct {
	PostgresPeerAuthority
	SourceMappingDigest string
	RoleDigest          string
}

// PostgresPeerGuardV2 binds the separate PG signer and actual process identity
// before the agent can perform a peer pull. Independent operator pins remain
// distinct from the role document and from the ordinary TLS/CRL purpose.
func PostgresPeerGuardV2(p phase6security.ProfileV2, a PostgresPeerAuthorityV2) (*PeerCRLGuard, error) {
	target, err := p.ResolveSlice6FinalPostgresAuthority(a.Owner)
	if err != nil || a.OperationTimeout < time.Second || a.OperationTimeout > 30*time.Second {
		return nil, ErrPeerCRLUnavailable
	}
	binding, _, agent, subject, _, err := p.PostgresClientSignerForOwner(a.Owner)
	if err != nil || a.AgentSocket == "" || binding.SocketPath != a.AgentSocket || binding.AgentUID != a.AgentUID || binding.AgentGID != a.AgentGID ||
		agent.UID != a.AgentUID || agent.GID != a.AgentGID || uint32(os.Getuid()) != subject.UID || uint32(os.Getgid()) != subject.GID ||
		a.PeerCRLRole.Digest() != a.RoleDigest || a.PeerCRLRole.ValidatePostgresV2(p, a.SourceMappingDigest, a.Owner, subject.PrincipalDigest) != nil ||
		len(a.PeerCRLRole.Edges) != 1 || a.PeerCRLRole.Edges[0].EdgeID != target.PeerEdgeID || a.PeerCRLRole.Edges[0].PeerAnchorID != target.ServerAnchor.ID {
		return nil, ErrPeerCRLUnavailable
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, ErrPeerCRLUnavailable
	}
	for _, group := range groups {
		if uint32(group) != subject.GID {
			return nil, ErrPeerCRLUnavailable
		}
	}
	client, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{SocketPath: a.AgentSocket, ExpectedUID: a.AgentUID, ExpectedGID: a.AgentGID, RoleGID: subject.GID, OperationTimeout: a.OperationTimeout, Now: time.Now})
	if err != nil {
		return nil, ErrPeerCRLUnavailable
	}
	return NewPostgresPeerCRLGuardV2(p, a.PeerCRLRole, a.SourceMappingDigest, a.RoleDigest, a.Owner, subject.PrincipalDigest, client, a.OperationTimeout, time.Now)
}
