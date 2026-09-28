package phase6security

import "slices"

// Slice6PostgresAuthority is a static, profile-bound connection target. It
// does not prove that the server loaded its HBA, SQL grants or certificates.
type Slice6PostgresAuthority struct {
	Owner         string
	Dialer        string
	Network       string
	EdgeID        string
	PeerEdgeID    string
	SourceAddress string
	ServerAddress string
	ServerHost    string
	ServerPort    int
	ServerURI     string
	Database      string
	SQLRole       string
	Migration     bool
	BrokerOnly    bool
	Signer        PostgresClientAgentBinding
	ServerAnchor  TrustAnchor
}

// ResolveSlice6FinalPostgresAuthority admits only the closed nine-owner
// shared-service profile. Runtime commands must resolve this before secret
// lookup, connection or listener creation; the DSN and live topology require
// separate checks against the returned values.
func (p Profile) ResolveSlice6FinalPostgresAuthority(owner string) (Slice6PostgresAuthority, error) {
	if VerifySlice6DesiredFinalExternalProfile(p) != nil {
		return Slice6PostgresAuthority{}, ErrInvalidProfile
	}
	var rule Slice6PostgresHBARule
	rules, err := Slice6DesiredFinalSharedPostgresHBARules()
	if err != nil {
		return Slice6PostgresAuthority{}, ErrInvalidProfile
	}
	for _, candidate := range rules {
		if candidate.Owner == owner {
			rule = candidate
			break
		}
	}
	if rule.Owner == "" {
		return Slice6PostgresAuthority{}, ErrInvalidProfile
	}
	signer, signerTarget, _, _, _, err := p.PostgresClientSignerForOwner(owner)
	if err != nil || signerTarget.DatabaseName != rule.Database || signerTarget.SQLRole != rule.SQLRole ||
		signerTarget.Migration != rule.Migration {
		return Slice6PostgresAuthority{}, ErrInvalidProfile
	}
	var path Slice6ExternalTransportPath
	for _, candidate := range Slice6DesiredFinalExternalTransports() {
		if candidate.LogicalCaller == owner && candidate.Service == "postgres" {
			if path.Network != "" {
				return Slice6PostgresAuthority{}, ErrInvalidProfile
			}
			path = candidate
		}
	}
	if path.Network == "" || path.Dialer != rule.Dialer || len(path.EdgeIDs) < 1 || len(path.EdgeIDs) > 2 {
		return Slice6PostgresAuthority{}, ErrInvalidProfile
	}
	source, err := Slice6DesiredFinalServiceEndpointAddress(path.Network, path.Dialer)
	if err != nil || source+"/32" != rule.SourceCIDR {
		return Slice6PostgresAuthority{}, ErrInvalidProfile
	}
	server, err := Slice6DesiredFinalServiceEndpointAddress(path.Network, "postgres")
	if err != nil {
		return Slice6PostgresAuthority{}, ErrInvalidProfile
	}
	var service ExternalService
	for _, candidate := range p.External {
		if candidate.Name == "postgres" {
			service = candidate
			break
		}
	}
	if len(service.DNSNames) != 1 || service.URI == "" || !slices.Contains(service.Networks, path.Network) {
		return Slice6PostgresAuthority{}, ErrInvalidProfile
	}
	var selected, peer TrustEdge
	for _, edge := range p.TrustEdges {
		if slices.Contains(path.EdgeIDs, edge.ID) && edge.From == path.Dialer && edge.To == "postgres" {
			if selected.ID != "" {
				return Slice6PostgresAuthority{}, ErrInvalidProfile
			}
			selected = edge
		}
		if slices.Contains(path.EdgeIDs, edge.ID) && edge.From == owner && edge.To == "postgres" {
			if peer.ID != "" {
				return Slice6PostgresAuthority{}, ErrInvalidProfile
			}
			peer = edge
		}
	}
	if selected.ID == "" || peer.ID == "" || peer.FromPrincipalDigest == "" ||
		peer.Protocol != "postgres" || peer.Port != 5432 || peer.ServerAnchorID != "external-server-ca" ||
		peer.ClientAnchorID != "" || peer.Authentication != "mtls" || !peer.CrossDomain ||
		selected.Protocol != "postgres" || selected.Port != 5432 ||
		selected.ServerAnchorID != "external-server-ca" || selected.ClientAnchorID != "" ||
		selected.Authentication != "mtls" || !selected.CrossDomain ||
		selected.ExternalIdentityDigest != service.IdentityDigest {
		return Slice6PostgresAuthority{}, ErrInvalidProfile
	}
	serverAnchor, clientAnchor, err := p.EdgeTrustAnchors(selected.ID)
	if err != nil || serverAnchor.ID != "external-server-ca" || clientAnchor.ID != "" {
		return Slice6PostgresAuthority{}, ErrInvalidProfile
	}
	brokerOnly := owner == "provider-browser-runtime" || owner == "provider-desktop-runtime"
	if brokerOnly != (path.Dialer != owner) {
		return Slice6PostgresAuthority{}, ErrInvalidProfile
	}
	return Slice6PostgresAuthority{Owner: owner, Dialer: path.Dialer, Network: path.Network,
		EdgeID: selected.ID, PeerEdgeID: peer.ID, SourceAddress: source, ServerAddress: server,
		ServerHost: service.DNSNames[0], ServerPort: selected.Port, ServerURI: service.URI,
		Database: rule.Database, SQLRole: rule.SQLRole, Migration: rule.Migration,
		BrokerOnly: brokerOnly, Signer: signer, ServerAnchor: serverAnchor}, nil
}

// IsSlice6FinalPostgresPeerEdge distinguishes the logical client's inner
// PostgreSQL TLS peer from a Browser/Desktop broker's physical dial edge.
// Only the PostgreSQL-purpose signer may request CRL reads on this edge.
func (p Profile) IsSlice6FinalPostgresPeerEdge(edgeID, localPrincipalDigest string) bool {
	for _, target := range Slice6DesiredFinalPostgresSignerTargets() {
		var principal Principal
		for _, candidate := range p.Principals {
			if candidate.Name == target.SubjectDeployment {
				principal = candidate
				break
			}
		}
		if principal.PrincipalDigest != localPrincipalDigest || principal.Name == "" {
			continue
		}
		authority, err := p.ResolveSlice6FinalPostgresAuthority(target.SubjectDeployment)
		return err == nil && authority.PeerEdgeID == edgeID
	}
	return false
}
