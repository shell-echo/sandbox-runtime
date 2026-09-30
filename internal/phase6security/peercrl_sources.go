package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

const PeerCRLSourcesProtocolID = "sandbox-runtime.phase6-peer-crl-sources.v1"

var peerCRLIssuerIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidSlice6IssuerID accepts only an immutable, canonical Vault issuer UUID.
func ValidSlice6IssuerID(value string) bool {
	return peerCRLIssuerIDPattern.MatchString(value)
}

// PeerCRLSources is a closed operator document bound to one canonical
// security-profile revision. It does not grant an agent a Vault URL or token.
// The existing certificate controller owns all fixed issuer-source reads.
type PeerCRLSources struct {
	Protocol                    string               `json:"protocol"`
	SecurityProfileDigest       string               `json:"security_profile_digest"`
	VaultExternalIdentityDigest string               `json:"vault_external_identity_digest"`
	Sources                     []PeerCRLSource      `json:"sources"`
	Edges                       []PeerCRLEdgeBinding `json:"edges"`
}

type PeerCRLSource struct {
	ID           string `json:"id"`
	Mount        string `json:"mount"`
	IssuerID     string `json:"issuer_id"`
	IssuerDigest string `json:"issuer_digest"`
}

type PeerCRLEdgeBinding struct {
	EdgeID               string `json:"edge_id"`
	LocalPrincipalDigest string `json:"local_principal_digest"`
	Direction            string `json:"direction"`
	PeerAnchorID         string `json:"peer_anchor_id"`
	SourceID             string `json:"source_id"`
}

// VerifyPeerCRLSourcesFile reads the fixed operator mapping as a private,
// bounded regular file. Both controller and role-owned agent must load the
// same canonical document pinned to the security profile.
func VerifyPeerCRLSourcesFile(path string, profile Profile) (PeerCRLSources, error) {
	document, err := secretfile.Read(path, 128<<10)
	if err != nil {
		return PeerCRLSources{}, ErrInvalidProfile
	}
	defer clear(document)
	return DecodePeerCRLSources(document, profile)
}

func DecodePeerCRLSources(document []byte, profile Profile) (PeerCRLSources, error) {
	if len(document) < 1 || len(document) > 128<<10 || rejectDuplicateMembers(document) != nil {
		return PeerCRLSources{}, ErrInvalidProfile
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var value PeerCRLSources
	if decoder.Decode(&value) != nil {
		return PeerCRLSources{}, ErrInvalidProfile
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PeerCRLSources{}, ErrInvalidProfile
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, document) || value.Validate(profile) != nil {
		return PeerCRLSources{}, ErrInvalidProfile
	}
	return value, nil
}

func (p PeerCRLSources) Validate(profile Profile) error {
	if profile.Validate() != nil || p.Protocol != PeerCRLSourcesProtocolID ||
		p.SecurityProfileDigest != profile.ProfileDigest ||
		len(p.Sources) < 1 || len(p.Sources) > 128 || len(p.Edges) < 1 || len(p.Edges) > 512 {
		return ErrInvalidProfile
	}
	vaultFound, vaultEdgeFound := false, false
	for _, external := range profile.External {
		if external.Name == "vault" && external.IdentityDigest == p.VaultExternalIdentityDigest {
			vaultFound = true
		}
	}
	for _, edge := range profile.TrustEdges {
		if edge.ID == "certificate-vault" && edge.From == "certificate-controller" && edge.To == "vault" &&
			edge.Authentication == "mtls" {
			vaultEdgeFound = true
		}
	}
	if !vaultFound || !vaultEdgeFound {
		return ErrInvalidProfile
	}
	sources := make(map[string]PeerCRLSource, len(p.Sources))
	locations := make(map[string]bool, len(p.Sources))
	previous := ""
	for _, source := range p.Sources {
		location := source.Mount + "/" + source.IssuerID
		if source.ID <= previous || !namePattern.MatchString(source.ID) || !namePattern.MatchString(source.Mount) ||
			!peerCRLIssuerIDPattern.MatchString(source.IssuerID) || !digestPattern.MatchString(source.IssuerDigest) ||
			locations[location] {
			return ErrInvalidProfile
		}
		previous = source.ID
		locations[location] = true
		sources[source.ID] = source
	}
	used := make(map[string]bool, len(sources))
	previous = ""
	for _, binding := range p.Edges {
		key := binding.EdgeID + "/" + binding.LocalPrincipalDigest + "/" + binding.Direction
		source, known := sources[binding.SourceID]
		if key <= previous || !known || !digestPattern.MatchString(binding.LocalPrincipalDigest) {
			return ErrInvalidProfile
		}
		previous = key
		var edge TrustEdge
		for _, candidate := range profile.TrustEdges {
			if candidate.ID == binding.EdgeID {
				edge = candidate
				break
			}
		}
		postgresPeer := edge.ClientAnchorID == "" && binding.Direction == "outbound" &&
			profile.IsSlice6FinalPostgresPeerEdge(edge.ID, binding.LocalPrincipalDigest)
		dnsPeer := edge.ClientAnchorID == "" &&
			profile.IsSlice6DNSPeerEdge(edge.ID, binding.LocalPrincipalDigest, binding.Direction)
		if edge.ID == "" || edge.Authentication != "mtls" ||
			(edge.ClientAnchorID == "" && !postgresPeer && !dnsPeer) || binding.SourceID != source.ID {
			return ErrInvalidProfile
		}
		localName, anchorID := "", ""
		switch binding.Direction {
		case "outbound":
			localName, anchorID = edge.From, edge.ServerAnchorID
			if binding.LocalPrincipalDigest != edge.FromPrincipalDigest {
				return ErrInvalidProfile
			}
		case "inbound":
			localName, anchorID = edge.To, edge.ClientAnchorID
			if binding.LocalPrincipalDigest != edge.ToPrincipalDigest {
				return ErrInvalidProfile
			}
		default:
			return ErrInvalidProfile
		}
		if binding.PeerAnchorID != anchorID ||
			(!postgresPeer && !localAgentOwnsEdge(profile, localName, binding.LocalPrincipalDigest)) ||
			(postgresPeer && edge.From != localName) {
			return ErrInvalidProfile
		}
		used[source.ID] = true
	}
	for sourceID := range sources {
		if !used[sourceID] {
			return ErrInvalidProfile
		}
	}
	return nil
}

func localAgentOwnsEdge(profile Profile, localName, principalDigest string) bool {
	for _, binding := range profile.TLSAgentBindings {
		if binding.SubjectDeployment == localName && binding.SubjectPrincipalDigest == principalDigest {
			return true
		}
	}
	return false
}

// Resolve uses only a validated edge/local-role/direction tuple and actual
// issuer DER from the TLS-verified peer chain. SourceID is never caller input.
func (p PeerCRLSources) Resolve(profile Profile, edgeID, localPrincipalDigest, direction, peerAnchorID string,
	issuerDER []byte) (PeerCRLSource, error) {
	if len(issuerDER) == 0 || len(issuerDER) > 64<<10 {
		return PeerCRLSource{}, ErrInvalidProfile
	}
	issuerHash := sha256.Sum256(issuerDER)
	issuerDigest := "sha256:" + hex.EncodeToString(issuerHash[:])
	sourceID, err := p.AuthorizedSourceID(profile, edgeID, localPrincipalDigest, direction, peerAnchorID, issuerDigest)
	if err != nil {
		return PeerCRLSource{}, err
	}
	for _, source := range p.Sources {
		if source.ID == sourceID {
			return source, nil
		}
	}
	return PeerCRLSource{}, ErrInvalidProfile
}

// AuthorizedSourceID is the only lookup the role-owned TLS agent needs.
// It exposes neither Vault mount nor issuer reference; the certificate
// controller independently resolves and reauthorizes that fixed source.
func (p PeerCRLSources) AuthorizedSourceID(profile Profile, edgeID, localPrincipalDigest, direction, peerAnchorID,
	issuerDigest string) (string, error) {
	if p.Validate(profile) != nil || !digestPattern.MatchString(issuerDigest) {
		return "", ErrInvalidProfile
	}
	for _, binding := range p.Edges {
		if binding.EdgeID != edgeID || binding.LocalPrincipalDigest != localPrincipalDigest ||
			binding.Direction != direction || binding.PeerAnchorID != peerAnchorID {
			continue
		}
		for _, source := range p.Sources {
			if source.ID == binding.SourceID && source.IssuerDigest == issuerDigest {
				return source.ID, nil
			}
		}
	}
	return "", ErrInvalidProfile
}
