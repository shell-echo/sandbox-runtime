package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

const PeerCRLRoleProtocolID = "sandbox-runtime.phase6-peer-crl-role.v1"

// PeerCRLRoleDocument is the minimal role-readable derivative of the
// operator's full source mapping. It contains no Vault mount, UUID, URL,
// credential or backend locator. The controller and agent keep the full
// document and independently authorize every read.
type PeerCRLRoleDocument struct {
	Protocol              string                   `json:"protocol"`
	SecurityProfileDigest string                   `json:"security_profile_digest"`
	SourceMappingDigest   string                   `json:"source_mapping_digest"`
	LocalPrincipalDigest  string                   `json:"local_principal_digest"`
	Edges                 []PeerCRLRoleEdgeBinding `json:"edges"`
}

type PeerCRLRoleEdgeBinding struct {
	EdgeID       string `json:"edge_id"`
	Direction    string `json:"direction"`
	PeerAnchorID string `json:"peer_anchor_id"`
	IssuerDigest string `json:"issuer_digest"`
}

func (d PeerCRLRoleDocument) Digest() string {
	document, _ := json.Marshal(d)
	hash := sha256.Sum256(append([]byte("sandbox-runtime/phase6-peer-crl-role/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(hash[:])
}

func (p PeerCRLSources) Digest() string {
	document, _ := json.Marshal(p)
	hash := sha256.Sum256(append([]byte("sandbox-runtime/phase6-peer-crl-sources/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(hash[:])
}

func DerivePeerCRLRoleDocument(profile Profile, sources PeerCRLSources, localPrincipalDigest string) (PeerCRLRoleDocument, error) {
	if sources.Validate(profile) != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	required, err := peerCRLRoleRequiredEdges(profile, localPrincipalDigest)
	if err != nil {
		return PeerCRLRoleDocument{}, err
	}
	document := PeerCRLRoleDocument{Protocol: PeerCRLRoleProtocolID, SecurityProfileDigest: profile.ProfileDigest,
		SourceMappingDigest: sources.Digest(), LocalPrincipalDigest: localPrincipalDigest,
		Edges: make([]PeerCRLRoleEdgeBinding, 0, len(required))}
	for _, bound := range required {
		matched := false
		for _, authorized := range sources.Edges {
			if authorized.EdgeID != bound.EdgeID || authorized.LocalPrincipalDigest != localPrincipalDigest ||
				authorized.Direction != bound.Direction || authorized.PeerAnchorID != bound.PeerAnchorID {
				continue
			}
			for _, source := range sources.Sources {
				if source.ID == authorized.SourceID {
					bound.IssuerDigest = source.IssuerDigest
					matched = true
					break
				}
			}
		}
		if !matched {
			return PeerCRLRoleDocument{}, ErrInvalidProfile
		}
		document.Edges = append(document.Edges, bound)
	}
	if document.Validate(profile, sources.Digest()) != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	return document, nil
}

func (d PeerCRLRoleDocument) Validate(profile Profile, expectedMappingDigest string) error {
	if profile.Validate() != nil || d.Protocol != PeerCRLRoleProtocolID ||
		d.SecurityProfileDigest != profile.ProfileDigest || !digestPattern.MatchString(expectedMappingDigest) ||
		d.SourceMappingDigest != expectedMappingDigest || len(d.Edges) < 1 || len(d.Edges) > 512 {
		return ErrInvalidProfile
	}
	required, err := peerCRLRoleRequiredEdges(profile, d.LocalPrincipalDigest)
	if err != nil || len(required) != len(d.Edges) {
		return ErrInvalidProfile
	}
	for index, actual := range d.Edges {
		if actual.EdgeID != required[index].EdgeID || actual.Direction != required[index].Direction ||
			actual.PeerAnchorID != required[index].PeerAnchorID || !digestPattern.MatchString(actual.IssuerDigest) {
			return ErrInvalidProfile
		}
	}
	return nil
}

func (d PeerCRLRoleDocument) ValidateForPrincipal(profile Profile, expectedMappingDigest, expectedPrincipalDigest string) error {
	if d.LocalPrincipalDigest != expectedPrincipalDigest {
		return ErrInvalidProfile
	}
	return d.Validate(profile, expectedMappingDigest)
}

func peerCRLRoleRequiredEdges(profile Profile, localPrincipalDigest string) ([]PeerCRLRoleEdgeBinding, error) {
	localName := ""
	for _, binding := range profile.TLSAgentBindings {
		if binding.SubjectPrincipalDigest == localPrincipalDigest {
			if localName != "" {
				return nil, ErrInvalidProfile
			}
			localName = binding.SubjectDeployment
		}
	}
	if localName == "" {
		return nil, ErrInvalidProfile
	}
	result := make([]PeerCRLRoleEdgeBinding, 0)
	for _, edge := range profile.TrustEdges {
		if edge.Authentication != "mtls" || edge.ClientAnchorID == "" {
			continue
		}
		if edge.From == localName && edge.FromPrincipalDigest == localPrincipalDigest {
			result = append(result, PeerCRLRoleEdgeBinding{EdgeID: edge.ID, Direction: "outbound", PeerAnchorID: edge.ServerAnchorID})
		}
		if edge.To == localName && edge.ToPrincipalDigest == localPrincipalDigest {
			result = append(result, PeerCRLRoleEdgeBinding{EdgeID: edge.ID, Direction: "inbound", PeerAnchorID: edge.ClientAnchorID})
		}
	}
	if len(result) < 1 || len(result) > 512 {
		return nil, ErrInvalidProfile
	}
	slices.SortFunc(result, func(a, b PeerCRLRoleEdgeBinding) int {
		first, second := a.EdgeID+"/"+a.Direction, b.EdgeID+"/"+b.Direction
		if first < second {
			return -1
		}
		if first > second {
			return 1
		}
		return 0
	})
	for index := 1; index < len(result); index++ {
		if result[index].EdgeID == result[index-1].EdgeID && result[index].Direction == result[index-1].Direction {
			return nil, ErrInvalidProfile
		}
	}
	return result, nil
}

func DecodePeerCRLRoleDocument(document []byte, profile Profile, expectedMappingDigest, expectedRoleDigest string) (PeerCRLRoleDocument, error) {
	if len(document) < 1 || len(document) > 128<<10 || rejectDuplicateMembers(document) != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var value PeerCRLRoleDocument
	if decoder.Decode(&value) != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, document) || value.Validate(profile, expectedMappingDigest) != nil ||
		!digestPattern.MatchString(expectedRoleDigest) || value.Digest() != expectedRoleDigest {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	return value, nil
}

func VerifyPeerCRLRoleFile(path string, profile Profile, expectedMappingDigest, expectedRoleDigest string) (PeerCRLRoleDocument, error) {
	document, err := secretfile.Read(path, 128<<10)
	if err != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	defer clear(document)
	return DecodePeerCRLRoleDocument(document, profile, expectedMappingDigest, expectedRoleDigest)
}

func (d PeerCRLRoleDocument) Binding(edgeID, direction string) (PeerCRLRoleEdgeBinding, error) {
	for _, edge := range d.Edges {
		if edge.EdgeID == edgeID && edge.Direction == direction {
			return edge, nil
		}
	}
	return PeerCRLRoleEdgeBinding{}, ErrInvalidProfile
}
