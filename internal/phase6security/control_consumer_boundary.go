package phase6security

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
)

const ControlConsumerBoundaryProtocol = "sandbox-runtime.control-consumer-boundary.v1"

// ControlConsumerBoundary describes a HELD diagnostic projection, not a second
// permission registry or full service readiness. All authority remains in the
// canonical Profile. Only the two CAs used by Control are in this boundary.
type ControlConsumerBoundary struct {
	Protocol           string              `json:"protocol"`
	ProfileBytesDigest string              `json:"profile_bytes_digest"`
	Review             ControlSourceReview `json:"review"`
	Anchors            []TrustAnchor       `json:"anchors"`
	TLSAgent           TLSAgentBinding     `json:"tls_agent"`
	Endpoints          []ControlEndpointV2 `json:"endpoints"`
	Consumers          []Principal         `json:"consumers"`
	ExcludedAnchors    []string            `json:"excluded_anchors"`
}

func ReviewControlConsumerBoundary(document []byte) (ControlConsumerBoundary, error) {
	return reviewControlConsumerBoundary(document, false)
}

func reviewControlConsumerBoundary(document []byte, trustObservation bool) (ControlConsumerBoundary, error) {
	r, err := ReviewControlSourceProfile(document)
	if err != nil || !trustObservation && len(r.TrustAnchors) != 0 {
		return ControlConsumerBoundary{}, ErrInvalidProfile
	}
	p, err := decodeV2Canonical(document)
	if err != nil {
		return ControlConsumerBoundary{}, err
	}
	sum := sha256.Sum256(document)
	out := ControlConsumerBoundary{Protocol: ControlConsumerBoundaryProtocol, ProfileBytesDigest: "sha256:" + hex.EncodeToString(sum[:]), Review: r, Endpoints: slices.Clone(p.DockerControl.Endpoints)}
	names := map[string]bool{r.Control.Name: true}
	for _, a := range p.TrustAnchors {
		if a.ID != "internal-client-ca" && a.ID != "internal-server-ca" {
			out.ExcludedAnchors = append(out.ExcludedAnchors, a.ID)
			continue
		}
		if !slices.Contains(a.Consumers, r.Control.Name) {
			return ControlConsumerBoundary{}, ErrInvalidProfile
		}
		out.Anchors = append(out.Anchors, a)
		for _, n := range a.Consumers {
			names[n] = true
		}
	}
	if len(out.Anchors) != 2 {
		return ControlConsumerBoundary{}, ErrInvalidProfile
	}
	for _, e := range out.Endpoints {
		names[e.ProviderDeployment] = true
	}
	found := 0
	for _, a := range p.TLSAgentBindings {
		if a.SubjectDeployment == r.Control.Name {
			out.TLSAgent = a
			names[a.AgentDeployment] = true
			found++
		}
	}
	if found != 1 {
		return ControlConsumerBoundary{}, ErrInvalidProfile
	}
	for _, c := range p.Principals {
		if names[c.Name] {
			out.Consumers = append(out.Consumers, c)
			delete(names, c.Name)
		}
	}
	if len(names) != 0 {
		return ControlConsumerBoundary{}, ErrInvalidProfile
	}
	slices.SortFunc(out.Consumers, func(a, b Principal) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return out, nil
}

// Mounts returns the exact diagnostic projection: no unrelated role mounts.
// The actual TLS socket contents and CA bytes require their separate gates.
func (b ControlConsumerBoundary) Mounts(p Principal) []Mount {
	if p.Name == b.Review.Control.Name {
		return slices.Clone(p.Mounts)
	}
	var out []Mount
	for _, m := range p.Mounts {
		include := p.Name == b.TLSAgent.AgentDeployment && m.StorageID == b.TLSAgent.SocketStorageID
		for _, a := range b.Anchors {
			if slices.Contains(a.Consumers, p.Name) && m.Kind == "trust_anchor" && m.StorageID == a.StorageID && m.Target == trustAnchorMountTarget(a) && m.ReadOnly {
				include = true
			}
		}
		if include {
			out = append(out, m)
		}
	}
	return out
}
