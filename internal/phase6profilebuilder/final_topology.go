package phase6profilebuilder

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidFinalTopologyDraft = errors.New("invalid Phase 6 Slice 6 final topology draft")

// FinalTopologyDraft binds the reviewed five external identities and 32
// physical service paths to the final 37-edge graph. It still lacks the
// controller/key, SQL, ingress, egress and remaining process configuration;
// it must never be passed to a launcher as a complete security profile.
type FinalTopologyDraft struct {
	TrustDraft
	External       []phase6security.ExternalService
	TrustEdges     []phase6security.TrustEdge
	ExternalSupply ExternalImageSupply
}

// BindSlice6FinalTopologyDraft reopens both operator CA files and every OCI
// archive before combining their checked bytes with reviewed network policy.
// The final freeze must independently reopen all original source inputs again.
func BindSlice6FinalTopologyDraft(ctx context.Context, draft TrustDraft,
	external ExternalImageSupply, now time.Time) (FinalTopologyDraft, error) {
	if ctx == nil || ctx.Err() != nil || draft.AnchorSupply.VerifySources(now) != nil ||
		external.VerifySources(ctx) != nil {
		return FinalTopologyDraft{}, ErrInvalidFinalTopologyDraft
	}
	return bindSlice6FinalTopologyDraft(draft, external)
}

func bindSlice6FinalTopologyDraft(draft TrustDraft, external ExternalImageSupply) (FinalTopologyDraft, error) {
	if draft.Supply.VerifyProfilePolicies(phase6security.Profile{Principals: draft.Principals}) != nil ||
		!reflect.DeepEqual(draft.Networks, phase6security.Slice6DesiredNetworks()) ||
		len(draft.Principals) != len(phase6security.Slice6DesiredDeploymentNames()) ||
		len(draft.TrustAnchors) != len(phase6security.Slice6DesiredFinalTrustAnchorTemplates()) ||
		phase6security.VerifySlice6DesiredFinalNetworks(phase6security.Slice6DesiredFinalNetworks()) != nil {
		return FinalTopologyDraft{}, ErrInvalidFinalTopologyDraft
	}
	for index, name := range phase6security.Slice6DesiredDeploymentNames() {
		principal := draft.Principals[index]
		if principal.Name != name {
			return FinalTopologyDraft{}, ErrInvalidFinalTopologyDraft
		}
		tls, err := phase6security.Slice6DesiredTLSIdentity(name, principal.PrincipalDigest)
		if err != nil || !reflect.DeepEqual(principal.TLS, tls) {
			return FinalTopologyDraft{}, ErrInvalidFinalTopologyDraft
		}
	}
	for index, template := range phase6security.Slice6DesiredFinalTrustAnchorTemplates() {
		actual := draft.TrustAnchors[index]
		bundle, err := draft.AnchorSupply.BundleBytes(template.ID)
		if err != nil || actual.BundleDigest != digestSlice6Bytes(bundle) {
			return FinalTopologyDraft{}, ErrInvalidFinalTopologyDraft
		}
		actual.BundleDigest = ""
		if !reflect.DeepEqual(actual, template) {
			return FinalTopologyDraft{}, ErrInvalidFinalTopologyDraft
		}
	}
	for _, principal := range draft.Principals {
		for _, anchor := range draft.TrustAnchors {
			count := 0
			for _, mount := range principal.Mounts {
				if mount.Kind == "trust_anchor" && mount.StorageID == anchor.StorageID &&
					mount.Target == anchor.TargetPath && mount.ReadOnly {
					count++
				}
			}
			want := 0
			if slices.Contains(anchor.Consumers, principal.Name) {
				want = 1
			}
			if count != want {
				return FinalTopologyDraft{}, ErrInvalidFinalTopologyDraft
			}
		}
		for _, mount := range principal.Mounts {
			if mount.Kind != "trust_anchor" {
				continue
			}
			known := false
			for _, anchor := range draft.TrustAnchors {
				if mount.StorageID == anchor.StorageID && mount.Target == anchor.TargetPath &&
					mount.ReadOnly && slices.Contains(anchor.Consumers, principal.Name) {
					known = true
				}
			}
			if !known {
				return FinalTopologyDraft{}, ErrInvalidFinalTopologyDraft
			}
		}
	}
	services, err := external.BindExternalServices()
	if err != nil || len(services) != len(phase6security.Slice6DesiredExternalServiceNames()) ||
		external.platform != draft.Principals[0].ImagePlatform {
		return FinalTopologyDraft{}, ErrInvalidFinalTopologyDraft
	}
	paths := phase6security.Slice6DesiredFinalExternalTransports()
	finalNetworks := phase6security.Slice6DesiredFinalNetworks()
	principalIndexes := make(map[string]int, len(draft.Principals))
	bound := draft
	bound.Principals = append([]phase6security.Principal(nil), draft.Principals...)
	bound.Networks = finalNetworks
	for index := range bound.Principals {
		principal := &bound.Principals[index]
		principalIndexes[principal.Name] = index
		principal.Networks = nil
		for _, network := range finalNetworks {
			if slices.Contains(network.Principals, principal.Name) {
				principal.Networks = append(principal.Networks, network.Name)
			}
		}
		if len(principal.Networks) == 0 {
			return FinalTopologyDraft{}, ErrInvalidFinalTopologyDraft
		}
	}
	serviceIndexes := make(map[string]int, len(services))
	for index := range services {
		serviceIndexes[services[index].Name] = index
		services[index].Networks = nil
		for _, network := range finalNetworks {
			if slices.Contains(network.ExternalServices, services[index].Name) {
				services[index].Networks = append(services[index].Networks, network.Name)
			}
		}
		services[index].IngressEdges = nil
	}
	for _, path := range paths {
		serviceIndex, serviceFound := serviceIndexes[path.Service]
		principalIndex, principalFound := principalIndexes[path.Dialer]
		if !serviceFound || !principalFound ||
			!slices.Contains(services[serviceIndex].Networks, path.Network) ||
			!slices.Contains(bound.Principals[principalIndex].Networks, path.Network) {
			return FinalTopologyDraft{}, ErrInvalidFinalTopologyDraft
		}
		services[serviceIndex].IngressEdges = append(services[serviceIndex].IngressEdges, path.EdgeIDs...)
	}
	for index := range services {
		sort.Strings(services[index].IngressEdges)
		for edgeIndex, id := range services[index].IngressEdges {
			if id == "" || edgeIndex > 0 && id == services[index].IngressEdges[edgeIndex-1] {
				return FinalTopologyDraft{}, ErrInvalidFinalTopologyDraft
			}
		}
		services[index].IdentityDigest = services[index].Digest()
	}
	edges, err := phase6security.BuildSlice6DesiredFinalTrustEdges(bound.Principals, services)
	if err != nil {
		return FinalTopologyDraft{}, ErrInvalidFinalTopologyDraft
	}
	return FinalTopologyDraft{TrustDraft: bound, External: services, TrustEdges: edges,
		ExternalSupply: external}, nil
}
