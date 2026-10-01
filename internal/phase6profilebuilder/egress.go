package phase6profilebuilder

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidEgressDraft = errors.New("invalid Phase 6 Slice 6 egress draft")

// EgressKeySupply retains only the public half and private source path. The
// launcher must reopen the 0600 private source for the authority's FD 3;
// neither secret bytes nor host paths belong in the security profile.
type EgressKeySupply struct {
	paths map[string]string
	keys  map[string]ed25519.PublicKey
}

type EgressDraft struct {
	FinalTopologyDraft
	EgressPolicies []phase6security.EgressPolicy
	EgressKeys     EgressKeySupply
}

// LoadSlice6EgressKeySupply accepts only the five reviewed key owners. Key
// files are raw, self-consistent Ed25519 private keys in a 0700 directory.
func LoadSlice6EgressKeySupply(paths map[string]string) (EgressKeySupply, error) {
	names := phase6security.Slice6DesiredEgressAuthorityNames()
	if len(paths) != len(names) {
		return EgressKeySupply{}, ErrInvalidEgressDraft
	}
	supply := EgressKeySupply{paths: make(map[string]string, len(names)), keys: make(map[string]ed25519.PublicKey, len(names))}
	seenPaths := make(map[string]bool, len(names))
	for _, name := range names {
		path, found := paths[name]
		if !found || seenPaths[path] {
			return EgressKeySupply{}, ErrInvalidEgressDraft
		}
		seenPaths[path] = true
		key, err := readSlice6OperatorPrivateKey(path)
		if err != nil {
			return EgressKeySupply{}, err
		}
		supply.paths[name], supply.keys[name] = path, key
	}
	return supply, nil
}

func (s EgressKeySupply) VerifySources() error {
	names := phase6security.Slice6DesiredEgressAuthorityNames()
	if len(s.paths) != len(names) || len(s.keys) != len(names) {
		return ErrInvalidEgressDraft
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		path, pathOK := s.paths[name]
		previous, keyOK := s.keys[name]
		if !pathOK || !keyOK || seen[path] || len(previous) != ed25519.PublicKeySize {
			return ErrInvalidEgressDraft
		}
		seen[path] = true
		current, err := readSlice6OperatorPrivateKey(path)
		if err != nil || !bytes.Equal(current, previous) {
			return ErrInvalidEgressDraft
		}
	}
	return nil
}

func (s EgressKeySupply) publicKeys() map[string]ed25519.PublicKey {
	result := make(map[string]ed25519.PublicKey, len(s.keys))
	for name, key := range s.keys {
		result[name] = bytes.Clone(key)
	}
	return result
}

// VerifySources checks all earlier image, resource, CA and external archive
// inputs again, as well as the private key sources. This is not a live gate.
func (d EgressDraft) VerifySources(ctx context.Context, now time.Time) error {
	if d.FinalTopologyDraft.VerifySources(ctx, now) != nil || d.EgressKeys.VerifySources() != nil {
		return ErrInvalidEgressDraft
	}
	expected, err := phase6security.BuildSlice6DesiredEgressPolicies(d.Principals, d.EgressKeys.publicKeys())
	if err != nil || !reflect.DeepEqual(d.EgressPolicies, expected) || !slice6BoundEgressMatches(d.Principals, d.TrustEdges, expected) {
		return ErrInvalidEgressDraft
	}
	return nil
}

func BindSlice6EgressDraft(ctx context.Context, draft FinalTopologyDraft,
	keys EgressKeySupply, now time.Time) (EgressDraft, error) {
	if draft.VerifySources(ctx, now) != nil || keys.VerifySources() != nil {
		return EgressDraft{}, ErrInvalidEgressDraft
	}
	return bindSlice6EgressDraft(draft, keys)
}

func bindSlice6EgressDraft(draft FinalTopologyDraft, keys EgressKeySupply) (EgressDraft, error) {
	policies, err := phase6security.BuildSlice6DesiredEgressPolicies(draft.Principals, keys.publicKeys())
	if err != nil || len(policies) != 5 || len(draft.TrustEdges) != 144 {
		return EgressDraft{}, ErrInvalidEgressDraft
	}
	bound := draft
	bound.Principals = append([]phase6security.Principal(nil), draft.Principals...)
	indexes := make(map[string]int, len(bound.Principals))
	for index := range bound.Principals {
		principal := &bound.Principals[index]
		indexes[principal.Name] = index
		principal.Mounts = slices.Clone(principal.Mounts)
		principal.Listeners = slices.Clone(principal.Listeners)
	}
	for _, policy := range policies {
		brokerIndex, brokerOK := indexes[policy.Broker]
		authorityIndex, authorityOK := indexes[policy.Authority.DeploymentName]
		if !brokerOK || !authorityOK || !slice6EgressEdgesBound(draft.TrustEdges, policy) ||
			len(bound.Principals[brokerIndex].Listeners) != 0 {
			return EgressDraft{}, ErrInvalidEgressDraft
		}
		for _, principal := range bound.Principals {
			for _, mount := range principal.Mounts {
				if mount.StorageID == policy.Authority.SocketStorageID ||
					mount.StorageID == policy.Authority.LedgerStorageID ||
					overlappingMountTarget(mount.Target, policy.Authority.SocketDirectory) ||
					overlappingMountTarget(mount.Target, policy.Authority.LedgerMountTarget) {
					return EgressDraft{}, ErrInvalidEgressDraft
				}
			}
		}
		bound.Principals[brokerIndex].Listeners = []phase6security.Listener{{Name: "egress", Protocol: "tcp", Port: 8443, Exposure: "trust_edge"}}
		bound.Principals[brokerIndex].Mounts = append(bound.Principals[brokerIndex].Mounts,
			phase6security.Mount{Target: policy.Authority.SocketDirectory, Kind: "private_socket", ReadOnly: true,
				StorageID: policy.Authority.SocketStorageID})
		bound.Principals[authorityIndex].Mounts = append(bound.Principals[authorityIndex].Mounts,
			phase6security.Mount{Target: policy.Authority.SocketDirectory, Kind: "private_socket",
				StorageID: policy.Authority.SocketStorageID},
			phase6security.Mount{Target: policy.Authority.LedgerMountTarget, Kind: "persistent_ledger", MaxBytes: 1 << 20,
				StorageID: policy.Authority.LedgerStorageID})
	}
	if !slice6BoundEgressMatches(bound.Principals, bound.TrustEdges, policies) {
		return EgressDraft{}, ErrInvalidEgressDraft
	}
	return EgressDraft{FinalTopologyDraft: bound, EgressPolicies: policies, EgressKeys: keys}, nil
}

func slice6BoundEgressMatches(principals []phase6security.Principal, edges []phase6security.TrustEdge,
	policies []phase6security.EgressPolicy) bool {
	if len(policies) != 5 {
		return false
	}
	byName := make(map[string]phase6security.Principal, len(principals))
	for _, principal := range principals {
		if _, duplicate := byName[principal.Name]; duplicate {
			return false
		}
		byName[principal.Name] = principal
	}
	for _, policy := range policies {
		broker, brokerOK := byName[policy.Broker]
		authority, authorityOK := byName[policy.Authority.DeploymentName]
		if !brokerOK || !authorityOK || !slice6EgressEdgesBound(edges, policy) ||
			len(broker.Listeners) != 1 || broker.Listeners[0] != (phase6security.Listener{Name: "egress", Protocol: "tcp", Port: 8443, Exposure: "trust_edge"}) ||
			!slice6ExactMount(broker, "private_socket", policy.Authority.SocketDirectory, policy.Authority.SocketStorageID, true) ||
			!slice6ExactMount(authority, "private_socket", policy.Authority.SocketDirectory, policy.Authority.SocketStorageID, false) ||
			!slice6ExactMount(authority, "persistent_ledger", policy.Authority.LedgerMountTarget, policy.Authority.LedgerStorageID, false) {
			return false
		}
		for _, principal := range principals {
			for _, mount := range principal.Mounts {
				if mount.StorageID != policy.Authority.SocketStorageID && mount.StorageID != policy.Authority.LedgerStorageID &&
					!overlappingMountTarget(mount.Target, policy.Authority.SocketDirectory) &&
					!overlappingMountTarget(mount.Target, policy.Authority.LedgerMountTarget) {
					continue
				}
				allowed := principal.Name == policy.Broker && mount == (phase6security.Mount{Target: policy.Authority.SocketDirectory,
					Kind: "private_socket", ReadOnly: true, StorageID: policy.Authority.SocketStorageID}) ||
					principal.Name == policy.Authority.DeploymentName && (mount == (phase6security.Mount{Target: policy.Authority.SocketDirectory,
						Kind: "private_socket", StorageID: policy.Authority.SocketStorageID}) ||
						mount == (phase6security.Mount{Target: policy.Authority.LedgerMountTarget,
							Kind: "persistent_ledger", MaxBytes: 1 << 20, StorageID: policy.Authority.LedgerStorageID}))
				if !allowed {
					return false
				}
			}
		}
	}
	return true
}

func slice6ExactMount(principal phase6security.Principal, kind, target, storageID string, readOnly bool) bool {
	count := 0
	for _, mount := range principal.Mounts {
		if mount.Target == target && mount.Kind == kind && mount.StorageID == storageID && mount.ReadOnly == readOnly {
			count++
		}
	}
	return count == 1
}

func slice6EgressEdgesBound(edges []phase6security.TrustEdge, policy phase6security.EgressPolicy) bool {
	role, unix := false, false
	for _, edge := range edges {
		if edge.From == policy.Principal && edge.To == policy.Broker && edge.Protocol == "tls" &&
			edge.Authentication == "mtls" && edge.Port == 8443 && edge.FromPrincipalDigest == policy.PrincipalDigest &&
			edge.ToPrincipalDigest == policy.BrokerDigest {
			role = true
		}
		if edge.From == policy.Broker && edge.To == policy.Authority.DeploymentName && edge.Protocol == "unix" &&
			edge.Authentication == "unix_peer_credentials" && edge.FromPrincipalDigest == policy.BrokerDigest &&
			edge.ToPrincipalDigest == policy.Authority.PrincipalDigest {
			unix = true
		}
	}
	return role && unix
}
