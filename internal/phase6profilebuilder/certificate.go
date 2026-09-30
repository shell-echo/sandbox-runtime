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

var ErrInvalidCertificateDraft = errors.New("invalid Phase 6 Slice 6 certificate draft")

// CertificateKeySupply is the closed set of production controller response,
// controller-managed request and agent request key sources. Only public
// halves are retained; the launcher must independently supply private FDs.
type CertificateKeySupply struct {
	paths map[string]string
	keys  map[string]ed25519.PublicKey
}

func LoadSlice6CertificateKeySupply(paths map[string]string) (CertificateKeySupply, error) {
	ids := phase6security.Slice6DesiredCertificateKeyIDs()
	if len(paths) != len(ids) {
		return CertificateKeySupply{}, ErrInvalidCertificateDraft
	}
	supply := CertificateKeySupply{paths: make(map[string]string, len(ids)), keys: make(map[string]ed25519.PublicKey, len(ids))}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		path, found := paths[id]
		if !found || seen[path] {
			return CertificateKeySupply{}, ErrInvalidCertificateDraft
		}
		seen[path] = true
		key, err := readSlice6OperatorPrivateKey(path)
		if err != nil {
			return CertificateKeySupply{}, ErrInvalidCertificateDraft
		}
		supply.paths[id], supply.keys[id] = path, key
	}
	return supply, nil
}

func (s CertificateKeySupply) VerifySources() error {
	ids := phase6security.Slice6DesiredCertificateKeyIDs()
	if len(s.paths) != len(ids) || len(s.keys) != len(ids) {
		return ErrInvalidCertificateDraft
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		path, pathOK := s.paths[id]
		previous, keyOK := s.keys[id]
		if !pathOK || !keyOK || seen[path] || len(previous) != ed25519.PublicKeySize {
			return ErrInvalidCertificateDraft
		}
		seen[path] = true
		current, err := readSlice6OperatorPrivateKey(path)
		if err != nil || !bytes.Equal(current, previous) {
			return ErrInvalidCertificateDraft
		}
	}
	return nil
}

func (s CertificateKeySupply) publicKeys() map[string]ed25519.PublicKey {
	result := make(map[string]ed25519.PublicKey, len(s.keys))
	for id, key := range s.keys {
		result[id] = bytes.Clone(key)
	}
	return result
}

type CertificateDraft struct {
	EgressDraft
	CertificateController phase6security.CertificateControllerAuthority
	TLSAgentBindings      []phase6security.TLSAgentBinding
	PostgresClientAgents  []phase6security.PostgresClientAgentBinding
	CertificateKeys       CertificateKeySupply
	base                  EgressDraft
}

func (d CertificateDraft) VerifySources(ctx context.Context, now time.Time) error {
	if d.base.VerifySources(ctx, now) != nil || d.CertificateKeys.VerifySources() != nil {
		return ErrInvalidCertificateDraft
	}
	want, err := bindSlice6CertificateDraft(d.base, d.CertificateKeys)
	if err != nil || !reflect.DeepEqual(d.EgressDraft, want.EgressDraft) ||
		!reflect.DeepEqual(d.CertificateController, want.CertificateController) ||
		!reflect.DeepEqual(d.TLSAgentBindings, want.TLSAgentBindings) ||
		!reflect.DeepEqual(d.PostgresClientAgents, want.PostgresClientAgents) {
		return ErrInvalidCertificateDraft
	}
	return nil
}

func BindSlice6CertificateDraft(ctx context.Context, draft EgressDraft,
	keys CertificateKeySupply, now time.Time) (CertificateDraft, error) {
	if draft.VerifySources(ctx, now) != nil || keys.VerifySources() != nil {
		return CertificateDraft{}, ErrInvalidCertificateDraft
	}
	return bindSlice6CertificateDraft(draft, keys)
}

func bindSlice6CertificateDraft(draft EgressDraft, keys CertificateKeySupply) (CertificateDraft, error) {
	for _, egressKey := range draft.EgressKeys.keys {
		for _, certificateKey := range keys.keys {
			if bytes.Equal(egressKey, certificateKey) {
				return CertificateDraft{}, ErrInvalidCertificateDraft
			}
		}
	}
	bindings, err := phase6security.BuildSlice6DesiredCertificateBindings(draft.Principals, keys.publicKeys())
	if err != nil {
		return CertificateDraft{}, ErrInvalidCertificateDraft
	}
	bound := draft
	bound.Principals = slices.Clone(draft.Principals)
	indexes := make(map[string]int, len(bound.Principals))
	for index := range bound.Principals {
		indexes[bound.Principals[index].Name] = index
		bound.Principals[index].Mounts = slices.Clone(bound.Principals[index].Mounts)
	}
	createdStorage := make(map[string]int)
	attach := func(deployment string, mount phase6security.Mount) bool {
		index, found := indexes[deployment]
		if !found || createdStorage[mount.StorageID] >= 2 {
			return false
		}
		for _, principal := range bound.Principals {
			for _, existing := range principal.Mounts {
				if existing.StorageID == mount.StorageID || overlappingMountTarget(existing.Target, mount.Target) {
					// Only the reviewed peer may reuse this exact storage and path.
					if existing.StorageID != mount.StorageID || existing.Target != mount.Target ||
						existing.Kind != mount.Kind || principal.Name == deployment ||
						createdStorage[mount.StorageID] != 1 || existing.ReadOnly == mount.ReadOnly {
						return false
					}
				}
			}
		}
		bound.Principals[index].Mounts = append(bound.Principals[index].Mounts, mount)
		createdStorage[mount.StorageID]++
		return true
	}
	controller := bindings.Controller
	if !slice6CertificateEdge(draft.TrustEdges, controller.SelfUnixEdgeID, controller.DeploymentName, controller.DeploymentName) ||
		!slice6CertificateEdge(draft.TrustEdges, controller.CredentialController.UnixEdgeID,
			"workload-credential-controller", controller.DeploymentName) ||
		!attach(controller.DeploymentName, phase6security.Mount{Target: controller.SelfSocketDirectory,
			Kind: "private_socket", StorageID: controller.SelfSocketStorageID}) ||
		!attach(controller.DeploymentName, phase6security.Mount{Target: controller.CredentialController.SocketDirectory,
			Kind: "private_socket", StorageID: controller.CredentialController.SocketStorageID}) ||
		!attach("workload-credential-controller", phase6security.Mount{Target: controller.CredentialController.SocketDirectory,
			Kind: "private_socket", ReadOnly: true, StorageID: controller.CredentialController.SocketStorageID}) {
		return CertificateDraft{}, ErrInvalidCertificateDraft
	}
	all := slices.Clone(bindings.Ordinary)
	for _, postgres := range bindings.Postgres {
		all = append(all, postgres.TLSAgentBinding)
	}
	for _, binding := range all {
		if !slice6CertificateEdge(draft.TrustEdges, binding.UnixEdgeID, binding.SubjectDeployment, binding.AgentDeployment) ||
			!slice6CertificateEdge(draft.TrustEdges, binding.ControllerUnixEdgeID, binding.AgentDeployment, controller.DeploymentName) ||
			!attach(binding.AgentDeployment, phase6security.Mount{Target: binding.SocketDirectory,
				Kind: "private_socket", StorageID: binding.SocketStorageID}) ||
			!attach(binding.SubjectDeployment, phase6security.Mount{Target: binding.SocketDirectory,
				Kind: "private_socket", ReadOnly: true, StorageID: binding.SocketStorageID}) ||
			!attach(controller.DeploymentName, phase6security.Mount{Target: binding.ControllerSocketDirectory,
				Kind: "private_socket", StorageID: binding.ControllerSocketStorageID}) ||
			!attach(binding.AgentDeployment, phase6security.Mount{Target: binding.ControllerSocketDirectory,
				Kind: "private_socket", ReadOnly: true, StorageID: binding.ControllerSocketStorageID}) {
			return CertificateDraft{}, ErrInvalidCertificateDraft
		}
	}
	return CertificateDraft{EgressDraft: bound, CertificateController: controller,
		TLSAgentBindings: bindings.Ordinary, PostgresClientAgents: bindings.Postgres,
		CertificateKeys: keys, base: draft}, nil
}

func slice6CertificateEdge(edges []phase6security.TrustEdge, id, from, to string) bool {
	for _, edge := range edges {
		if edge.ID == id {
			return edge.From == from && edge.To == to && edge.Protocol == "unix" &&
				edge.Authentication == "unix_peer_credentials" && edge.TenantScope == "system" &&
				edge.MaxConnectionSeconds <= 30
		}
	}
	return false
}
