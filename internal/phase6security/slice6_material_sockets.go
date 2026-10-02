package phase6security

import (
	"path"
	"slices"
	"strings"
)

const slice6MaterialSocketRoot = "/run/phase6/material"

// Slice6MaterialSocketBinding is the closed owner -> material-agent Unix
// authority. A 0710 directory owned by the agent with the owner's GID
// restricts traversal; a 0666 socket is then guarded by exact peer UID/GID.
// These draft Profile v1 fields are mandatory at the Slice 6 final gate.
type Slice6MaterialSocketBinding struct {
	AgentDeployment     string `json:"agent_deployment"`
	OwnerDeployment     string `json:"owner_deployment"`
	AgentUID            uint32 `json:"agent_uid"`
	AgentGID            uint32 `json:"agent_gid"`
	OwnerUID            uint32 `json:"owner_uid"`
	OwnerGID            uint32 `json:"owner_gid"`
	SocketDirectory     string `json:"socket_directory"`
	SocketStorageID     string `json:"socket_storage_id"`
	SocketPath          string `json:"socket_path"`
	DirectoryMode       uint32 `json:"directory_mode"`
	SocketMode          uint32 `json:"socket_mode"`
	FirstFrameSeconds   int    `json:"first_frame_seconds"`
	MaxOperationSeconds int    `json:"max_operation_seconds"`
	MaxConnections      int    `json:"max_connections"`
	CleanupClass        string `json:"cleanup_class"`
}

func slice6DesiredMaterialSocket(template slice6MaterialAccessTemplate, agent, owner Principal) Slice6MaterialSocketBinding {
	directory := path.Join(slice6MaterialSocketRoot, template.agent)
	return Slice6MaterialSocketBinding{AgentDeployment: template.agent, OwnerDeployment: template.owner,
		AgentUID: agent.UID, AgentGID: agent.GID, OwnerUID: owner.UID, OwnerGID: owner.GID,
		SocketDirectory: directory, SocketStorageID: "material-" + template.agent + "-socket",
		SocketPath: path.Join(directory, "agent.sock"), DirectoryMode: 0o710, SocketMode: 0o666,
		FirstFrameSeconds: 2, MaxOperationSeconds: 30, MaxConnections: 4, CleanupClass: "sockets"}
}

// AttachSlice6MaterialSocketBindings derives every mount and endpoint from
// the existing 11 agent/owner facts, before the Profile digest is frozen.
func AttachSlice6MaterialSocketBindings(principals []Principal) ([]Principal, []Slice6MaterialSocketBinding, error) {
	if len(slice6MaterialAccessTemplates) != 11 {
		return nil, nil, errSlice6DesiredInventory
	}
	result := slices.Clone(principals)
	byName := make(map[string]int, len(result))
	for index := range result {
		if _, duplicate := byName[result[index].Name]; duplicate {
			return nil, nil, errSlice6DesiredInventory
		}
		byName[result[index].Name] = index
		result[index].Mounts = slices.Clone(result[index].Mounts)
	}
	bindings := make([]Slice6MaterialSocketBinding, 0, len(slice6MaterialAccessTemplates))
	for _, template := range slice6MaterialAccessTemplates {
		agentIndex, agentOK := byName[template.agent]
		ownerIndex, ownerOK := byName[template.owner]
		if !agentOK || !ownerOK || result[agentIndex].Kind != "material_agent" ||
			(result[ownerIndex].Kind != "runtime" && result[ownerIndex].Kind != "migration_job") ||
			result[agentIndex].UID == result[ownerIndex].UID || result[agentIndex].GID == result[ownerIndex].GID {
			return nil, nil, errSlice6DesiredInventory
		}
		binding := slice6DesiredMaterialSocket(template, result[agentIndex], result[ownerIndex])
		result[agentIndex].Mounts = append(result[agentIndex].Mounts, Mount{Target: binding.SocketDirectory,
			Kind: "private_socket", StorageID: binding.SocketStorageID})
		result[ownerIndex].Mounts = append(result[ownerIndex].Mounts, Mount{Target: binding.SocketDirectory,
			Kind: "private_socket", StorageID: binding.SocketStorageID, ReadOnly: true})
		bindings = append(bindings, binding)
	}
	if VerifySlice6MaterialSocketBindings(Profile{Principals: result, MaterialSockets: bindings}) != nil {
		return nil, nil, errSlice6DesiredInventory
	}
	return result, bindings, nil
}

// VerifySlice6MaterialSocketBindings rejects missing, extra, aliased or
// cross-owner endpoints, including rewritten Profile digests.
func VerifySlice6MaterialSocketBindings(profile Profile) error {
	if len(profile.MaterialSockets) != len(slice6MaterialAccessTemplates) || len(slice6MaterialAccessTemplates) != 11 {
		return errSlice6DesiredInventory
	}
	byName := make(map[string]Principal, len(profile.Principals))
	for _, principal := range profile.Principals {
		if byName[principal.Name].Name != "" {
			return errSlice6DesiredInventory
		}
		byName[principal.Name] = principal
	}
	for index, template := range slice6MaterialAccessTemplates {
		agent, owner := byName[template.agent], byName[template.owner]
		if agent.Name == "" || owner.Name == "" || agent.Kind != "material_agent" ||
			(owner.Kind != "runtime" && owner.Kind != "migration_job") ||
			agent.UID == owner.UID || agent.GID == owner.GID ||
			profile.MaterialSockets[index] != slice6DesiredMaterialSocket(template, agent, owner) {
			return errSlice6DesiredInventory
		}
	}
	for _, binding := range profile.MaterialSockets {
		found := 0
		for _, principal := range profile.Principals {
			for _, mount := range principal.Mounts {
				if mount.StorageID == binding.SocketStorageID || mount.Target == binding.SocketDirectory ||
					strings.HasPrefix(mount.Target, binding.SocketDirectory+"/") ||
					strings.HasPrefix(binding.SocketDirectory, mount.Target+"/") {
					if !slice6MaterialSocketMember([]Slice6MaterialSocketBinding{binding}, principal.Name, mount) {
						return errSlice6DesiredInventory
					}
					found++
				}
			}
		}
		if found != 2 {
			return errSlice6DesiredInventory
		}
	}
	for _, principal := range profile.Principals {
		for _, mount := range principal.Mounts {
			if mount.Target == slice6MaterialSocketRoot || strings.HasPrefix(mount.Target, slice6MaterialSocketRoot+"/") {
				if !slice6MaterialSocketMember(profile.MaterialSockets, principal.Name, mount) {
					return errSlice6DesiredInventory
				}
			}
		}
	}
	return nil
}

func slice6MaterialSocketMember(bindings []Slice6MaterialSocketBinding, principalName string, mount Mount) bool {
	for _, binding := range bindings {
		if mount == (Mount{Target: binding.SocketDirectory, Kind: "private_socket", StorageID: binding.SocketStorageID}) &&
			principalName == binding.AgentDeployment ||
			mount == (Mount{Target: binding.SocketDirectory, Kind: "private_socket", StorageID: binding.SocketStorageID, ReadOnly: true}) &&
				principalName == binding.OwnerDeployment {
			return true
		}
	}
	return false
}

// Slice6MaterialSocketForOwner resolves an exact endpoint only after final
// Profile verification. It never accepts a caller-selected path or agent.
func (p Profile) Slice6MaterialSocketForOwner(owner string) (Slice6MaterialSocketBinding, error) {
	if VerifySlice6FinalGateProfile(p) != nil {
		return Slice6MaterialSocketBinding{}, errSlice6DesiredInventory
	}
	for _, binding := range p.MaterialSockets {
		if binding.OwnerDeployment == owner {
			return binding, nil
		}
	}
	return Slice6MaterialSocketBinding{}, errSlice6DesiredInventory
}
