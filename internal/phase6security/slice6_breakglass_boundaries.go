package phase6security

import (
	"path"
	"slices"
	"strings"
)

const (
	slice6BreakGlassRoot        = "/run/phase6/break-glass"
	slice6BreakGlassOperatorUID = 20091
	slice6BreakGlassOperatorGID = 30091
	slice6BreakGlassImage       = "docker.io/library/alpine@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40"
)

// Slice6BreakGlassSocketBinding is one v2 Unix transport authorization. It
// does not replace the signed v1 break-glass business payload or actor checks.
type Slice6BreakGlassSocketBinding struct {
	ID                  string `json:"id"`
	Kind                string `json:"kind"`
	TargetAgent         string `json:"target_agent"`
	ServerDeployment    string `json:"server_deployment"`
	ClientDeployment    string `json:"client_deployment"`
	ClientTaskID        string `json:"client_task_id"`
	ServerUID           uint32 `json:"server_uid"`
	ServerGID           uint32 `json:"server_gid"`
	ClientUID           uint32 `json:"client_uid"`
	ClientGID           uint32 `json:"client_gid"`
	SocketDirectory     string `json:"socket_directory"`
	SocketStorageID     string `json:"socket_storage_id"`
	SocketPath          string `json:"socket_path"`
	DirectoryMode       uint32 `json:"directory_mode"`
	SocketMode          uint32 `json:"socket_mode"`
	FirstFrameSeconds   int    `json:"first_frame_seconds"`
	MaxOperationSeconds int    `json:"max_operation_seconds"`
	MaxConnections      int    `json:"max_connections"`
	OperationSet        string `json:"operation_set"`
	CleanupClass        string `json:"cleanup_class"`
}

// Slice6BreakGlassOperatorTask is a finite one-shot transport task, not a
// 79th deployment or a new source of requester/approver/operator signatures.
// Each invocation selects one operation and mounts only the shared reviewed
// executable file plus its sole read-only socket directory.
type Slice6BreakGlassOperatorTask struct {
	ID                     string `json:"id"`
	SocketBindingID        string `json:"socket_binding_id"`
	OperationSet           string `json:"operation_set"`
	UID                    uint32 `json:"uid"`
	GID                    uint32 `json:"gid"`
	ImageReference         string `json:"image_reference"`
	Executable             string `json:"executable"`
	ExecutableArtifactID   string `json:"executable_artifact_id"`
	ExecutableMount        Mount  `json:"executable_mount"`
	NetworkMode            string `json:"network_mode"`
	ReadOnlyRootFilesystem bool   `json:"read_only_root_filesystem"`
	DropAllCapabilities    bool   `json:"drop_all_capabilities"`
	NoNewPrivileges        bool   `json:"no_new_privileges"`
	MemoryBytes            int64  `json:"memory_bytes"`
	CPUMillis              int    `json:"cpu_millis"`
	PIDs                   int    `json:"pids"`
	MaxExecutionSeconds    int    `json:"max_execution_seconds"`
	Mount                  Mount  `json:"mount"`
}

func slice6BreakGlassSocket(kind, agent string, server Principal, client Principal) Slice6BreakGlassSocketBinding {
	var id, directory, operations, clientTask string
	switch kind {
	case "control":
		id = "break-glass-control"
		directory = path.Join(slice6BreakGlassRoot, "controller", "operator")
		operations, clientTask = "approve,issue,revoke,submit", id
	case "consume":
		id = "break-glass-consume-" + agent
		directory = path.Join(slice6BreakGlassRoot, "controller", agent)
		operations = "consume"
	case "delivery":
		id = "break-glass-deliver-" + agent
		directory = path.Join(slice6BreakGlassRoot, "agents", agent)
		operations, clientTask = "deliver", id
	}
	binding := Slice6BreakGlassSocketBinding{ID: id, Kind: kind, TargetAgent: agent,
		ServerDeployment: server.Name, ServerUID: server.UID, ServerGID: server.GID,
		ClientDeployment: client.Name, ClientUID: client.UID, ClientGID: client.GID,
		ClientTaskID: clientTask, SocketDirectory: directory, SocketStorageID: id + "-socket",
		SocketPath: path.Join(directory, "break-glass.sock"), DirectoryMode: 0o710, SocketMode: 0o666,
		FirstFrameSeconds: 2, MaxOperationSeconds: 30, MaxConnections: 4,
		OperationSet: operations, CleanupClass: "sockets"}
	if kind == "control" {
		binding.TargetAgent = ""
	}
	return binding
}

func slice6BreakGlassTask(binding Slice6BreakGlassSocketBinding) Slice6BreakGlassOperatorTask {
	return Slice6BreakGlassOperatorTask{ID: binding.ClientTaskID, SocketBindingID: binding.ID,
		OperationSet: binding.OperationSet, UID: slice6BreakGlassOperatorUID, GID: slice6BreakGlassOperatorGID,
		ImageReference: slice6BreakGlassImage, Executable: "/phase6-break-glass-operator", NetworkMode: "none",
		ExecutableArtifactID: "break-glass-operator", ExecutableMount: Mount{Target: "/phase6-break-glass-operator",
			Kind: "read_only_executable", ReadOnly: true, StorageID: "break-glass-operator-source-binary"},
		ReadOnlyRootFilesystem: true, DropAllCapabilities: true, NoNewPrivileges: true,
		MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 16, MaxExecutionSeconds: 30,
		Mount: Mount{Target: binding.SocketDirectory, Kind: "private_socket", ReadOnly: true,
			StorageID: binding.SocketStorageID}}
}

func slice6BreakGlassDesired(principals []Principal) ([]Slice6BreakGlassSocketBinding, []Slice6BreakGlassOperatorTask, error) {
	byName := make(map[string]Principal, len(principals))
	for _, principal := range principals {
		if byName[principal.Name].Name != "" || principal.UID == slice6BreakGlassOperatorUID ||
			principal.GID == slice6BreakGlassOperatorGID || principal.UID == 20090 || principal.GID == 30090 {
			return nil, nil, errSlice6DesiredInventory
		}
		byName[principal.Name] = principal
	}
	controller := byName["break-glass-controller"]
	if controller.Name == "" || controller.Kind != "controller" {
		return nil, nil, errSlice6DesiredInventory
	}
	operator := Principal{Name: "break-glass-operator-task", UID: slice6BreakGlassOperatorUID, GID: slice6BreakGlassOperatorGID}
	control := slice6BreakGlassSocket("control", "", controller, operator)
	sockets := []Slice6BreakGlassSocketBinding{control}
	tasks := []Slice6BreakGlassOperatorTask{slice6BreakGlassTask(control)}
	runtimeAgents := 0
	for _, template := range slice6MaterialAccessTemplates {
		agent, owner := byName[template.agent], byName[template.owner]
		if owner.Kind == "migration_job" {
			continue
		}
		if agent.Name != template.agent || agent.Kind != "material_agent" || owner.Name != template.owner ||
			owner.Kind != "runtime" || agent.UID == controller.UID || agent.GID == controller.GID ||
			agent.UID == operator.UID || agent.GID == operator.GID {
			return nil, nil, errSlice6DesiredInventory
		}
		consume := slice6BreakGlassSocket("consume", agent.Name, controller, agent)
		delivery := slice6BreakGlassSocket("delivery", agent.Name, agent, operator)
		sockets = append(sockets, consume, delivery)
		tasks = append(tasks, slice6BreakGlassTask(delivery))
		runtimeAgents++
	}
	if runtimeAgents != 7 || len(sockets) != 15 || len(tasks) != 8 {
		return nil, nil, errSlice6DesiredInventory
	}
	return sockets, tasks, nil
}

// AttachSlice6BreakGlassBoundaries grants the controller and only seven
// nonmigration agents their exact server/client mounts. Operator mounts live
// exclusively in the finite one-shot task inventory above.
func AttachSlice6BreakGlassBoundaries(principals []Principal) ([]Principal, []Slice6BreakGlassSocketBinding, []Slice6BreakGlassOperatorTask, error) {
	bindings, tasks, err := slice6BreakGlassDesired(principals)
	if err != nil {
		return nil, nil, nil, err
	}
	result := slices.Clone(principals)
	byName := make(map[string]int, len(result))
	for index := range result {
		byName[result[index].Name] = index
		result[index].Mounts = slices.Clone(result[index].Mounts)
	}
	for _, binding := range bindings {
		serverIndex := byName[binding.ServerDeployment]
		result[serverIndex].Mounts = append(result[serverIndex].Mounts, Mount{Target: binding.SocketDirectory,
			Kind: "private_socket", StorageID: binding.SocketStorageID})
		if binding.Kind == "consume" {
			clientIndex := byName[binding.ClientDeployment]
			result[clientIndex].Mounts = append(result[clientIndex].Mounts, Mount{Target: binding.SocketDirectory,
				Kind: "private_socket", StorageID: binding.SocketStorageID, ReadOnly: true})
		}
	}
	if VerifySlice6BreakGlassBoundaries(Profile{Principals: result, BreakGlassSockets: bindings,
		BreakGlassOperatorTasks: tasks}) != nil {
		return nil, nil, nil, errSlice6DesiredInventory
	}
	return result, bindings, tasks, nil
}

// VerifySlice6BreakGlassBoundaries closes all 15 endpoint identities, 8
// one-shot task permissions and principal mount readers before runtime.
func VerifySlice6BreakGlassBoundaries(profile Profile) error {
	wantedSockets, wantedTasks, err := slice6BreakGlassDesired(profile.Principals)
	if err != nil || !slices.Equal(profile.BreakGlassSockets, wantedSockets) ||
		!slices.Equal(profile.BreakGlassOperatorTasks, wantedTasks) {
		return errSlice6DesiredInventory
	}
	for _, binding := range wantedSockets {
		found := 0
		for _, principal := range profile.Principals {
			for _, mount := range principal.Mounts {
				if mount.StorageID == binding.SocketStorageID || mount.Target == binding.SocketDirectory ||
					strings.HasPrefix(mount.Target, binding.SocketDirectory+"/") ||
					strings.HasPrefix(binding.SocketDirectory, mount.Target+"/") {
					if !slice6BreakGlassSocketMember([]Slice6BreakGlassSocketBinding{binding}, principal.Name, mount) {
						return errSlice6DesiredInventory
					}
					found++
				}
			}
		}
		want := 1
		if binding.Kind == "consume" {
			want = 2
		}
		if found != want {
			return errSlice6DesiredInventory
		}
	}
	for _, principal := range profile.Principals {
		for _, mount := range principal.Mounts {
			if mount.Target == slice6BreakGlassRoot || strings.HasPrefix(mount.Target, slice6BreakGlassRoot+"/") {
				if !slice6BreakGlassSocketMember(wantedSockets, principal.Name, mount) {
					return errSlice6DesiredInventory
				}
			}
		}
	}
	return nil
}

func slice6BreakGlassSocketMember(bindings []Slice6BreakGlassSocketBinding, principalName string, mount Mount) bool {
	for _, binding := range bindings {
		if mount == (Mount{Target: binding.SocketDirectory, Kind: "private_socket", StorageID: binding.SocketStorageID}) &&
			principalName == binding.ServerDeployment ||
			binding.Kind == "consume" && mount == (Mount{Target: binding.SocketDirectory, Kind: "private_socket",
				ReadOnly: true, StorageID: binding.SocketStorageID}) && principalName == binding.ClientDeployment {
			return true
		}
	}
	return false
}
