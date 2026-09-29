package phase6profilebuilder

import (
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// bindCredentialIssuerSockets adds the reviewed per-client issuer mounts to
// placed principals. The socket identities and paths come from the same
// phase6security binding builder used by the final profile validator.
func bindCredentialIssuerSockets(principals []phase6security.Principal) ([]phase6security.Principal,
	[]phase6security.CredentialIssuerSocketBinding, error) {
	bindings, err := phase6security.BuildCredentialIssuerSocketBindings(principals)
	if err != nil {
		return nil, nil, ErrInvalidPlacement
	}
	bound := make([]phase6security.Principal, len(principals))
	serverIndex := -1
	clientIndexes := make(map[string]int, len(bindings))
	for index, principal := range principals {
		bound[index] = principal
		bound[index].Mounts = append([]phase6security.Mount(nil), principal.Mounts...)
		if principal.Name == "workload-credential-controller" {
			serverIndex = index
		}
		for _, binding := range bindings {
			if principal.Name == binding.ClientDeployment {
				clientIndexes[principal.Name] = index
			}
		}
		for _, mount := range principal.Mounts {
			for _, binding := range bindings {
				if mount.StorageID == binding.SocketStorageID || overlappingMountTarget(mount.Target, binding.SocketDirectory) {
					return nil, nil, ErrInvalidPlacement
				}
			}
		}
	}
	if serverIndex < 0 || len(clientIndexes) != len(bindings) {
		return nil, nil, ErrInvalidPlacement
	}
	for _, binding := range bindings {
		bound[serverIndex].Mounts = append(bound[serverIndex].Mounts, phase6security.Mount{
			Target: binding.SocketDirectory, Kind: "private_socket", StorageID: binding.SocketStorageID,
		})
		clientIndex := clientIndexes[binding.ClientDeployment]
		bound[clientIndex].Mounts = append(bound[clientIndex].Mounts, phase6security.Mount{
			Target: binding.SocketDirectory, Kind: "private_socket", ReadOnly: true, StorageID: binding.SocketStorageID,
		})
	}
	return bound, bindings, nil
}

func overlappingMountTarget(first, second string) bool {
	return first == second || strings.HasPrefix(first, second+"/") || strings.HasPrefix(second, first+"/")
}
