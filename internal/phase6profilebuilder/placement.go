package phase6profilebuilder

import (
	"errors"
	"slices"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidPlacement = errors.New("invalid Phase 6 Slice 6 reviewed principal placement")

// bindPrincipalPlacement derives static UID/GID and network membership from
// the reviewed repository inventory, before Docker exists. It never copies
// observed addresses, credentials or access from a running container.
func bindPrincipalPlacement(principals []phase6security.Principal) ([]phase6security.Principal, []phase6security.Network, error) {
	names := phase6security.Slice6DesiredDeploymentNames()
	accounts := phase6security.Slice6DesiredUIDGID()
	networks := phase6security.Slice6DesiredNetworks()
	if len(principals) != len(names) || len(accounts) != len(names) {
		return nil, nil, ErrInvalidPlacement
	}
	seen := make(map[string]bool, len(names))
	for _, principal := range principals {
		if _, approved := accounts[principal.Name]; !approved || seen[principal.Name] {
			return nil, nil, ErrInvalidPlacement
		}
		seen[principal.Name] = true
	}
	bound := append([]phase6security.Principal(nil), principals...)
	for index := range bound {
		principal := &bound[index]
		account := accounts[principal.Name]
		principal.UID, principal.GID = account[0], account[1]
		principal.Networks = nil
		principal.HostNetwork = false
		principal.ExternalUplink = false
		principal.DirectEgressBlocked = true
		for _, network := range networks {
			if !slices.Contains(network.Principals, principal.Name) {
				continue
			}
			principal.Networks = append(principal.Networks, network.Name)
			if network.Kind == "external_uplink" || network.Kind == "public_ingress" {
				principal.ExternalUplink = true
				principal.DirectEgressBlocked = false
			}
		}
		if len(principal.Networks) == 0 {
			return nil, nil, ErrInvalidPlacement
		}
	}
	return bound, networks, nil
}
