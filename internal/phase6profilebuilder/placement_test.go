package phase6profilebuilder

import (
	"errors"
	"slices"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestPrincipalPlacementComesOnlyFromReviewedInventory(t *testing.T) {
	names := phase6security.Slice6DesiredDeploymentNames()
	principals := make([]phase6security.Principal, 0, len(names))
	for _, name := range names {
		principals = append(principals, phase6security.Principal{Name: name,
			UID: 1, GID: 1, Networks: []string{"attacker-network"}, HostNetwork: true, ExternalUplink: true})
	}
	bound, networks, err := bindPrincipalPlacement(principals)
	if err != nil || len(bound) != len(names) || len(networks) != len(phase6security.Slice6DesiredNetworks()) {
		t.Fatalf("reviewed placement rejected: %d/%d, %v", len(bound), len(networks), err)
	}
	wantedAccounts := phase6security.Slice6DesiredUIDGID()
	for index, principal := range bound {
		account := wantedAccounts[principal.Name]
		if principal.UID != account[0] || principal.GID != account[1] || principal.HostNetwork ||
			slices.Contains(principal.Networks, "attacker-network") || principals[index].UID != 1 {
			t.Fatalf("unreviewed placement retained for %s", principal.Name)
		}
		wantedNetworks := []string{}
		for _, network := range networks {
			if slices.Contains(network.Principals, principal.Name) {
				wantedNetworks = append(wantedNetworks, network.Name)
			}
		}
		if !slices.Equal(principal.Networks, wantedNetworks) {
			t.Fatalf("wrong networks for %s", principal.Name)
		}
	}
	duplicate := append([]phase6security.Principal(nil), principals...)
	duplicate[0] = duplicate[1]
	if _, _, err := bindPrincipalPlacement(duplicate); !errors.Is(err, ErrInvalidPlacement) {
		t.Fatal("duplicate deployment admitted to placement")
	}
}
