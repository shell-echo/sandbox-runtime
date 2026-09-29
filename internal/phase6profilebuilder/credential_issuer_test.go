package phase6profilebuilder

import (
	"slices"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestCredentialIssuerMountsComeFromReviewedPrincipalBindings(t *testing.T) {
	core, err := newPrincipalSkeleton(strings.Repeat("c", 32), "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	placed, _, err := bindPrincipalPlacement(core)
	if err != nil {
		t.Fatal(err)
	}
	bound, bindings, err := bindCredentialIssuerSockets(placed)
	if err != nil || len(bindings) != 14 {
		t.Fatalf("reviewed issuer mounts = %d, %v", len(bindings), err)
	}
	for _, binding := range bindings {
		server, client := false, false
		for _, principal := range bound {
			for _, mount := range principal.Mounts {
				if mount.StorageID != binding.SocketStorageID {
					continue
				}
				if mount.Target != binding.SocketDirectory || mount.Kind != "private_socket" {
					t.Fatal("issuer mount target drift")
				}
				switch principal.Name {
				case "workload-credential-controller":
					server = !mount.ReadOnly
				case binding.ClientDeployment:
					client = mount.ReadOnly
				default:
					t.Fatal("issuer socket leaked to another principal")
				}
			}
		}
		if !server || !client {
			t.Fatal("issuer socket missing server or client mount")
		}
	}
	if slices.ContainsFunc(core, func(value phase6security.Principal) bool { return len(value.Mounts) != 0 }) {
		t.Fatal("input principal mounts mutated")
	}
	draft, err := BuildSlice6PrincipalDraft(strings.Repeat("c", 32), "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64))
	if err != nil || len(draft.Principals) != len(bound) || len(draft.Networks) == 0 ||
		!slices.Equal(draft.CredentialIssuerSockets, bindings) {
		t.Fatal("incomplete principal draft")
	}
	bad := append([]phase6security.Principal(nil), placed...)
	bad[0].Mounts = []phase6security.Mount{{Target: bindings[0].SocketDirectory, Kind: "private_socket", StorageID: "alias"}}
	if _, _, err := bindCredentialIssuerSockets(bad); err == nil {
		t.Fatal("issuer path alias admitted")
	}
}
