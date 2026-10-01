package phase6profilebuilder

import (
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestPrincipalSkeletonBindsReviewedPerRunIdentities(t *testing.T) {
	environment := "sha256:" + strings.Repeat("a", 64)
	profile := "sha256:" + strings.Repeat("b", 64)
	first, err := newPrincipalSkeleton(strings.Repeat("c", 32), environment, profile)
	if err != nil || len(first) != 78 {
		t.Fatalf("reviewed principal skeleton = %d, %v", len(first), err)
	}
	second, err := newPrincipalSkeleton(strings.Repeat("d", 32), environment, profile)
	if err != nil {
		t.Fatal(err)
	}
	for index, principal := range first {
		if principal.Name != second[index].Name || !principal.ReadOnlyRootFilesystem ||
			!principal.NoNewPrivileges || principal.HostNetwork || principal.DockerSocket || principal.HostDevices {
			t.Fatalf("principal %s gained unsafe baseline", principal.Name)
		}
		if principal.Kind == "sandbox" {
			if principal.AuthorizationPrincipal != nil || principal.PrincipalDigest != "" || principal.TLS != nil ||
				principal.ControllingPrincipalDigest == second[index].ControllingPrincipalDigest {
				t.Fatalf("sandbox template %s lost fresh controller binding", principal.Name)
			}
		} else if principal.AuthorizationPrincipal == nil || principal.PrincipalDigest == second[index].PrincipalDigest {
			t.Fatalf("principal %s lost fresh run identity", principal.Name)
		}
		kind, err := phase6security.Slice6DesiredDeploymentKind(principal.Name)
		if err != nil || kind != principal.Kind {
			t.Fatalf("deployment kind drifted for %s", principal.Name)
		}
	}
	if _, err := newPrincipalSkeleton("invalid", environment, profile); err == nil {
		t.Fatal("noncanonical run ID admitted")
	}
}
