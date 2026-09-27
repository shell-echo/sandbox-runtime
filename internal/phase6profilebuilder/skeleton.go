package phase6profilebuilder

import (
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// newPrincipalSkeleton binds the complete reviewed deployment list to one
// fresh run's authorization identities and expected TLS leaf policies. It is
// deliberately incomplete until image, placement, mount, listener, resource
// and external/bootstrap binding succeeds; never launch from this draft.
func newPrincipalSkeleton(runID, environmentDigest, principalProfileDigest string) ([]phase6security.Principal, error) {
	identities, err := phase6security.Slice6DesiredAuthorizationPrincipals(runID,
		environmentDigest, principalProfileDigest)
	if err != nil {
		return nil, ErrInvalidPlacement
	}
	names := phase6security.Slice6DesiredDeploymentNames()
	if len(names) != len(identities)+2 {
		return nil, ErrInvalidPlacement
	}
	principals := make([]phase6security.Principal, 0, len(names))
	for _, name := range names {
		kind, err := phase6security.Slice6DesiredDeploymentKind(name)
		if err != nil {
			return nil, ErrInvalidPlacement
		}
		principal := phase6security.Principal{Name: name, Kind: kind,
			ReadOnlyRootFilesystem: true, NoNewPrivileges: true, DroppedCapabilities: []string{"ALL"},
			DirectEgressBlocked: true}
		if kind == "sandbox" {
			controller := "provider-browser-runtime"
			if name == "desktop-sandbox-runtime" {
				controller = "provider-desktop-runtime"
			} else if name != "browser-sandbox-runtime" {
				return nil, ErrInvalidPlacement
			}
			owner, found := identities[controller]
			if !found {
				return nil, ErrInvalidPlacement
			}
			principal.ControllingPrincipalDigest = owner.Digest()
		} else {
			identity, found := identities[name]
			if !found {
				return nil, ErrInvalidPlacement
			}
			principal.AuthorizationPrincipal = &identity
			principal.PrincipalDigest = identity.Digest()
		}
		principal.TLS, err = phase6security.Slice6DesiredTLSIdentity(name, principal.PrincipalDigest)
		if err != nil {
			return nil, ErrInvalidPlacement
		}
		principals = append(principals, principal)
	}
	return principals, nil
}
