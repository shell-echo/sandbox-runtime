package phase6security

import "sort"

// Slice6DirectExternalDependency is a command-level dial requirement, kept
// independent of the desired trust-edge table. A matching transport path is
// only coverage of desired configuration; it is not an observed connection.
// The command audit is intentionally explicit so that dropping a deployment
// from the profile inventory cannot silently drop its external dependency.
type Slice6DirectExternalDependency struct {
	Dialer  string
	Service string
	Network string
}

var slice6RequiredDirectExternalDependencies = []Slice6DirectExternalDependency{
	{"browser-action-ingress-agent", "vault", "service-browser-action-ingress-agent-vault"},
	{"browser-agent", "vault", "service-browser-agent-vault"},
	{"certificate-controller", "vault", "network-certificate-controller"},
	{"desktop-agent", "vault", "service-desktop-agent-vault"},
	{"gateway-agent", "vault", "service-gateway-agent-vault"},
	{"gateway-runtime", "postgres", "service-gateway-postgres"},
	{"guest-agent", "vault", "service-guest-agent-vault"},
	{"product-migration-agent", "vault", "service-product-migration-agent-vault"},
	{"product-migration-job", "postgres", "service-product-migration-job-postgres"},
	{"product-runtime", "postgres", "service-product-postgres"},
	{"product-runtime-agent", "vault", "service-product-runtime-agent-vault"},
	{"provider-browser-runtime-agent", "vault", "service-provider-browser-runtime-agent-vault"},
	{"provider-desktop-runtime-agent", "vault", "service-provider-desktop-runtime-agent-vault"},
	{"provider-migration-agent", "vault", "service-provider-migration-agent-vault"},
	{"provider-migration-job", "postgres", "service-provider-migration-job-postgres"},
	{"provider-runtime", "postgres", "service-provider-runtime-postgres"},
	{"provider-runtime-agent", "vault", "service-provider-runtime-agent-vault"},
	{"workload-credential-controller", "vault", "service-workload-credential-controller-vault"},
}

func Slice6RequiredDirectExternalDependencies() []Slice6DirectExternalDependency {
	return append([]Slice6DirectExternalDependency(nil), slice6RequiredDirectExternalDependencies...)
}

// MissingSlice6DirectExternalDependencies reports every command-level direct
// dial that is absent or incorrectly routed through a broker/shared bridge.
// In particular, the old edge-complete 17/12 table is not a deployable graph.
func MissingSlice6DirectExternalDependencies(paths []Slice6ExternalTransportPath) []Slice6DirectExternalDependency {
	missing := make([]Slice6DirectExternalDependency, 0)
	for _, required := range slice6RequiredDirectExternalDependencies {
		found := false
		for _, path := range paths {
			if path.LogicalCaller == required.Dialer && path.Dialer == required.Dialer &&
				path.Service == required.Service && path.Network == required.Network {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, required)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].Dialer < missing[j].Dialer })
	return missing
}

// VerifySlice6ExecutableExternalDependencyCoverage is the command-level
// preflight. It must be used in addition to the reviewed trust-edge coverage
// check before a complete candidate profile can be frozen.
func VerifySlice6ExecutableExternalDependencyCoverage(paths []Slice6ExternalTransportPath) error {
	if len(MissingSlice6DirectExternalDependencies(paths)) != 0 {
		return errSlice6DesiredInventory
	}
	return nil
}
