//go:build phase6slice6gate

package productphase6gate

import (
	"errors"
	"slices"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// A launch plan contains only source-bound placement authority. It does not
// attest that a socket, PostgreSQL server or Product PID1 is running.
type slice6ProductRuntimeLaunchPlan struct {
	Principal       phase6security.Principal
	ServiceNetwork  phase6security.Network
	Networks        []phase6security.Network
	SocketStorageID []string
	SourceAddress   string
}

func slice6BuildProductRuntimeLaunchPlan(profile phase6security.Profile) (slice6ProductRuntimeLaunchPlan, error) {
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil {
		return slice6ProductRuntimeLaunchPlan{}, errors.New("Product runtime final Profile unavailable")
	}
	authority, err := profile.ResolveSlice6FinalPostgresAuthority("product-runtime")
	material, materialErr := profile.Slice6MaterialSocketForOwner("product-runtime")
	publicTLS, publicAgent, subject, publicErr := profile.TLSAgentForSubject("product-runtime")
	postgresSigner, postgresTarget, postgresAgent, postgresSubject, _, postgresErr :=
		profile.PostgresClientSignerForOwner("product-runtime")
	if err != nil || materialErr != nil || publicErr != nil || postgresErr != nil ||
		authority.Network != "service-product-postgres" || authority.SourceAddress == "" ||
		authority.Dialer != "product-runtime" || authority.Database != "product" ||
		authority.SQLRole != "product_runtime" || authority.Migration || authority.BrokerOnly ||
		material.AgentDeployment != "product-runtime-agent" || material.OwnerDeployment != "product-runtime" ||
		publicAgent.Name != "product-tls-agent" || subject.Name != "product-runtime" ||
		postgresTarget.AgentDeployment != "product-postgres-tls-agent" ||
		postgresTarget.SubjectDeployment != "product-runtime" || postgresTarget.Migration ||
		postgresAgent.Name != postgresTarget.AgentDeployment || postgresSubject.Name != subject.Name {
		return slice6ProductRuntimeLaunchPlan{}, errors.New("Product runtime signer or SQL authority drift")
	}
	owner := subject
	if owner.Kind != "runtime" || owner.ImageLocation != "local" ||
		owner.ImageReference != owner.ImageDigest || owner.UID == 0 || owner.GID == 0 ||
		!owner.ReadOnlyRootFilesystem || !owner.NoNewPrivileges || owner.HostNetwork ||
		owner.ExternalUplink || !owner.DirectEgressBlocked ||
		!slices.Equal(owner.DroppedCapabilities, []string{"ALL"}) ||
		owner.Resources.MemoryBytes <= 0 || owner.Resources.CPUMillis <= 0 || owner.Resources.PIDs <= 0 {
		return slice6ProductRuntimeLaunchPlan{}, errors.New("Product runtime image or least-privilege identity drift")
	}
	private, ok := phase6security.Slice6PrivateConfigMount(owner.Name)
	if !ok || private.Target != phase6security.Slice6PrivateConfigDirectory ||
		!slices.Equal(strings.Split(private.PrivateFiles, ","), []string{
			phase6security.Slice6PeerCRLRoleFile,
			phase6security.Slice6PostgresPeerCRLRoleFile,
			phase6security.Slice6ProfileConfigFile,
			phase6security.Slice6StartupConfigFile,
		}) {
		return slice6ProductRuntimeLaunchPlan{}, errors.New("Product runtime private startup file manifest drift")
	}
	sockets := []string{material.SocketStorageID, publicTLS.SocketStorageID, postgresSigner.SocketStorageID}
	seenSockets := make(map[string]bool, len(sockets))
	for _, id := range sockets {
		if id == "" || seenSockets[id] {
			return slice6ProductRuntimeLaunchPlan{}, errors.New("Product runtime socket identity alias")
		}
		seenSockets[id] = true
	}
	mountedSockets := 0
	for _, mount := range owner.Mounts {
		if mount.Kind != "private_socket" {
			continue
		}
		if !seenSockets[mount.StorageID] || !mount.ReadOnly {
			return slice6ProductRuntimeLaunchPlan{}, errors.New("Product runtime private socket mount drift")
		}
		mountedSockets++
	}
	if mountedSockets != len(sockets) {
		return slice6ProductRuntimeLaunchPlan{}, errors.New("Product runtime private socket mount count drift")
	}
	wantedNetworks := []string{"guest-product", "ingress-product", "product-internal",
		"product-provider", "product-provider-browser", "product-provider-desktop", "service-product-postgres"}
	slices.Sort(wantedNetworks)
	actualNetworks := slices.Clone(owner.Networks)
	slices.Sort(actualNetworks)
	if !slices.Equal(actualNetworks, wantedNetworks) {
		return slice6ProductRuntimeLaunchPlan{}, errors.New("Product runtime isolated network inventory drift")
	}
	plan := slice6ProductRuntimeLaunchPlan{Principal: owner, SocketStorageID: sockets,
		SourceAddress: authority.SourceAddress}
	for _, network := range profile.Networks {
		if !slices.Contains(wantedNetworks, network.Name) {
			continue
		}
		if !network.Internal || network.GatewayModeIPv4 != "isolated" ||
			!slices.Contains(network.Principals, owner.Name) {
			return slice6ProductRuntimeLaunchPlan{}, errors.New("Product runtime network isolation drift")
		}
		plan.Networks = append(plan.Networks, network)
		if network.Name == authority.Network {
			plan.ServiceNetwork = network
		}
	}
	if len(plan.Networks) != len(wantedNetworks) || plan.ServiceNetwork.Name != authority.Network ||
		!slices.Equal(plan.ServiceNetwork.Principals, []string{owner.Name}) ||
		!slices.Equal(plan.ServiceNetwork.ExternalServices, []string{"postgres"}) {
		return slice6ProductRuntimeLaunchPlan{}, errors.New("Product runtime PostgreSQL service bridge drift")
	}
	return plan, nil
}
