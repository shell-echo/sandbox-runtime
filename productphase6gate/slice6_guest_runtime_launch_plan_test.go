//go:build phase6slice6gate

package productphase6gate

import (
	"errors"
	"slices"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type slice6GuestRuntimeLaunchPlan struct {
	Principal                       phase6security.Principal
	ProductNetwork, InternalNetwork phase6security.Network
	ProductIP, InternalIP           string
	MaterialSocketID, TLSSocketID   string
	PrivateConfigStorageID          string
}

// This freezes only placement and mount authority. A constructed plan is not
// an observation that Guest PID1, its Product peer, or any signer is running.
func slice6BuildGuestRuntimeLaunchPlan(profile phase6security.Profile) (slice6GuestRuntimeLaunchPlan, error) {
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		phase6security.VerifySlice6GuestStorageMounts(profile) != nil {
		return slice6GuestRuntimeLaunchPlan{}, errors.New("Guest final Profile or storage authority unavailable")
	}
	material, materialErr := profile.Slice6MaterialSocketForOwner("guest-runtime")
	tls, tlsAgent, subject, tlsErr := profile.TLSAgentForSubject("guest-runtime")
	private, privateOK := phase6security.Slice6PrivateConfigMount("guest-runtime")
	wantFiles := []string{
		phase6security.Slice6CredentialAuthorityFile,
		phase6security.Slice6DependencyAuthorityFile,
		phase6security.Slice6PeerCRLRoleFile,
		phase6security.Slice6PolicyAuthorityFile,
		phase6security.Slice6ProfileConfigFile,
		phase6security.Slice6StartupConfigFile,
	}
	if materialErr != nil || tlsErr != nil || !privateOK ||
		material.OwnerDeployment != "guest-runtime" || material.AgentDeployment != "guest-agent" ||
		tlsAgent.Name != "guest-tls-agent" || subject.Name != "guest-runtime" ||
		material.SocketStorageID == tls.SocketStorageID ||
		private.Target != phase6security.Slice6PrivateConfigDirectory ||
		!slices.Equal(strings.Split(private.PrivateFiles, ","), wantFiles) {
		return slice6GuestRuntimeLaunchPlan{}, errors.New("Guest private configuration or signer boundary drift")
	}
	principal := subject
	if principal.Kind != "runtime" || principal.ImageLocation != "local" ||
		principal.ImageReference != principal.ImageDigest || principal.UID == 0 || principal.GID == 0 ||
		!principal.ReadOnlyRootFilesystem || !principal.NoNewPrivileges ||
		principal.HostNetwork || principal.ExternalUplink || !principal.DirectEgressBlocked ||
		!slices.Equal(principal.DroppedCapabilities, []string{"ALL"}) ||
		principal.Resources.MemoryBytes <= 0 || principal.Resources.CPUMillis <= 0 ||
		principal.Resources.PIDs <= 0 ||
		!slices.Equal(principal.Networks, []string{"guest-product", "network-guest-runtime"}) {
		return slice6GuestRuntimeLaunchPlan{}, errors.New("Guest immutable process identity or network set drift")
	}
	allowedSockets := map[string]bool{material.SocketStorageID: false, tls.SocketStorageID: false}
	allowedStorage := map[string]bool{}
	for _, mount := range phase6security.Slice6GuestStorageMounts() {
		allowedStorage[mount.Target] = false
	}
	privateCount, trustCount := 0, 0
	for _, mount := range principal.Mounts {
		switch mount.Kind {
		case "private_config":
			if mount != private {
				return slice6GuestRuntimeLaunchPlan{}, errors.New("Guest private config mount drift")
			}
			privateCount++
		case "private_socket":
			if _, ok := allowedSockets[mount.StorageID]; !ok || !mount.ReadOnly {
				return slice6GuestRuntimeLaunchPlan{}, errors.New("Guest private socket mount drift")
			}
			allowedSockets[mount.StorageID] = true
		case "guest_storage", "tmpfs":
			if _, ok := allowedStorage[mount.Target]; !ok || allowedStorage[mount.Target] ||
				!slices.Contains(phase6security.Slice6GuestStorageMounts(), mount) {
				return slice6GuestRuntimeLaunchPlan{}, errors.New("Guest business-storage mount drift")
			}
			allowedStorage[mount.Target] = true
		case "trust_anchor":
			trustCount++
		default:
			return slice6GuestRuntimeLaunchPlan{}, errors.New("Guest unreviewed mount kind")
		}
	}
	if privateCount != 1 || trustCount == 0 || !allowedSockets[material.SocketStorageID] ||
		!allowedSockets[tls.SocketStorageID] {
		return slice6GuestRuntimeLaunchPlan{}, errors.New("Guest private config, socket or anchor inventory incomplete")
	}
	for _, found := range allowedStorage {
		if !found {
			return slice6GuestRuntimeLaunchPlan{}, errors.New("Guest storage inventory incomplete")
		}
	}
	var plan slice6GuestRuntimeLaunchPlan
	plan.Principal = principal
	plan.MaterialSocketID, plan.TLSSocketID = material.SocketStorageID, tls.SocketStorageID
	plan.PrivateConfigStorageID = private.StorageID
	for _, network := range profile.Networks {
		switch network.Name {
		case "guest-product":
			plan.ProductNetwork = network
		case "network-guest-runtime":
			plan.InternalNetwork = network
		}
	}
	if plan.ProductNetwork.Name == "" || plan.InternalNetwork.Name == "" ||
		!plan.ProductNetwork.Internal || !plan.InternalNetwork.Internal ||
		plan.ProductNetwork.GatewayModeIPv4 != "isolated" ||
		plan.InternalNetwork.GatewayModeIPv4 != "isolated" ||
		!slices.Equal(plan.ProductNetwork.Principals, []string{"guest-runtime", "product-runtime"}) ||
		!slices.Equal(plan.InternalNetwork.Principals, []string{"guest-runtime"}) ||
		len(plan.ProductNetwork.ExternalServices) != 0 ||
		len(plan.InternalNetwork.ExternalServices) != 0 {
		return slice6GuestRuntimeLaunchPlan{}, errors.New("Guest Product or internal isolated network drift")
	}
	var err error
	plan.ProductIP, err = phase6security.Slice6DesiredEndpointAddress(plan.ProductNetwork.Name, principal.Name)
	if err != nil {
		return slice6GuestRuntimeLaunchPlan{}, errors.New("Guest Product edge IP unavailable")
	}
	plan.InternalIP, err = phase6security.Slice6DesiredEndpointAddress(plan.InternalNetwork.Name, principal.Name)
	if err != nil || plan.ProductIP == plan.InternalIP {
		return slice6GuestRuntimeLaunchPlan{}, errors.New("Guest internal IP unavailable")
	}
	return plan, nil
}
