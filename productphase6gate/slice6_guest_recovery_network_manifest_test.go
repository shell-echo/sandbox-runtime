//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type slice6GuestRecoveryNetworkManifest struct {
	runID         string
	createdDigest string
	byName        map[string]phase6security.NetworkObservation
}

// A and B both use this immutable map returned by the one original allocator.
// A same-named replacement network cannot be substituted by a later lookup.
func slice6GuestRecoveryOriginalNetworkManifest(run slice6DockerRun,
	inventory []phase6security.NetworkObservation, createdDigest string,
	evidence *slice6ReceiptEvidenceRun) (slice6GuestRecoveryNetworkManifest, error) {
	desired := phase6security.Slice6DesiredFinalNetworks()
	if evidence == nil || evidence.check() != nil || evidence.id != run.id ||
		len(inventory) != len(desired) || !guestRevokeFixtureDigestGate(createdDigest) ||
		phase6security.VerifySlice6DesiredFinalNetworks(desired) != nil {
		return slice6GuestRecoveryNetworkManifest{}, errors.New("Guest E original network inventory unavailable")
	}
	raw, err := evidence.readFile(slice6GuestRecoveryCreatedReceiptRaw, 512)
	if err != nil || slice6ReceiptSHA256(raw) != createdDigest {
		clear(raw)
		return slice6GuestRecoveryNetworkManifest{}, errors.New("Guest E original network receipt unavailable")
	}
	var original slice6GuestRecoveryCreatedNetworks
	decodeErr := json.Unmarshal(raw, &original)
	canonical, canonicalErr := json.Marshal(original)
	if decodeErr != nil || canonicalErr != nil || !bytes.Equal(raw, canonical) ||
		original.RunID != run.id || original.Protocol != "sandbox-runtime.phase6-guest-created-networks.v1" {
		clear(raw)
		clear(canonical)
		return slice6GuestRecoveryNetworkManifest{}, errors.New("Guest E original network receipt drift")
	}
	clear(raw)
	clear(canonical)
	byName := make(map[string]phase6security.NetworkObservation, len(inventory))
	ids := make(map[string]bool, len(inventory))
	for index, expected := range desired {
		entry := inventory[index]
		if entry.Name != expected.Name || len(entry.NetworkID) != 64 ||
			!lowerHexSlice6(entry.NetworkID) || ids[entry.NetworkID] ||
			!guestRevokeFixtureDigestGate(entry.InspectDigest) || entry.Driver != "bridge" ||
			entry.Internal != expected.Internal || entry.IPv6Enabled ||
			entry.GatewayModeIPv4 != expected.GatewayModeIPv4 ||
			entry.Subnet != expected.IPv4Subnet || len(entry.ContainerIDs) != 0 ||
			len(entry.Endpoints) != 0 {
			return slice6GuestRecoveryNetworkManifest{}, errors.New("Guest E original network allocation drift")
		}
		ids[entry.NetworkID] = true
		byName[entry.Name] = entry
	}
	if byName["guest-product"].NetworkID != original.GuestProductID ||
		byName["network-guest-runtime"].NetworkID != original.GuestRuntimeID ||
		original.GuestProductID == original.GuestRuntimeID {
		return slice6GuestRecoveryNetworkManifest{}, errors.New("Guest E original Product/Guest network IDs changed")
	}
	return slice6GuestRecoveryNetworkManifest{runID: run.id,
		createdDigest: createdDigest, byName: byName}, nil
}

func (manifest slice6GuestRecoveryNetworkManifest) productEndpoints(
	ctx context.Context, run slice6DockerRun,
	plan slice6ProductRuntimeLaunchPlan) ([]slice6ProductRuntimeEndpoint, error) {
	if ctx == nil || ctx.Err() != nil || manifest.runID != run.id ||
		len(manifest.byName) != len(phase6security.Slice6DesiredFinalNetworks()) ||
		!guestRevokeFixtureDigestGate(manifest.createdDigest) || len(plan.Networks) != 7 {
		return nil, errors.New("Guest E Product original network authority unavailable")
	}
	ordered := make([]phase6security.Network, 0, len(plan.Networks))
	ordered = append(ordered, plan.ServiceNetwork)
	for _, network := range plan.Networks {
		if network.Name != plan.ServiceNetwork.Name {
			ordered = append(ordered, network)
		}
	}
	if len(ordered) != 7 {
		return nil, errors.New("Guest E Product network count drift")
	}
	endpoints := make([]slice6ProductRuntimeEndpoint, 0, 7)
	for _, network := range ordered {
		original, ok := manifest.byName[network.Name]
		ip, err := phase6security.Slice6DesiredEndpointAddress(network.Name, plan.Principal.Name)
		if err != nil {
			ip, err = phase6security.Slice6DesiredFinalServiceEndpointAddress(network.Name, plan.Principal.Name)
		}
		if !ok || err != nil || ip == "" || original.NetworkID == "" {
			return nil, fmt.Errorf("Guest E Product original network %s endpoint unavailable", network.Name)
		}
		if network.Name == plan.ServiceNetwork.Name && ip != plan.SourceAddress {
			return nil, errors.New("Guest E Product SQL source address drift")
		}
		if slices.ContainsFunc(endpoints, func(entry slice6ProductRuntimeEndpoint) bool {
			return entry.ID == original.NetworkID
		}) {
			return nil, fmt.Errorf("Guest E Product original network %s ID reused", network.Name)
		}
		if err := slice6VerifyGuestRecoveryOriginalNetworkStatic(ctx, run, network, original.NetworkID); err != nil {
			return nil, fmt.Errorf("Guest E Product original network %s: %w", network.Name, err)
		}
		endpoints = append(endpoints, slice6ProductRuntimeEndpoint{Network: network,
			ID: original.NetworkID, IP: ip})
	}
	return endpoints, nil
}

func (manifest slice6GuestRecoveryNetworkManifest) guestNetworks(ctx context.Context,
	run slice6DockerRun, plan slice6GuestRuntimeLaunchPlan) (string, string, error) {
	if ctx == nil || ctx.Err() != nil || manifest.runID != run.id ||
		!guestRevokeFixtureDigestGate(manifest.createdDigest) ||
		plan.ProductNetwork.Name != "guest-product" ||
		plan.InternalNetwork.Name != "network-guest-runtime" ||
		plan.ProductIP == "" || plan.InternalIP == "" {
		return "", "", errors.New("Guest E original Guest network authority unavailable")
	}
	product := manifest.byName[plan.ProductNetwork.Name]
	internal := manifest.byName[plan.InternalNetwork.Name]
	if product.NetworkID == "" || internal.NetworkID == "" || product.NetworkID == internal.NetworkID ||
		slice6VerifyGuestRecoveryOriginalNetworkStatic(ctx, run, plan.ProductNetwork, product.NetworkID) != nil ||
		slice6VerifyGuestRecoveryOriginalNetworkStatic(ctx, run, plan.InternalNetwork, internal.NetworkID) != nil {
		return "", "", errors.New("Guest E original Guest network ID changed")
	}
	return product.NetworkID, internal.NetworkID, nil
}

func slice6VerifyGuestRecoveryOriginalNetworkStatic(ctx context.Context,
	run slice6DockerRun, expected phase6security.Network, id string) error {
	if ctx == nil || ctx.Err() != nil || len(id) != 64 || !lowerHexSlice6(id) {
		return errors.New("Guest E original network ID unavailable")
	}
	raw, commandErr, overflow := slice6DockerBounded(ctx, 64<<10, nil, "network", "inspect", id)
	defer clear(raw)
	var observed []struct {
		ID, Name, Driver     string
		Internal, EnableIPv6 bool
		Options, Labels      map[string]string
		IPAM                 struct{ Config []struct{ Subnet string } }
	}
	if commandErr != nil || overflow || json.Unmarshal(raw, &observed) != nil || len(observed) != 1 {
		return errors.New("Guest E original network inspect unavailable")
	}
	if observed[0].ID != id || observed[0].Name != expected.Name ||
		observed[0].Driver != "bridge" || observed[0].Internal != expected.Internal ||
		observed[0].EnableIPv6 || observed[0].Options["com.docker.network.bridge.gateway_mode_ipv4"] != expected.GatewayModeIPv4 ||
		observed[0].Labels[slice6RunLabel] != run.id {
		return errors.New("Guest E original network static identity drift")
	}
	if len(observed[0].IPAM.Config) != 1 || observed[0].IPAM.Config[0].Subnet != expected.IPv4Subnet {
		return errors.New("Guest E original network subnet drift")
	}
	return nil
}

func slice6VerifyGuestRecoveryCreatedName(ctx context.Context,
	run slice6DockerRun, id, name string) error {
	if ctx == nil || ctx.Err() != nil || len(id) != 64 || !lowerHexSlice6(id) ||
		name == "" || !strings.HasSuffix(name, "-"+run.id) {
		return errors.New("Guest E created PID1 name unavailable")
	}
	raw, err, overflow := slice6DockerBounded(ctx, 256, nil, "inspect", "--format", "{{.Name}}|{{.Id}}", id)
	defer clear(raw)
	if err != nil || overflow || !bytes.Equal(raw, []byte("/"+name+"|"+id+"\n")) {
		return errors.New("Guest E created PID1 name/ID drift")
	}
	return nil
}
