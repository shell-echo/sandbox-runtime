//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"reflect"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// The bootstrap receives one explicit allocation source through its run
// handle. The strict create primitive itself is never made idempotent.
type slice6ProfileNetworkSource interface {
	resolve(context.Context, slice6DockerRun, phase6security.Network) (phase6security.NetworkObservation, error)
}

type slice6LegacyProfileNetworkSource struct{}

func (slice6LegacyProfileNetworkSource) resolve(ctx context.Context, run slice6DockerRun,
	expected phase6security.Network) (phase6security.NetworkObservation, error) {
	return createSlice6ProfileNetwork(ctx, run, expected)
}

type slice6OriginalProfileNetworkSource struct {
	manifest slice6GuestRecoveryNetworkManifest
}

func (run slice6DockerRun) withGuestRecoveryOriginalNetworks(
	manifest slice6GuestRecoveryNetworkManifest) (slice6DockerRun, error) {
	if manifest.runID != run.id || len(manifest.byName) != len(phase6security.Slice6DesiredFinalNetworks()) ||
		!guestRevokeFixtureDigestGate(manifest.createdDigest) {
		return slice6DockerRun{}, errors.New("Guest E original allocation source unavailable")
	}
	copyOf := make(map[string]phase6security.NetworkObservation, len(manifest.byName))
	ids := make(map[string]bool, len(manifest.byName))
	for _, frozen := range phase6security.Slice6DesiredFinalNetworks() {
		observation, found := manifest.byName[frozen.Name]
		if !found || observation.Name != frozen.Name ||
			len(observation.NetworkID) != 64 || !lowerHexSlice6(observation.NetworkID) ||
			ids[observation.NetworkID] || !guestRevokeFixtureDigestGate(observation.InspectDigest) ||
			observation.Driver != "bridge" || observation.Internal != frozen.Internal ||
			observation.IPv6Enabled || observation.GatewayModeIPv4 != frozen.GatewayModeIPv4 ||
			observation.Subnet != frozen.IPv4Subnet || len(observation.ContainerIDs) != 0 ||
			len(observation.Endpoints) != 0 {
			return slice6DockerRun{}, errors.New("Guest E original allocation manifest drift")
		}
		ids[observation.NetworkID] = true
		copyOf[frozen.Name] = observation
	}
	run.networkSource = slice6OriginalProfileNetworkSource{manifest: slice6GuestRecoveryNetworkManifest{
		runID: manifest.runID, createdDigest: manifest.createdDigest, byName: copyOf}}
	return run, nil
}

func (run slice6DockerRun) resolveProfileNetwork(ctx context.Context,
	expected phase6security.Network) (phase6security.NetworkObservation, error) {
	if ctx == nil || ctx.Err() != nil || len(run.id) != 32 || !lowerHexSlice6(run.id) ||
		run.networkSource == nil {
		return phase6security.NetworkObservation{}, errors.New("Slice 6 network source unavailable")
	}
	return run.networkSource.resolve(ctx, run, expected)
}

func (source slice6OriginalProfileNetworkSource) resolve(ctx context.Context, run slice6DockerRun,
	expected phase6security.Network) (phase6security.NetworkObservation, error) {
	if ctx == nil || ctx.Err() != nil || source.manifest.runID != run.id ||
		len(source.manifest.byName) != len(phase6security.Slice6DesiredFinalNetworks()) ||
		!guestRevokeFixtureDigestGate(source.manifest.createdDigest) {
		return phase6security.NetworkObservation{}, errors.New("Guest E original network source drift")
	}
	var frozen phase6security.Network
	for _, candidate := range phase6security.Slice6DesiredFinalNetworks() {
		if candidate.Name == expected.Name {
			frozen = candidate
			break
		}
	}
	original, found := source.manifest.byName[expected.Name]
	if !found || frozen.Name == "" || !reflect.DeepEqual(expected, frozen) ||
		original.Name != expected.Name || len(original.NetworkID) != 64 ||
		!lowerHexSlice6(original.NetworkID) || original.Driver != "bridge" ||
		original.Internal != expected.Internal || original.IPv6Enabled ||
		original.GatewayModeIPv4 != expected.GatewayModeIPv4 ||
		original.Subnet != expected.IPv4Subnet ||
		!guestRevokeFixtureDigestGate(original.InspectDigest) ||
		slice6VerifyGuestRecoveryOriginalNetworkStatic(ctx, run, expected, original.NetworkID) != nil {
		return phase6security.NetworkObservation{}, errors.New("Guest E original network identity replaced or changed")
	}
	// Allocation identity only. Callers still re-observe their stage's live
	// members; the original empty observation is never a membership receipt.
	return original, nil
}
