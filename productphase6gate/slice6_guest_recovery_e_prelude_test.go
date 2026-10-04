//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// The shared Vault/Controller/PG/agent bootstrap hands these exact observed
// resources to E. This runner owns Product/Guest A and B, not the old
// component's hidden PG fault, v1 receipt, or stop callbacks.
type slice6GuestRecoveryEBootstrap struct {
	Run                  slice6DockerRun
	Evidence             *slice6ReceiptEvidenceRun
	Composed             slice6VaultComposedInputs
	Manifest             slice6GuestRecoveryNetworkManifest
	PostgresID           string
	VaultID              string
	Migration            slice6ProductMigrationExitProof
	Binding              slice6GuestBindingFixtureReceipt
	PreIssuerShellDigest string
	ProductSockets       map[string]string
	GuestSockets         map[string]string
	Anchors              map[string]string
	ProductObserver      slice6ProductRuntimeObserver
}

func slice6GuestRecoveryPostgresEndpoints(ctx context.Context, run slice6DockerRun,
	profile phase6security.Profile,
	manifest slice6GuestRecoveryNetworkManifest) ([]slice6PostgresEndpoint, error) {
	if ctx == nil || ctx.Err() != nil || manifest.runID != run.id ||
		len(manifest.byName) != len(phase6security.Slice6DesiredFinalNetworks()) {
		return nil, errors.New("Guest E PostgreSQL original network manifest unavailable")
	}
	byName := make(map[string]phase6security.Network, len(profile.Networks))
	for _, network := range profile.Networks {
		if byName[network.Name].Name != "" {
			return nil, errors.New("Guest E PostgreSQL duplicate profile network")
		}
		byName[network.Name] = network
	}
	endpoints := make([]slice6PostgresEndpoint, 0, 9)
	for _, path := range phase6security.Slice6DesiredFinalExternalTransports() {
		if path.Service != "postgres" {
			continue
		}
		network := byName[path.Network]
		original := manifest.byName[path.Network]
		ip, err := phase6security.Slice6DesiredFinalServiceEndpointAddress(path.Network, "postgres")
		if err != nil || network.Name != path.Network || original.NetworkID == "" ||
			slice6VerifyGuestRecoveryOriginalNetworkStatic(ctx, run,
				network, original.NetworkID) != nil {
			return nil, errors.New("Guest E PostgreSQL original bridge drift")
		}
		endpoints = append(endpoints, slice6PostgresEndpoint{Network: network,
			ID: original.NetworkID, IP: ip})
	}
	if len(endpoints) != 9 {
		return nil, errors.New("Guest E PostgreSQL nine original bridges unavailable")
	}
	return endpoints, nil
}

func slice6GuestRecoveryAStageMembers(run slice6DockerRun, postgresID, productID string,
	migration *slice6ProductMigrationExitProof) (map[string]slice6GuestPGMember, error) {
	if len(productID) != 64 || !lowerHexSlice6(productID) || migration == nil ||
		migration.RunID != run.id || migration.PostgresID != postgresID ||
		len(migration.ContainerID) != 64 || !lowerHexSlice6(migration.ContainerID) ||
		len(migration.RemovalRaw) == 0 || migration.ContainerID == productID {
		return nil, errors.New("Guest E original Product/migration identity unavailable")
	}
	members := make(map[string]slice6GuestPGMember, 9)
	for _, path := range phase6security.Slice6DesiredFinalExternalTransports() {
		if path.Service != "postgres" {
			continue
		}
		switch slice6GuestOperatorAStageState(path.Dialer) {
		case "started":
			members[path.Dialer] = slice6GuestPGMember{State: "started", ID: productID}
		case "migrated_exited_removed":
			members[path.Dialer] = slice6GuestPGMember{State: "migrated_exited_removed",
				ID: migration.ContainerID, Migration: migration}
		case "not_started":
			members[path.Dialer] = slice6GuestPGMember{State: "not_started"}
		default:
			return nil, errors.New("Guest E unreviewed PostgreSQL dialer stage")
		}
	}
	return members, slice6ValidateGuestOperatorAStageMembers(members)
}

func slice6RunGuestRecoveryEAfterBootstrap(t *testing.T, ctx context.Context,
	bootstrap slice6GuestRecoveryEBootstrap) (slice6GuestRecoveryPrecleanupInput, string, error) {
	run, evidence, composed := bootstrap.Run, bootstrap.Evidence, bootstrap.Composed
	originalSource, original := run.networkSource.(slice6OriginalProfileNetworkSource)
	if t == nil || ctx == nil || ctx.Err() != nil || !original ||
		originalSource.manifest.runID != run.id ||
		originalSource.manifest.createdDigest != bootstrap.Manifest.createdDigest ||
		!reflect.DeepEqual(originalSource.manifest.byName, bootstrap.Manifest.byName) ||
		evidence == nil || evidence.check() != nil || evidence.id != run.id ||
		composed.GuestReceiptEvidence != evidence || !composed.PrivateGuestReceipt ||
		bootstrap.Binding.RunID != run.id || !bootstrap.Binding.IdempotentReplay ||
		bootstrap.Binding.ProfileDigest != composed.Profile.ProfileDigest ||
		bootstrap.Migration.RunID != run.id || bootstrap.Migration.PostgresID != bootstrap.PostgresID ||
		len(bootstrap.Migration.ContainerID) != 64 ||
		!lowerHexSlice6(bootstrap.Migration.ContainerID) ||
		len(bootstrap.Migration.RemovalRaw) == 0 ||
		len(bootstrap.PostgresID) != 64 || !lowerHexSlice6(bootstrap.PostgresID) ||
		len(bootstrap.VaultID) != 64 || !lowerHexSlice6(bootstrap.VaultID) {
		return slice6GuestRecoveryPrecleanupInput{}, "", errors.New("Guest E shared bootstrap handoff unavailable")
	}
	recorder, err := newSlice6GuestRecoveryERecorder(run.id)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	origin, err := evidence.captureGuestRecoveryImplicitOrigin(ctx, bootstrap.VaultID)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	productA, err := slice6CreateGuestRecoveryProductProcess(ctx, run, composed,
		bootstrap.PostgresID, bootstrap.ProductSockets, bootstrap.Anchors,
		bootstrap.ProductObserver, bootstrap.Manifest, evidence,
		"product-a", "", "", recorder)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	startErr := productA.start(ctx, recorder, "")
	if productA.Capture != nil {
		defer productA.Capture.abort()
	}
	if startErr != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", startErr
	}
	guestPlan, err := slice6BuildGuestRuntimeLaunchPlan(composed.Profile)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	prepared, err := slice6PrepareGuestRuntimeResources(t, ctx, run, composed,
		guestPlan, bootstrap.Binding, bootstrap.PreIssuerShellDigest)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	guestA, err := slice6CreateGuestRecoveryGuestProcess(ctx, run, composed, prepared,
		bootstrap.GuestSockets, bootstrap.Anchors, bootstrap.Manifest, evidence,
		productA, "guest-a", "", "", recorder)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	startErr = guestA.start(ctx, recorder, "")
	if guestA.Capture != nil {
		defer guestA.Capture.abort()
	}
	if startErr != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", startErr
	}
	var postgres phase6security.ExternalService
	for _, service := range composed.Profile.External {
		if service.Name == "postgres" {
			postgres = service
		}
	}
	target := slice6GuestOperatorTarget{Run: run, PostgresID: bootstrap.PostgresID,
		ImageID: postgres.ImageDigest, ImageRef: postgres.ImageReference,
		UID: 70, GID: 70, TenantID: "tenant-phase6-" + run.id,
		WorkspaceID: bootstrap.Binding.WorkspaceID, SlotKey: "primary-code",
		SlotProfileID: "coding-shell-v1", SlotGeneration: bootstrap.Binding.SlotGeneration,
		GuestID: bootstrap.Binding.GuestID, BindingGeneration: bootstrap.Binding.BindingGeneration}
	endpoints, err := slice6GuestRecoveryPostgresEndpoints(ctx, run, composed.Profile,
		bootstrap.Manifest)
	if err != nil || !target.valid() {
		return slice6GuestRecoveryPrecleanupInput{}, "", errors.New("Guest E formal PostgreSQL target unavailable")
	}
	members, err := slice6GuestRecoveryAStageMembers(run, bootstrap.PostgresID,
		productA.ID, &bootstrap.Migration)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	source, err := slice6ProveGuestOperatorFormalSource(ctx, target, composed.Profile,
		endpoints, members, evidence)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	var productBridge slice6PostgresEndpoint
	for _, endpoint := range endpoints {
		if endpoint.Network.Name == "service-product-postgres" {
			productBridge = endpoint
		}
	}
	productIP, productIPErr := phase6security.Slice6DesiredFinalServiceEndpointAddress(
		"guest-product", "product-runtime")
	if productIPErr != nil {
		productIP, productIPErr = phase6security.Slice6DesiredEndpointAddress(
			"guest-product", "product-runtime")
	}
	if productBridge.ID == "" || productIPErr != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", errors.New("Guest E original fault endpoints unavailable")
	}
	pgEdge := slice6ProductPGFaultEdge{Run: run, ProductID: productA.ID,
		PostgresID: bootstrap.PostgresID, NetworkName: productBridge.Network.Name,
		NetworkID: productBridge.ID, ProductIP: productA.SourceAddress,
		PostgresIP: productBridge.IP, PostgresImageID: postgres.ImageDigest,
		ImageRef: postgres.ImageReference}
	guestEdge := slice6GuestRecoveryEdge{Run: run, ProductID: productA.ID,
		GuestID: guestA.ID, ProductNetworkName: guestPlan.ProductNetwork.Name,
		ProductNetworkID: guestA.ProductNetID, ProductIP: productIP,
		GuestIP: guestPlan.ProductIP, RuntimeNetworkName: guestPlan.InternalNetwork.Name,
		RuntimeNetworkID: guestA.InternalNetID, GuestRuntimeIP: guestPlan.InternalIP}
	return slice6RunGuestRecoveryE29(ctx, slice6GuestRecoveryESequenceInput{
		Run: run, Evidence: evidence, Composed: composed, Source: source,
		Target: target, ProductA: productA, GuestA: guestA,
		PGEdge: pgEdge, GuestEdge: guestEdge, Manifest: bootstrap.Manifest,
		Prepared: prepared, ProductSockets: bootstrap.ProductSockets,
		GuestSockets: bootstrap.GuestSockets, Anchors: bootstrap.Anchors,
		VaultOrigin: origin, Recorder: recorder})
}
