//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type slice6GuestRuntimePrepared struct {
	RunID         string
	ProfileDigest string
	GuestID       string
	Generation    int64
	ConfigVolume  string
	Storage       map[string]string
	StartupDigest string
	Seccomp       string
}

// Prepare once for Guest A. Formal E reuses this exact config and three
// storage volume identities for B; it never reruns provisioning on restart.
func slice6PrepareGuestRuntimeResources(t *testing.T, ctx context.Context,
	run slice6DockerRun, composed slice6VaultComposedInputs,
	plan slice6GuestRuntimeLaunchPlan, binding slice6GuestBindingFixtureReceipt,
	preIssuerShellDigest string) (slice6GuestRuntimePrepared, error) {
	if t == nil || ctx == nil || ctx.Err() != nil ||
		binding.Protocol != slice6GuestBindingFixtureProtocol || !binding.IdempotentReplay ||
		binding.RunID != run.id || binding.ProfileDigest != composed.Profile.ProfileDigest ||
		binding.GuestID == "" || binding.BindingGeneration != 1 ||
		plan.Principal.Name != "guest-runtime" {
		return slice6GuestRuntimePrepared{}, errors.New("Guest original resource authority unavailable")
	}
	if err := slice6PreflightGuestStorageCapacity(ctx, run); err != nil {
		return slice6GuestRuntimePrepared{}, err
	}
	shellDigest, err := slice6MeasureGuestShell(ctx, run, plan.Principal)
	if err != nil || shellDigest != preIssuerShellDigest || preIssuerShellDigest == "" {
		return slice6GuestRuntimePrepared{}, errors.New("selected Guest shell changed after pre-issuer measurement")
	}
	files, err := slice6BuildGuestRuntimeInputs(composed, run.id, binding.GuestID,
		binding.BindingGeneration, shellDigest)
	if err != nil {
		return slice6GuestRuntimePrepared{}, err
	}
	startupDigest := slice6ReceiptConfigDigest(files[phase6security.Slice6StartupConfigFile])
	archive, err := phase6security.BuildSlice6PrivateConfigArchive(composed.Profile, "guest-runtime", files)
	for _, value := range files {
		clear(value)
	}
	if err != nil {
		return slice6GuestRuntimePrepared{}, err
	}
	slice6PrepareOneControllerPrivateConfig(t, ctx, run, composed.Profile, "guest-runtime", archive)
	storage := slice6PrepareGuestStorageVolumes(t, ctx, run, plan.Principal.UID, plan.Principal.GID)
	if err := slice6ValidateGuestStorageVolumes(ctx, run, storage); err != nil {
		return slice6GuestRuntimePrepared{}, err
	}
	root, err := filepath.Abs("..")
	if err != nil {
		return slice6GuestRuntimePrepared{}, err
	}
	return slice6GuestRuntimePrepared{
		RunID: run.id, ProfileDigest: composed.Profile.ProfileDigest,
		GuestID: binding.GuestID, Generation: binding.BindingGeneration,
		ConfigVolume: "sr-p6-config-guest-runtime-" + run.id,
		Storage:      storage, StartupDigest: startupDigest,
		Seccomp: filepath.Join(root, "profiles", "phase6", "security", "originals", "moby-default-seccomp-836ae4d3.json")}, nil
}
