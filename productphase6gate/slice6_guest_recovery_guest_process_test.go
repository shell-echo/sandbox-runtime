//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

type slice6GuestRecoveryGuestProcess struct {
	Run           slice6DockerRun
	Evidence      *slice6ReceiptEvidenceRun
	Slot          string
	ID            string
	Product       *slice6GuestRecoveryProductProcess
	ImageID       string
	ImageRef      string
	ProfileDigest string
	ConfigDigest  string
	Plan          slice6GuestRuntimeLaunchPlan
	ProductNetID  string
	InternalNetID string
	Capture       *slice6GuestRecoveryCapture
}

func slice6CreateGuestRecoveryGuestProcess(ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, prepared slice6GuestRuntimePrepared,
	socketVolumes, anchorFiles map[string]string,
	manifest slice6GuestRecoveryNetworkManifest, evidence *slice6ReceiptEvidenceRun,
	product *slice6GuestRecoveryProductProcess,
	slot, priorAID, beforeBDigest string,
	recorder *slice6GuestRecoveryERecorder) (*slice6GuestRecoveryGuestProcess, error) {
	if ctx == nil || ctx.Err() != nil || evidence == nil || evidence.check() != nil ||
		evidence.id != run.id || composed.GuestReceiptEvidence != evidence ||
		!composed.PrivateGuestReceipt || prepared.RunID != run.id ||
		prepared.ProfileDigest != composed.Profile.ProfileDigest ||
		prepared.GuestID == "" || prepared.Generation < 1 ||
		!guestRevokeFixtureDigestGate(prepared.StartupDigest) ||
		len(socketVolumes) != 68 || product == nil || product.Run.id != run.id ||
		product.Evidence != evidence || product.Capture == nil ||
		product.ProfileDigest != composed.Profile.ProfileDigest ||
		product.Capture.confirmStillRunning(ctx, run) != nil ||
		recorder == nil || recorder.runID != run.id {
		return nil, errors.New("Guest E Guest/Product source authority unavailable")
	}
	if slot == "guest-a" {
		if product.Slot != "product-a" || priorAID != "" || beforeBDigest != "" {
			return nil, errors.New("Guest E original Guest process order drift")
		}
	} else if slot == "guest-b" {
		if product.Slot != "product-b" || len(priorAID) != 64 || !lowerHexSlice6(priorAID) ||
			evidence.checkGuestRecoveryReplacementStart(slot, beforeBDigest, recorder) != nil ||
			!slice6GuestRecoveryProductPriorAbsent(ctx, priorAID) {
			return nil, errors.New("Guest E replacement Guest preceded A seal/removal")
		}
	} else {
		return nil, errors.New("Guest E Guest slot unavailable")
	}
	plan, err := slice6BuildGuestRuntimeLaunchPlan(composed.Profile)
	if err != nil || plan.Principal.ImageDigest != product.ImageID ||
		plan.Principal.ImageReference != product.ImageRef ||
		prepared.ConfigVolume != "sr-p6-config-guest-runtime-"+run.id ||
		slice6ValidateGuestStorageVolumes(ctx, run, prepared.Storage) != nil ||
		slice6VerifyGuestFixtureVolume(ctx, run, prepared.ConfigVolume) != nil {
		return nil, errors.New("Guest E Guest original config/storage/image drift")
	}
	productNetID, internalNetID, err := manifest.guestNetworks(ctx, run, plan)
	if err != nil || len(productNetID) != 64 || len(internalNetID) != 64 {
		return nil, errors.New("Guest E Guest original networks unavailable")
	}
	productOnNetwork := false
	for _, endpoint := range product.Endpoints {
		if endpoint.Network.Name == plan.ProductNetwork.Name && endpoint.ID == productNetID {
			productOnNetwork = true
		}
	}
	if !productOnNetwork {
		return nil, errors.New("Guest E Guest original Product edge changed")
	}
	args, err := slice6GuestRuntimeCreateArgumentsForSlot(ctx, run, composed.Profile, plan,
		productNetID, prepared.ConfigVolume, prepared.Storage, socketVolumes,
		anchorFiles, prepared.Seccomp, slot)
	if err != nil {
		return nil, err
	}
	created, err := run.docker(ctx, args...)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) || id == priorAID || id == product.ID {
		return nil, errors.New("Guest E Guest PID1 create unconfirmed")
	}
	if _, err := run.docker(ctx, "network", "connect", "--ip", plan.InternalIP, internalNetID, id); err != nil {
		return nil, errors.New("Guest E Guest original internal edge attach unavailable")
	}
	if err := slice6VerifyGuestRuntimeContainer(ctx, run, id, plan, productNetID,
		internalNetID, prepared.ConfigVolume, prepared.Storage, socketVolumes,
		anchorFiles, prepared.Seccomp); err != nil {
		return nil, err
	}
	name := "sr-p6-guest-runtime-" + run.id
	if slot == "guest-b" {
		name = "sr-p6-guest-runtime-b-" + run.id
	}
	if err := slice6VerifyGuestRecoveryCreatedName(ctx, run, id, name); err != nil {
		return nil, err
	}
	return &slice6GuestRecoveryGuestProcess{Run: run, Evidence: evidence,
		Slot: slot, ID: id, Product: product,
		ImageID: plan.Principal.ImageDigest, ImageRef: plan.Principal.ImageReference,
		ProfileDigest: composed.Profile.ProfileDigest, ConfigDigest: prepared.StartupDigest,
		Plan: plan, ProductNetID: productNetID, InternalNetID: internalNetID}, nil
}

func (process *slice6GuestRecoveryGuestProcess) start(ctx context.Context,
	recorder *slice6GuestRecoveryERecorder, beforeBDigest string) error {
	if process == nil || ctx == nil || ctx.Err() != nil || process.Capture != nil ||
		process.Evidence == nil || process.Evidence.check() != nil ||
		process.Run.id != process.Evidence.id || recorder == nil ||
		recorder.runID != process.Run.id || process.Product == nil ||
		process.Product.Capture == nil {
		return phase6guestreceipt.ErrUnavailable
	}
	startContext, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if process.Product.Capture.confirmStillRunning(startContext, process.Run) != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	var capture *slice6GuestRecoveryCapture
	var err error
	if process.Slot == "guest-b" {
		capture, err = slice6StartGuestRecoveryReplacementCaptureWithPreflight(ctx, startContext, process.Run,
			process.Evidence, process.Slot, process.ID, process.ImageID,
			process.ImageRef, process.ProfileDigest, process.ConfigDigest, beforeBDigest, recorder)
	} else if process.Slot == "guest-a" && beforeBDigest == "" {
		capture, err = slice6StartGuestRecoveryCaptureWithPreflight(ctx, startContext, process.Run,
			process.Evidence, process.Slot, process.ID, process.ImageID,
			process.ImageRef, process.ProfileDigest, process.ConfigDigest, recorder)
	} else {
		return phase6guestreceipt.ErrUnavailable
	}
	if err != nil {
		return errors.Join(errors.New("Guest E Guest PID1 attached capture start unavailable"), err)
	}
	process.Capture = capture
	if err := slice6AwaitGuestRecoveryRunning(startContext, capture, process.Run); err != nil {
		return errors.Join(errors.New("Guest E Guest PID1 running observation unavailable"), err)
	}
	if err := slice6VerifyGuestRuntimeRunningNetworks(startContext, process.Run, process.ID,
		process.Plan, process.ProductNetID, process.InternalNetID); err != nil {
		return err
	}
	deadline, _ := startContext.Deadline()
	if err := slice6AwaitGuestConnected(startContext, time.Until(deadline), 250*time.Millisecond,
		func(check context.Context) (bool, error) {
			member, inspectErr := slice6InspectProductRuntimeMember(check, process.Run, process.ID)
			if inspectErr != nil {
				return false, inspectErr
			}
			name := "/sr-p6-guest-runtime-" + process.Run.id
			if process.Slot == "guest-b" {
				name = "/sr-p6-guest-runtime-b-" + process.Run.id
			}
			if member.ID != process.ID || member.Name != name {
				return false, errors.New("Guest E Guest running identity drift")
			}
			return true, nil
		}, func(check context.Context) (int, error) {
			return slice6ProbeGuestReady(check, process.ID)
		}); err != nil {
		return err
	}
	return process.Product.Capture.confirmStillRunning(startContext, process.Run)
}
