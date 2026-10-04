//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// E owns the whole PID1 lifecycle. This handle does not inject the old
// component's pre-Guest PG fault, collect v1 receipts, or stop a container.
type slice6GuestRecoveryProductProcess struct {
	Run           slice6DockerRun
	Evidence      *slice6ReceiptEvidenceRun
	Slot          string
	ID            string
	ImageID       string
	ImageRef      string
	ProfileDigest string
	ConfigDigest  string
	PostgresID    string
	SourceAddress string
	Profile       phase6security.Profile
	Plan          slice6ProductRuntimeLaunchPlan
	Endpoints     []slice6ProductRuntimeEndpoint
	AnchorFiles   map[string]string
	Observer      slice6ProductRuntimeObserver
	Capture       *slice6GuestRecoveryCapture
}

func slice6CreateGuestRecoveryProductProcess(ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, postgresID string,
	socketVolumes, anchorFiles map[string]string, observer slice6ProductRuntimeObserver,
	manifest slice6GuestRecoveryNetworkManifest, evidence *slice6ReceiptEvidenceRun,
	slot, priorAID, beforeBDigest string,
	recorder *slice6GuestRecoveryERecorder) (*slice6GuestRecoveryProductProcess, error) {
	if ctx == nil || ctx.Err() != nil || evidence == nil || evidence.check() != nil ||
		evidence.id != run.id || composed.GuestReceiptEvidence != evidence ||
		!composed.PrivateGuestReceipt || len(socketVolumes) != 74 ||
		len(postgresID) != 64 || !lowerHexSlice6(postgresID) ||
		slice6VerifyApprovedProductRuntimeObserver(observer) != nil ||
		recorder == nil || recorder.runID != run.id {
		return nil, errors.New("Guest E Product source authority unavailable")
	}
	if slot != "product-a" && slot != "product-b" {
		return nil, errors.New("Guest E Product slot unavailable")
	}
	if slot == "product-a" {
		if priorAID != "" || beforeBDigest != "" {
			return nil, errors.New("Guest E original Product has replacement authority")
		}
	} else {
		if len(priorAID) != 64 || !lowerHexSlice6(priorAID) ||
			evidence.checkGuestRecoveryReplacementStart(slot, beforeBDigest, recorder) != nil ||
			!slice6GuestRecoveryProductPriorAbsent(ctx, priorAID) {
			return nil, errors.New("Guest E Product replacement preceded A seal/removal")
		}
	}
	plan, err := slice6BuildProductRuntimeLaunchPlan(composed.Profile)
	if err != nil {
		return nil, err
	}
	config, err := slice6BuildProductRuntimeConfig(composed)
	if err != nil {
		return nil, err
	}
	configDigest := slice6ReceiptConfigDigest(config)
	clear(config)
	endpoints, err := manifest.productEndpoints(ctx, run, plan)
	if err != nil || len(endpoints) != 7 {
		return nil, errors.New("Guest E Product original endpoints unavailable")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		return nil, errors.New("Guest E Product source root unavailable")
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "originals", "moby-default-seccomp-836ae4d3.json")
	seccompRaw, err := os.ReadFile(seccomp)
	seccompSHA := sha256.Sum256(seccompRaw)
	clear(seccompRaw)
	if err != nil || plan.Principal.SeccompDigest != "sha256:"+hex.EncodeToString(seccompSHA[:]) {
		return nil, errors.New("Guest E Product seccomp source drift")
	}
	name := "sr-p6-product-runtime-" + run.id
	if slot == "product-b" {
		name = "sr-p6-product-runtime-b-" + run.id
	}
	args, err := slice6ProductRuntimeCreateArguments(run, plan, endpoints, seccomp,
		socketVolumes, anchorFiles, composed.Profile, name)
	if err != nil {
		return nil, err
	}
	created, err := run.docker(ctx, args...)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) || id == priorAID {
		return nil, errors.New("Guest E Product original PID1 create unconfirmed")
	}
	// If a later connect/inspect fails, the outer run-label cleanup owns this
	// exact ID. E must not start B from a partial A creation.
	for _, endpoint := range endpoints[1:] {
		if _, err := run.docker(ctx, "network", "connect", "--ip", endpoint.IP, endpoint.ID, id); err != nil {
			return nil, errors.New("Guest E Product original network attach unavailable")
		}
	}
	if err := slice6VerifyProductRuntimeContainer(ctx, run, id, plan, endpoints,
		seccomp, socketVolumes, anchorFiles, composed.Profile); err != nil {
		return nil, err
	}
	if err := slice6VerifyGuestRecoveryCreatedName(ctx, run, id, name); err != nil {
		return nil, err
	}
	return &slice6GuestRecoveryProductProcess{Run: run, Evidence: evidence,
		Slot: slot, ID: id, ImageID: plan.Principal.ImageDigest,
		ImageRef: plan.Principal.ImageReference, ProfileDigest: composed.Profile.ProfileDigest,
		ConfigDigest: configDigest, PostgresID: postgresID, SourceAddress: plan.SourceAddress,
		Profile: composed.Profile, Plan: plan, Endpoints: endpoints,
		AnchorFiles: anchorFiles, Observer: observer}, nil
}

func slice6GuestRecoveryProductPriorAbsent(ctx context.Context, id string) bool {
	if ctx == nil || ctx.Err() != nil || len(id) != 64 || !lowerHexSlice6(id) {
		return false
	}
	raw, err, overflow := slice6DockerBounded(ctx, 512, nil, "inspect", id)
	defer clear(raw)
	return err != nil && !overflow && slice6GuestRecoveryExactOriginMissing(raw, id, false)
}

func (process *slice6GuestRecoveryProductProcess) start(ctx context.Context,
	recorder *slice6GuestRecoveryERecorder, beforeBDigest string) error {
	if ctx == nil || ctx.Err() != nil || process == nil || process.Capture != nil ||
		process.Evidence == nil || process.Evidence.check() != nil ||
		process.Run.id != process.Evidence.id || recorder == nil ||
		recorder.runID != process.Run.id {
		return phase6guestreceipt.ErrUnavailable
	}
	// Product readiness already has a 20s observer plus 8s command budget.
	// Start that same absolute budget before collector preflight/inspection,
	// without shortening the attached stdout collector's PID1 lifetime.
	startContext, cancel := context.WithTimeout(ctx, 28*time.Second)
	defer cancel()
	var capture *slice6GuestRecoveryCapture
	var err error
	if process.Slot == "product-b" {
		capture, err = slice6StartGuestRecoveryReplacementCaptureWithPreflight(ctx, startContext, process.Run,
			process.Evidence, process.Slot, process.ID, process.ImageID,
			process.ImageRef, process.ProfileDigest, process.ConfigDigest, beforeBDigest, recorder)
	} else if process.Slot == "product-a" && beforeBDigest == "" {
		capture, err = slice6StartGuestRecoveryCaptureWithPreflight(ctx, startContext, process.Run,
			process.Evidence, process.Slot, process.ID, process.ImageID,
			process.ImageRef, process.ProfileDigest, process.ConfigDigest, recorder)
	} else {
		return phase6guestreceipt.ErrUnavailable
	}
	if err != nil {
		return err
	}
	process.Capture = capture
	if err := capture.observeRunning(startContext, process.Run); err != nil {
		return err
	}
	if _, err := slice6ObserveProductReady(startContext, process.Run, process.Profile,
		process.Plan, process.Endpoints, process.AnchorFiles, process.Observer, http.StatusOK, 20); err != nil {
		return err
	}
	return slice6VerifyProductRuntimeSQLSession(startContext, process.PostgresID, process.SourceAddress)
}
