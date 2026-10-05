package dockercontrol

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	codingimage "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/image"
)

var ErrInvalidCodingCompletionObservation = errors.New("invalid private Coding physical completion observation")

// codingCompletionObservation is Control-private evidence from one bounded
// original-daemon read sequence. It is not a caller-supplied completion
// digest, a Provider terminal result, a late-effect quiescence proof, or a
// durable receipt by itself. Raw Docker host paths are never retained. The
// safe object/image/root projections are bound to the original document
// digests so a later private reviewer can recheck more than a caller bool.
type codingCompletionObservation struct {
	AuthorityDigest      string
	EffectID             string
	ProfileDigest        string
	PlanDigest           string
	TemplateDigest       string
	ReceiptRevision      uint64
	Daemon               CodingDaemonObservation
	RuntimeID            string
	InitialRuntimeDigest string
	FinalRuntimeDigest   string
	ImageDescriptorProof string
	ImageInspectDigest   string
	SelectedImageDigest  string
	ArchiveDigests       [3]string
	ExactInventoryDigest string
	InitialInventory     CodingResourceInventory
	FinalInventory       CodingResourceInventory
	Image                phase6security.DockerImageObservation
	ArchiveRoots         [3]codingEmptyRootObservation
	InitialRuntime       codingRuntimeSecurityProjection
	FinalRuntime         codingRuntimeSecurityProjection
	CompletionDigest     string
}

type codingEmptyRootObservation struct {
	Target        string
	StatName      string
	StatMode      uint32
	StatSize      int64
	ArchiveName   string
	ArchiveUID    int
	ArchiveGID    int
	ArchiveMode   int64
	ArchiveSize   int64
	ArchiveDigest string
}

// observeCompleted keeps the same ten-second deadline and one frozen SDK
// client across admission, original-daemon Info, whole-effect inventory,
// pinned image/config validation, initial empty-volume ownership, final
// object remapping and Info. It is intentionally not connected to the
// durable Completed transition until a real source/gate and review exist.
func (o *codingUnixObserver) observeCompleted(ctx context.Context, receipt CodingReceipt,
	receiptRevision uint64) (codingCompletionObservation, error) {
	if o == nil || ctx == nil || ctx.Err() != nil || receiptRevision == 0 ||
		o.bounded == nil || o.binding.Validate() != nil ||
		receipt.Status != ReceiptUnknown || receipt.Authority != o.authority ||
		receipt.AuthorityDigest != o.authority.Digest() || receipt.CompletionDigest != "" ||
		receipt.CleanupAuthority != (CodingCleanupAuthority{}) {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	boundedCtx, cancel := context.WithTimeout(ctx, maxCodingInventoryDuration)
	defer cancel()
	if !o.acquire(boundedCtx) {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	defer o.release()
	if o.api == nil || o.bounded.archiveID != "" || boundedCtx.Err() != nil {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	o.stage = "source-binding"
	set, err := NewCodingResourceSet(o.binding, o.authority)
	if err != nil || o.template.BindPlan(o.binding.Plan) != nil {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	policySum := sha256.Sum256(o.policy)
	if len(o.policy) == 0 || len(o.policy) > 64<<10 ||
		"sha256:"+hex.EncodeToString(policySum[:]) != o.template.SeccompPolicyDigest {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	expectedLabels := map[CodingResourceRole]map[string]string{}
	for _, role := range []CodingResourceRole{CodingPreparationRole, CodingRuntimeRole} {
		labels, err := set.ContainerLabels(role, o.template, o.documents)
		if err != nil {
			return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
		}
		expectedLabels[role] = labels
	}
	var slot codingidentity.Slot
	for _, candidate := range o.template.Slots {
		if candidate.ID == o.authority.SlotID {
			slot = candidate
		}
	}
	if slot.ID == "" {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	o.stage = "daemon-before"
	before, err := ObserveCodingDaemon(boundedCtx, o.api, o.binding.EndpointScopeDigest)
	if err != nil || before.MatchBinding(o.binding) != nil || before.Platform != o.template.Image.Platform {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	var initial CodingResourceInventory
	o.stage = "initial-inventory"
	if readCodingInventoryObjects(boundedCtx, o.api, set, expectedLabels, &initial) != nil ||
		initial.Containers[0].Present || !initial.Containers[1].Present {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	initial.Daemon = before
	for _, volume := range initial.Volumes {
		if !volume.Present {
			return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
		}
	}
	runtimeID := initial.Containers[1].ID
	if !codingArchiveRuntimeID.MatchString(runtimeID) {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	runtimeName, _ := set.ContainerName(CodingRuntimeRole)
	o.stage = "initial-runtime"
	inspect, err := o.api.ContainerInspect(boundedCtx, runtimeName, client.ContainerInspectOptions{})
	if err != nil || validateCodingRuntimeInspect(inspect.Container, runtimeID, runtimeName,
		expectedLabels[CodingRuntimeRole], o.template, slot, set.Mounts(), string(o.policy)) != nil {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	initialRuntime, err := projectCodingRuntimeSecurity(inspect.Container)
	if err != nil {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	var rawImage bytes.Buffer
	o.stage = "image-index"
	imageIndex, err := o.api.ImageInspect(boundedCtx, o.template.Image.Reference,
		client.ImageInspectWithRawResponse(&rawImage))
	if err != nil || imageIndex.Descriptor == nil ||
		imageIndex.Descriptor.Digest.String() != o.template.Image.Descriptor.Digest ||
		imageIndex.Descriptor.Size != o.template.Image.Descriptor.Size {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	platform, ok := codingOCIPlatform(o.template.Image.Platform)
	if !ok {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	var rawSelected bytes.Buffer
	o.stage = "image-selected"
	selected, err := o.api.ImageInspect(boundedCtx, o.template.Image.Reference,
		client.ImageInspectWithPlatform(&platform), client.ImageInspectWithRawResponse(&rawSelected))
	if err != nil || !validCodingSelectedImage(selected, o.template) {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	o.stage = "image-chain"
	imageProof, err := phase6security.ObserveDockerRuntimeImage(
		codingInspectArray(inspect.Raw), codingInspectArray(rawImage.Bytes()),
		o.template.Image.Location, o.template.Image.IdentityKind, o.template.Image.Reference,
		o.template.Image.Descriptor.Digest, o.template.Image.Platform,
		o.template.Image.SelectedManifestDigest, o.template.Image.ConfigDigest, o.documents)
	if err != nil || imageProof.ContainerID != runtimeID {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	o.bounded.archiveID = runtimeID
	defer func() { o.bounded.archiveID = "" }()
	var archiveDigests [3]string
	var archiveRoots [3]codingEmptyRootObservation
	for index, mount := range set.Mounts() {
		o.stage = []string{"archive-inputs", "archive-workspace", "archive-outputs"}[index]
		result, err := o.api.CopyFromContainer(boundedCtx, runtimeID,
			client.CopyFromContainerOptions{SourcePath: mount.Target})
		if err != nil || result.Content == nil || result.Stat.Name != strings.TrimPrefix(mount.Target, "/") {
			return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
		}
		archive, readErr := io.ReadAll(result.Content)
		closeErr := result.Content.Close()
		if readErr != nil || closeErr != nil || len(archive) == 0 || len(archive) > maxCodingArchiveResponseBytes {
			return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
		}
		archiveDigests[index] = digest(append([]byte("sandbox-runtime/docker-control-coding-empty-root/v1\x00"), archive...))
		archiveReader := tar.NewReader(bytes.NewReader(archive))
		archiveHeader, headerErr := archiveReader.Next()
		if headerErr != nil || archiveHeader == nil {
			return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
		}
		archiveRoots[index] = codingEmptyRootObservation{Target: mount.Target,
			StatName: result.Stat.Name, StatMode: uint32(result.Stat.Mode), StatSize: result.Stat.Size,
			ArchiveName: archiveHeader.Name, ArchiveUID: archiveHeader.Uid,
			ArchiveGID: archiveHeader.Gid, ArchiveMode: archiveHeader.Mode,
			ArchiveSize: archiveHeader.Size, ArchiveDigest: archiveDigests[index]}
	}
	o.stage = "final-runtime"
	finalInspect, err := o.api.ContainerInspect(boundedCtx, runtimeName, client.ContainerInspectOptions{})
	if err != nil || validateCodingRuntimeInspect(finalInspect.Container, runtimeID, runtimeName,
		expectedLabels[CodingRuntimeRole], o.template, slot, set.Mounts(), string(o.policy)) != nil {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	finalRuntime, err := projectCodingRuntimeSecurity(finalInspect.Container)
	if err != nil {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	var final CodingResourceInventory
	o.stage = "final-inventory"
	if readCodingInventoryObjects(boundedCtx, o.api, set, expectedLabels, &final) != nil ||
		final.Containers != initial.Containers || final.Volumes != initial.Volumes {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	o.stage = "daemon-after"
	after, err := ObserveCodingDaemon(boundedCtx, o.api, o.binding.EndpointScopeDigest)
	if err != nil || after != before || after.MatchBinding(o.binding) != nil || boundedCtx.Err() != nil {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	final.Daemon = after
	inventoryDocument, err := json.Marshal(initial)
	if err != nil {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	proof := codingCompletionObservation{AuthorityDigest: o.authority.Digest(), EffectID: o.authority.EffectID,
		ProfileDigest: o.binding.ProfileDigest, PlanDigest: o.binding.PlanDigest,
		TemplateDigest: o.binding.Plan.TemplateDigest, ReceiptRevision: receiptRevision,
		Daemon: before, RuntimeID: runtimeID,
		InitialRuntimeDigest: digest(append([]byte("sandbox-runtime/docker-control-coding-runtime-inspect/v1\x00"), inspect.Raw...)),
		FinalRuntimeDigest:   digest(append([]byte("sandbox-runtime/docker-control-coding-runtime-inspect/v1\x00"), finalInspect.Raw...)),
		ImageDescriptorProof: imageProof.DescriptorProofDigest, ImageInspectDigest: imageProof.ImageInspectDigest,
		SelectedImageDigest:  digest(append([]byte("sandbox-runtime/docker-control-coding-selected-image/v1\x00"), rawSelected.Bytes()...)),
		ArchiveDigests:       archiveDigests,
		ExactInventoryDigest: digest(append([]byte("sandbox-runtime/docker-control-coding-inventory/v1\x00"), inventoryDocument...)),
		InitialInventory:     initial, FinalInventory: final, Image: imageProof, ArchiveRoots: archiveRoots,
		InitialRuntime: initialRuntime, FinalRuntime: finalRuntime}
	proofDocument, err := json.Marshal(proof)
	if err != nil {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	proof.CompletionDigest = digest(append([]byte("sandbox-runtime/docker-control-coding-completion/v1\x00"), proofDocument...))
	o.stage = "proof-recheck"
	if proof.recheck(o.binding, o.authority, o.template, o.documents, o.policy) != nil {
		return codingCompletionObservation{}, ErrInvalidCodingCompletionObservation
	}
	o.stage = "complete"
	return proof, nil
}

func codingInspectArray(raw []byte) []byte {
	result := make([]byte, 0, len(raw)+2)
	result = append(result, '[')
	result = append(result, raw...)
	return append(result, ']')
}

func validCodingSelectedImage(selected client.ImageInspectResult,
	template phase6security.CodingRuntimeTemplateV2) bool {
	manifest, err := codingimage.LockedManifest()
	if err != nil || selected.Descriptor == nil || selected.Descriptor.Platform == nil ||
		selected.Descriptor.Digest.String() != template.Image.SelectedManifestDigest ||
		selected.Descriptor.MediaType != "application/vnd.oci.image.manifest.v1+json" ||
		selected.Descriptor.Size != template.Image.SelectedManifestSize ||
		!codingSelectedPlatformMatches(selected.Descriptor.Platform.OS,
			selected.Descriptor.Platform.Architecture, selected.Descriptor.Platform.Variant,
			template.Image.Platform) || selected.Config == nil {
		return false
	}
	return slices.Equal(selected.Config.Env, template.Environment) &&
		len(selected.Config.Entrypoint) == 0 && slices.Equal(selected.Config.Cmd, manifest.Runtime.Command) &&
		len(selected.Config.Volumes) == 0 && selected.Config.Healthcheck == nil &&
		selected.Config.WorkingDir == template.WorkingDirectory &&
		selected.Config.User == fmt.Sprintf("%d:%d", manifest.Security.UID, manifest.Security.GID)
}

func validateCodingRuntimeInspect(observed container.InspectResponse, id, name string,
	labels map[string]string, template phase6security.CodingRuntimeTemplateV2,
	slot codingidentity.Slot, mounts []codingidentity.VolumeMount, policy string) error {
	startedAt := time.Time{}
	if observed.State != nil {
		startedAt, _ = time.Parse(time.RFC3339Nano, observed.State.StartedAt)
	}
	if observed.ID != id || observed.Name != "/"+name || observed.State == nil ||
		observed.State.Status != "running" || !observed.State.Running || observed.State.Pid <= 0 ||
		observed.State.Paused || observed.State.Restarting || observed.State.OOMKilled || observed.State.Dead ||
		observed.State.ExitCode != 0 || observed.State.Error != "" || startedAt.IsZero() ||
		observed.RestartCount != 0 || len(observed.ExecIDs) != 0 || observed.Config == nil ||
		len(observed.Config.ExposedPorts) != 0 || observed.NetworkSettings == nil ||
		len(observed.NetworkSettings.Ports) != 0 || len(observed.NetworkSettings.Networks) != 1 ||
		observed.NetworkSettings.Networks["none"] == nil ||
		matchEffectiveCodingContainerLabels(labels, observed.Config.Labels) != nil ||
		codingProbeContainerMismatch(observed, template, slot, mounts,
			fmt.Sprintf("%d:%d", slot.WorkloadUID, slot.WorkloadGID), policy, codingProbeRuntime) != "" {
		return ErrInvalidCodingCompletionObservation
	}
	return nil
}
