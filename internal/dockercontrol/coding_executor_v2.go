package dockercontrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"time"

	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// CodingExecutorV2 owns only create and Completed-only cleanup. It has no
// generic Docker, exec, terminal, archive-upload, or historical Unknown
// retirement port. The caller owns the existing ledger's lifetime lock.
type CodingExecutorV2 struct {
	gate      chan struct{}
	ledger    *CodingReceiptLedger
	endpoint  codingBoundUnixEndpoint
	binding   CodingReceiptBinding
	template  phase6security.CodingRuntimeTemplateV2
	documents phase6security.ImageDescriptorDocuments
	policy    []byte
}

func NewCodingExecutorV2(p phase6security.ProfileV2, address string, binding CodingReceiptBinding,
	ledger *CodingReceiptLedger, documents phase6security.ImageDescriptorDocuments, policy []byte) (*CodingExecutorV2, error) {
	// Keep the public Profile-v2 admission hold ahead of all filesystem,
	// network, ledger or Docker work. No field-only or v1 fallback exists.
	if p.Validate() != nil || ledger == nil {
		return nil, ErrInvalidCodingCreation
	}
	boundary, err := p.PrivateServiceBoundary("coding", address)
	if err != nil || binding.Validate() != nil || binding.ProfileDigest != p.ProfileDigest ||
		binding.PeerPrincipalDigest != boundary.Provider.PrincipalDigest || p.CodingTemplate.BindPlan(binding.Plan) != nil ||
		verifyCodingCreationSource(binding, p.CodingTemplate, documents, policy) != nil {
		return nil, ErrInvalidCodingCreation
	}
	ledger.mu.Lock()
	valid := reflect.DeepEqual(ledger.binding, binding) && ledger.checkDiskLocked() == nil
	ledger.mu.Unlock()
	if !valid {
		return nil, ErrInvalidCodingCreation
	}
	// Scope and daemon/environment digests are the persisted operator binding,
	// not values recomputed from today's daemon. This is not authentication of
	// the daemon and confers no external late-effect quiescence authority.
	endpoint := codingBoundUnixEndpoint{path: p.DockerControl.DaemonSocketPath, scopeDigest: binding.EndpointScopeDigest}
	if verifyCodingUnixSocket(endpoint.path) != nil {
		return nil, ErrInvalidCodingCreation
	}
	template := p.CodingTemplate
	template.Command = slices.Clone(template.Command)
	template.Environment = slices.Clone(template.Environment)
	template.Mounts = slices.Clone(template.Mounts)
	template.Slots = slices.Clone(template.Slots)
	documents.Index, documents.Manifest, documents.Config = slices.Clone(documents.Index), slices.Clone(documents.Manifest), slices.Clone(documents.Config)
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &CodingExecutorV2{gate: gate, ledger: ledger, endpoint: endpoint, binding: binding.clone(),
		template: template, documents: documents, policy: slices.Clone(policy)}, nil
}

func (e *CodingExecutorV2) acquire(ctx context.Context) bool {
	if e == nil || e.ledger == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case <-e.gate:
		if ctx.Err() != nil {
			e.gate <- struct{}{}
			return false
		}
		return true
	}
}

func (e *CodingExecutorV2) Create(ctx context.Context, authority CodingCreateAuthority) error {
	if ctx == nil || authority.Validate(time.Now().UTC()) != nil {
		return ErrInvalidCodingCreation
	}
	ctx, cancel := context.WithDeadline(ctx, authority.ExpiresAt)
	defer cancel()
	if !e.acquire(ctx) {
		return ErrInvalidCodingCreation
	}
	defer func() { e.gate <- struct{}{} }()
	if _, _, _, err := e.ledger.LookupBoundProjection(authority, e.binding.PeerPrincipalDigest, time.Now().UTC()); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return ErrReceiptReplay
		}
		return ErrInvalidCodingCreation
	}
	plan, err := newCodingCreationPlan(e.binding, authority, e.template, e.documents, e.policy)
	if err != nil {
		return ErrInvalidCodingCreation
	}
	observer, err := newCodingUnixObserver(e.endpoint, e.binding, authority, e.template, e.documents, e.policy)
	if err != nil {
		return ErrInvalidCodingCreation
	}
	defer observer.Close()
	writer, err := newCodingUnixCreation(e.endpoint, plan, e.template.Image.Platform)
	if err != nil {
		return ErrInvalidCodingCreation
	}
	defer writer.close()
	return e.dispatchCreate(ctx, authority, observer, writer)
}

func (e *CodingExecutorV2) dispatchCreate(ctx context.Context, authority CodingCreateAuthority, observer *codingUnixObserver, writer *codingUnixCreation) error {
	_, err := e.ledger.DispatchCodingCreate(ctx, authority, func(physical context.Context, accepted CodingCreateAuthority) error {
		if accepted != authority {
			return ErrInvalidCodingCreation
		}
		return runCodingCreation(physical, observer, writer)
	})
	if err != nil {
		return err
	}
	_, err = e.ledger.completeCodingCreate(ctx, authority.RequestID, observer)
	return err
}

func (e *CodingExecutorV2) Cleanup(ctx context.Context, authority CodingCreateAuthority, intent CodingCleanupAuthority) error {
	if ctx == nil || intent.Validate(time.Now().UTC()) != nil {
		return ErrInvalidCodingCreation
	}
	ctx, cancel := context.WithDeadline(ctx, intent.ExpiresAt)
	defer cancel()
	if !e.acquire(ctx) {
		return ErrInvalidCodingCreation
	}
	defer func() { e.gate <- struct{}{} }()
	receipt, _, _, err := e.ledger.LookupBoundProjection(authority, e.binding.PeerPrincipalDigest, time.Now().UTC())
	if err != nil || receipt.Status != ReceiptCompleted || receipt.CleanupAuthority != (CodingCleanupAuthority{}) {
		return ErrReceiptConflict
	}
	runtimeID, _, err := readCompletionRuntimeID(e.ledger.path, receipt)
	if err != nil {
		return ErrReceiptConflict
	}
	observer, err := newCodingUnixObserver(e.endpoint, e.binding, authority, e.template, e.documents, e.policy)
	if err != nil {
		return ErrInvalidCodingCreation
	}
	defer observer.Close()
	deletion, err := newCodingUnixDeletion(e.endpoint, e.binding, authority, runtimeID)
	if err != nil {
		return ErrInvalidCodingCreation
	}
	defer deletion.Close()
	_, err = e.ledger.completeCodingCleanup(ctx, authority.RequestID, intent, observer, deletion)
	return err
}

func runCodingCreation(ctx context.Context, observer *codingUnixObserver, writer *codingUnixCreation) error {
	if observer == nil || writer == nil || ctx == nil || ctx.Err() != nil || writer.step != 0 {
		return ErrInvalidCodingCreation
	}
	// Reads run before the first write, but after Unknown has been persisted.
	// Missing supplied images fail here; Control never pulls or builds them.
	if observer.preflightCreation(ctx) != nil {
		return ErrInvalidCodingCreation
	}
	for range 3 {
		if writer.next(ctx) != nil {
			return ErrInvalidCodingCreation
		}
	}
	if writer.next(ctx) != nil || observer.inspectCreated(ctx, writer.plan, writer.prepID, codingProbePreparation) != nil {
		return ErrInvalidCodingCreation
	}
	if writer.next(ctx) != nil || observer.verifyPreparedRoots(ctx, writer.plan, writer.prepID) != nil {
		return ErrInvalidCodingCreation
	}
	if writer.next(ctx) != nil {
		return ErrInvalidCodingCreation
	}
	// A whole-effect inventory is only a sequencing check here, never a
	// terminal absence/quiescence/release proof or a reason to retry a write.
	inventory, err := observer.ReadInventory(ctx)
	if err != nil || inventory.Containers[0].Present || inventory.Containers[1].Present {
		return ErrInvalidCodingCreation
	}
	for _, volume := range inventory.Volumes {
		if !volume.Present {
			return ErrInvalidCodingCreation
		}
	}
	if writer.next(ctx) != nil || observer.inspectCreated(ctx, writer.plan, writer.runtimeID, codingProbeRuntime) != nil {
		return ErrInvalidCodingCreation
	}
	return writer.next(ctx) // only the separate, fully checked runtime starts
}

func (o *codingUnixObserver) preflightCreation(ctx context.Context) error {
	inventory, err := o.ReadInventory(ctx)
	if err != nil {
		return ErrInvalidCodingCreation
	}
	for _, item := range inventory.Containers {
		if item.Present {
			return ErrInvalidCodingCreation
		}
	}
	for _, item := range inventory.Volumes {
		if item.Present {
			return ErrInvalidCodingCreation
		}
	}
	bounded, cancel := context.WithTimeout(ctx, maxCodingInventoryDuration)
	defer cancel()
	if !o.acquire(bounded) {
		return ErrInvalidCodingCreation
	}
	defer o.release()
	if o.api == nil {
		return ErrInvalidCodingCreation
	}
	index, err := o.api.ImageInspect(bounded, o.template.Image.Reference)
	if err != nil || index.Descriptor == nil || index.Descriptor.Digest.String() != o.template.Image.Descriptor.Digest ||
		index.Descriptor.Size != o.template.Image.Descriptor.Size || index.Descriptor.MediaType != o.template.Image.Descriptor.MediaType {
		return ErrInvalidCodingCreation
	}
	platform, ok := codingOCIPlatform(o.template.Image.Platform)
	if !ok {
		return ErrInvalidCodingCreation
	}
	selected, err := o.api.ImageInspect(bounded, o.template.Image.Reference, client.ImageInspectWithPlatform(&platform))
	if err != nil || !validCodingSelectedImage(selected, o.template) {
		return ErrInvalidCodingCreation
	}
	daemon, err := ObserveCodingDaemon(bounded, o.api, o.binding.EndpointScopeDigest)
	if err != nil || daemon != inventory.Daemon || daemon.MatchBinding(o.binding) != nil || bounded.Err() != nil {
		return ErrInvalidCodingCreation
	}
	return nil
}

func (o *codingUnixObserver) inspectCreated(ctx context.Context, plan codingCreationPlan, id string, phase codingProbePhase) error {
	bounded, cancel := context.WithTimeout(ctx, maxCodingInventoryDuration)
	defer cancel()
	if !codingArchiveRuntimeID.MatchString(id) || !o.acquire(bounded) {
		return ErrInvalidCodingCreation
	}
	defer o.release()
	if o.api == nil {
		return ErrInvalidCodingCreation
	}
	role, name := CodingPreparationRole, plan.prepName
	if phase == codingProbeRuntime {
		role, name = CodingRuntimeRole, plan.runtimeName
	}
	result, err := o.api.ContainerInspect(bounded, name, client.ContainerInspectOptions{})
	observed := result.Container
	if err != nil || observed.ID != id || observed.Name != "/"+name || observed.State == nil ||
		observed.State.Running || observed.State.Pid != 0 || observed.State.Status != "created" ||
		observed.State.Paused || observed.State.Restarting || observed.State.Dead || observed.State.Error != "" || observed.State.ExitCode != 0 ||
		observed.State.OOMKilled || !codingNeverStartedTime(observed.State.StartedAt) || !codingNeverStartedTime(observed.State.FinishedAt) ||
		observed.RestartCount != 0 || len(observed.ExecIDs) != 0 || observed.Config == nil ||
		plan.set.MatchContainerLabels(role, o.template, o.documents, observed.Config.Labels) != nil ||
		codingProbeContainerMismatch(observed, o.template, plan.slot, plan.set.Mounts(), fmt.Sprintf("%d:%d", plan.slot.WorkloadUID, plan.slot.WorkloadGID), string(o.policy), phase) != "" || bounded.Err() != nil {
		return ErrInvalidCodingCreation
	}
	return nil
}

func codingNeverStartedTime(value string) bool {
	timestamp, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && timestamp.IsZero()
}

func (o *codingUnixObserver) verifyPreparedRoots(ctx context.Context, plan codingCreationPlan, id string) error {
	// Recheck the never-started carrier before allowing the archive reader to
	// target its ID. The same GET-only transport enforces exact empty tar root
	// ownership/mode and rejects links, extra entries, PAX data and file bytes.
	if o.inspectCreated(ctx, plan, id, codingProbePreparation) != nil {
		return ErrInvalidCodingCreation
	}
	bounded, cancel := context.WithTimeout(ctx, maxCodingInventoryDuration)
	defer cancel()
	if !o.acquire(bounded) {
		return ErrInvalidCodingCreation
	}
	defer o.release()
	if o.api == nil || o.bounded.archiveID != "" {
		return ErrInvalidCodingCreation
	}
	o.bounded.archiveID = id
	defer func() { o.bounded.archiveID = "" }()
	for _, mount := range plan.set.Mounts() {
		result, err := o.api.CopyFromContainer(bounded, id, client.CopyFromContainerOptions{SourcePath: mount.Target})
		if err != nil || result.Content == nil {
			return ErrInvalidCodingCreation
		}
		var sink bytes.Buffer
		_, readErr := io.Copy(&sink, io.LimitReader(result.Content, maxCodingArchiveResponseBytes+1))
		closeErr := result.Content.Close()
		if readErr != nil || closeErr != nil || sink.Len() > maxCodingArchiveResponseBytes || bounded.Err() != nil {
			return ErrInvalidCodingCreation
		}
	}
	return nil
}
