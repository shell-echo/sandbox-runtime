package qualificationsupervisor

import (
	"bytes"
	"context"
	"errors"
	"os"

	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
)

var ErrDelivery = errors.New("adapter invocation delivery failed")

// CredentialPayload is caller-owned secret input for exactly one startup-
// declared channel. Data is copied before any process write and is never
// retained by the supervisor. The caller must not mutate it until this call
// returns and must manage its own original buffer lifetime.
type CredentialPayload struct {
	ChannelID string
	Data      []byte
}

// DeliveryStats contains only bounded counts suitable for later sanitized
// supervisor evidence. It contains no channel IDs, locations, or payload bytes.
type DeliveryStats struct {
	InvocationBytes        int64
	CredentialChannelCount int
	CredentialPayloadBytes int64
}

type bufferedCredential struct {
	descriptor int
	data       []byte
}

type deliveryPlan struct {
	message      protocol.DecodedMessage
	invocationID string
	credentials  []bufferedCredential
	stats        DeliveryStats
}

type deliveryWriteResult struct {
	invocation bool
	bytes      int64
	err        error
}

// DeliverInvocation validates one private invocation against the locked Codec,
// committed locations, observed startup requirements, and transport fd map.
// It then writes stdin plus all credential pipes concurrently and closes every
// input endpoint to produce EOF. Any ambiguous or partial delivery terminates
// and reaps the process. This method never reads post-invocation output.
func (p *StartedProcess) DeliverInvocation(ctx context.Context, invocationDocument []byte, credentials []CredentialPayload) (DeliveryStats, error) {
	if p == nil || p.core == nil {
		return DeliveryStats{}, ErrDelivery
	}
	core := p.core
	core.protocolMu.Lock()
	defer core.protocolMu.Unlock()
	if core.deliveryAttempted || core.isStopping() {
		return DeliveryStats{}, failDelivery(core, ErrDelivery)
	}
	core.deliveryAttempted = true
	if ctx == nil {
		return DeliveryStats{}, failDelivery(core, ErrDelivery)
	}
	if err := ctx.Err(); err != nil {
		return DeliveryStats{}, failDelivery(core, err)
	}
	operationContext, release, err := clippedContext(core.runContext, ctx)
	if err != nil {
		return DeliveryStats{}, failDelivery(core, err)
	}
	defer release()
	ctx = operationContext
	if !core.startupValidated || core.codec == nil || core.decoder == nil ||
		core.admission.machine.State() != protocol.PhaseStateReadyForInvocation {
		return DeliveryStats{}, failDelivery(core, ErrDelivery)
	}
	if err := core.admission.Recheck(ctx); err != nil {
		return DeliveryStats{}, failDelivery(core, err)
	}
	plan, err := prepareDelivery(core, invocationDocument, credentials)
	if err != nil {
		return DeliveryStats{}, failDelivery(core, err)
	}
	defer wipeCredentials(plan.credentials)
	if err := core.admission.machine.AuthorizeInvocationInput(); err != nil {
		return DeliveryStats{}, failDelivery(core, err)
	}

	writes := make([]struct {
		file       *os.File
		data       []byte
		invocation bool
	}, 0, 1+launchCredentialSlots)
	writes = append(writes, struct {
		file       *os.File
		data       []byte
		invocation bool
	}{file: core.parent[0], data: plan.message.Document, invocation: true})
	byDescriptor := make(map[int][]byte, len(plan.credentials))
	for _, credential := range plan.credentials {
		byDescriptor[credential.descriptor] = credential.data
	}
	// Close even unused inherited credential slots so every child input fd has
	// an unambiguous EOF after this one-shot delivery.
	for descriptor := 3; descriptor < 3+launchCredentialSlots; descriptor++ {
		writes = append(writes, struct {
			file       *os.File
			data       []byte
			invocation bool
		}{file: core.parent[descriptor], data: byDescriptor[descriptor]})
	}

	results := make(chan deliveryWriteResult, len(writes))
	for _, write := range writes {
		go func(file *os.File, data []byte, invocation bool) {
			count, err := writeAllAndClose(file, data)
			results <- deliveryWriteResult{invocation: invocation, bytes: count, err: err}
		}(write.file, write.data, write.invocation)
	}

	var invocationBytes, credentialBytes int64
	remaining := len(writes)
	for remaining > 0 {
		var failure error
		select {
		case result := <-results:
			remaining--
			if result.err != nil {
				failure = result.err
			} else if result.invocation {
				invocationBytes += result.bytes
			} else {
				credentialBytes += result.bytes
			}
		case <-ctx.Done():
			failure = contextFailure(ctx)
		case <-core.done:
			failure = ErrDelivery
		}
		if failure != nil {
			cleanupErr := core.close()
			for remaining > 0 {
				<-results
				remaining--
			}
			core.admission.owner.failure = failure
			return DeliveryStats{}, errors.Join(ErrDelivery, failure, cleanupErr)
		}
	}
	if invocationBytes != plan.stats.InvocationBytes || credentialBytes != plan.stats.CredentialPayloadBytes {
		return DeliveryStats{}, failDelivery(core, ErrDelivery)
	}
	if err := contextFailure(ctx); err != nil {
		return DeliveryStats{}, failDelivery(core, err)
	}
	if err := core.admission.Recheck(ctx); err != nil {
		return DeliveryStats{}, failDelivery(core, err)
	}
	if err := core.admission.machine.RecordInvocationDelivered(plan.message); err != nil {
		return DeliveryStats{}, failDelivery(core, err)
	}
	core.delivery = plan.stats
	core.invocationID = plan.invocationID
	core.deliveryComplete = true
	return core.delivery, nil
}

func prepareDelivery(core *processCore, invocationDocument []byte, credentials []CredentialPayload) (*deliveryPlan, error) {
	if core == nil || len(invocationDocument) == 0 || int64(len(invocationDocument)) > protocol.MaxInvocationBytes ||
		len(credentials) > protocol.MaxCredentialChannels {
		return nil, ErrDelivery
	}
	privateInvocation := append([]byte(nil), invocationDocument...)
	message, err := core.codec.DecodeInvocation(bytes.NewReader(privateInvocation))
	if err != nil {
		return nil, err
	}
	details, err := protocol.InvocationDetailsFrom(message)
	if err != nil || details.Phase != core.admission.phase {
		return nil, ErrDelivery
	}
	locations := core.admission.Locations()
	if details.ProfilePath != locations.ProfilePath || details.ProviderOrigin != locations.ProviderOrigin ||
		details.GatewayProbeEndpoint != locations.GatewayProbeEndpoint || details.CallerStateRoot != locations.CallerStateRoot ||
		len(details.CredentialChannels) != len(core.startup.CredentialChannels) {
		return nil, ErrDelivery
	}
	requirements := make(map[string]protocol.CredentialChannelRequirement, len(core.startup.CredentialChannels))
	for _, requirement := range core.startup.CredentialChannels {
		requirements[requirement.ChannelID] = requirement
	}
	payloads := make(map[string][]byte, len(credentials))
	for _, credential := range credentials {
		if _, exists := payloads[credential.ChannelID]; exists {
			return nil, ErrDelivery
		}
		payloads[credential.ChannelID] = credential.Data
	}
	if len(payloads) != len(details.CredentialChannels) {
		return nil, ErrDelivery
	}
	plan := &deliveryPlan{message: message, invocationID: details.InvocationID, credentials: make([]bufferedCredential, 0, len(details.CredentialChannels))}
	for _, descriptor := range details.CredentialChannels {
		requirement, exists := requirements[descriptor.ChannelID]
		payload, supplied := payloads[descriptor.ChannelID]
		if !exists || !supplied || descriptor.FileDescriptor < 3 || descriptor.FileDescriptor >= 3+launchCredentialSlots ||
			requirement.Role != descriptor.Role || !equalActor(requirement.Actor, descriptor.Actor) ||
			requirement.MediaType != descriptor.MediaType || requirement.MaxBytes != descriptor.MaxBytes ||
			descriptor.MaxBytes > protocol.MaxCredentialChannelBytes || int64(len(payload)) > descriptor.MaxBytes {
			wipeCredentials(plan.credentials)
			return nil, ErrDelivery
		}
		plan.stats.CredentialPayloadBytes += int64(len(payload))
		if plan.stats.CredentialPayloadBytes > protocol.MaxCredentialTotalBytes {
			wipeCredentials(plan.credentials)
			return nil, ErrDelivery
		}
		plan.credentials = append(plan.credentials, bufferedCredential{
			descriptor: descriptor.FileDescriptor,
			data:       append([]byte(nil), payload...),
		})
	}
	plan.stats.InvocationBytes = message.WireBytes
	plan.stats.CredentialChannelCount = len(plan.credentials)
	return plan, nil
}

func equalActor(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func writeAllAndClose(file *os.File, data []byte) (int64, error) {
	if file == nil {
		return 0, ErrDelivery
	}
	var written int64
	for len(data) > 0 {
		count, err := file.Write(data)
		written += int64(count)
		data = data[count:]
		if err != nil || count == 0 {
			_ = file.Close()
			return written, ErrDelivery
		}
	}
	if err := file.Close(); err != nil {
		return written, ErrDelivery
	}
	return written, nil
}

func wipeCredentials(credentials []bufferedCredential) {
	for i := range credentials {
		clear(credentials[i].data)
	}
}

func failDelivery(core *processCore, cause error) error {
	if core == nil {
		return errors.Join(ErrDelivery, cause)
	}
	core.admission.owner.failure = cause
	return errors.Join(ErrDelivery, cause, core.close())
}

// DeliveryStats returns a historical defensive value only after every input
// endpoint was written and closed and the protocol state recorded delivery.
func (p *StartedProcess) DeliveryStats() (DeliveryStats, bool) {
	if p == nil || p.core == nil {
		return DeliveryStats{}, false
	}
	p.core.protocolMu.Lock()
	defer p.core.protocolMu.Unlock()
	if !p.core.deliveryComplete {
		return DeliveryStats{}, false
	}
	return p.core.delivery, true
}
