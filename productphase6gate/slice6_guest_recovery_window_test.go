//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// These E-only operations touch one already-existing run-owned Guest–Product
// edge. The caller must first prove the actual PostgreSQL-loss close on both
// original PID1 streams; these operations do not themselves prove that cause.
type slice6GuestRecoveryEdge struct {
	Run                slice6DockerRun
	ProductID, GuestID string
	ProductNetworkName string
	ProductNetworkID   string
	ProductIP, GuestIP string
	RuntimeNetworkName string
	RuntimeNetworkID   string
	GuestRuntimeIP     string
}

type slice6GuestRecoveryEdgeAction struct {
	RunID, ProductID, GuestID, ProductNetworkID string
	GuestPID, ProductPID                        int
	GuestStartedAt, ProductStartedAt            string
	GuestIP, RuntimeIP                          string
	StartedUTC, FinishedUTC                     string
	BeforeDigest, AfterDigest                   string
	BeforeProjection, AfterProjection           string
	BeforeDocker, AfterDocker                   slice6GuestRecoveryDockerSnapshot
	Disconnected                                bool
	Attempted, OutcomeUnknown                   bool
}

func (edge slice6GuestRecoveryEdge) valid() bool {
	if len(edge.Run.id) != 32 || !lowerHexSlice6(edge.Run.id) ||
		len(edge.ProductID) != 64 || !lowerHexSlice6(edge.ProductID) ||
		len(edge.GuestID) != 64 || !lowerHexSlice6(edge.GuestID) ||
		len(edge.ProductNetworkID) != 64 || !lowerHexSlice6(edge.ProductNetworkID) ||
		len(edge.RuntimeNetworkID) != 64 || !lowerHexSlice6(edge.RuntimeNetworkID) ||
		edge.ProductID == edge.GuestID || edge.ProductNetworkID == edge.RuntimeNetworkID ||
		!slice6GuestOperatorID(edge.ProductNetworkName) ||
		!slice6GuestOperatorID(edge.RuntimeNetworkName) ||
		edge.ProductNetworkName == edge.RuntimeNetworkName {
		return false
	}
	for _, raw := range []string{edge.ProductIP, edge.GuestIP, edge.GuestRuntimeIP} {
		ip, err := netip.ParseAddr(raw)
		if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() {
			return false
		}
	}
	return true
}

type slice6GuestEdgeProcess struct {
	ID, Name, RunID, StartedAt string
	PID                        int
	Networks                   map[string]struct {
		NetworkID string `json:"NetworkID"`
		IPAddress string `json:"IPAddress"`
	}
}

func slice6InspectGuestEdgeProcess(ctx context.Context, run slice6DockerRun,
	id, expectedName string) (slice6GuestEdgeProcess, error) {
	process, raw, err := slice6InspectGuestEdgeProcessRaw(ctx, run, id, expectedName)
	clear(raw)
	return process, err
}

func slice6InspectGuestEdgeProcessRaw(ctx context.Context, run slice6DockerRun,
	id, expectedName string) (slice6GuestEdgeProcess, []byte, error) {
	output, err, overflow := slice6DockerBounded(ctx, 16<<10, nil, "inspect", "--format",
		"{{.Id}}|{{.Name}}|{{index .Config.Labels \""+slice6RunLabel+"\"}}|"+
			"{{.State.Running}}|{{.State.Pid}}|{{.State.StartedAt}}|"+
			"{{json .NetworkSettings.Networks}}", id)
	if err != nil || overflow {
		clear(output)
		return slice6GuestEdgeProcess{}, nil, errors.New("Guest isolation process inspect unavailable")
	}
	process, parseErr := slice6ParseGuestEdgeProcessRaw(output, run, id, expectedName)
	if parseErr != nil {
		clear(output)
		return slice6GuestEdgeProcess{}, nil, parseErr
	}
	return process, output, nil
}

func slice6ParseGuestEdgeProcessRaw(output []byte, run slice6DockerRun,
	id, expectedName string) (slice6GuestEdgeProcess, error) {
	if len(output) == 0 || len(output) > 16<<10 ||
		output[len(output)-1] != '\n' {
		return slice6GuestEdgeProcess{}, errors.New("Guest isolation process inspect unavailable")
	}
	parts := strings.Split(string(output[:len(output)-1]), "|")
	if len(parts) != 7 || parts[0] != id || parts[1] != "/"+expectedName ||
		parts[2] != run.id || parts[3] != "true" {
		return slice6GuestEdgeProcess{}, errors.New("Guest isolation process identity drift")
	}
	pid, pidErr := strconv.Atoi(parts[4])
	started, startErr := time.Parse(time.RFC3339Nano, parts[5])
	var networks map[string]struct {
		NetworkID string `json:"NetworkID"`
		IPAddress string `json:"IPAddress"`
	}
	if pidErr != nil || pid < 1 || pid > 1<<22 || startErr != nil || started.IsZero() ||
		json.Unmarshal([]byte(parts[6]), &networks) != nil || len(networks) == 0 || len(networks) > 9 {
		return slice6GuestEdgeProcess{}, errors.New("Guest isolation PID/network identity invalid")
	}
	return slice6GuestEdgeProcess{ID: id, Name: expectedName, RunID: run.id,
		PID: pid, StartedAt: parts[5], Networks: networks}, nil
}

func slice6CheckGuestEdgeSnapshot(ctx context.Context, edge slice6GuestRecoveryEdge,
	connected bool) (slice6GuestRecoveryEdgeAction, error) {
	if ctx == nil || ctx.Err() != nil || !edge.valid() {
		return slice6GuestRecoveryEdgeAction{}, errors.New("Guest isolation target invalid")
	}
	product, productRaw, err := slice6InspectGuestEdgeProcessRaw(ctx, edge.Run, edge.ProductID,
		"sr-p6-product-runtime-"+edge.Run.id)
	if err != nil {
		return slice6GuestRecoveryEdgeAction{}, err
	}
	defer clear(productRaw)
	guest, guestRaw, err := slice6InspectGuestEdgeProcessRaw(ctx, edge.Run, edge.GuestID,
		"sr-p6-guest-runtime-"+edge.Run.id)
	if err != nil {
		return slice6GuestRecoveryEdgeAction{}, err
	}
	defer clear(guestRaw)
	productNetwork, productFound := product.Networks[edge.ProductNetworkName]
	guestRuntime, runtimeFound := guest.Networks[edge.RuntimeNetworkName]
	guestProduct, guestFound := guest.Networks[edge.ProductNetworkName]
	if !productFound || productNetwork.NetworkID != edge.ProductNetworkID ||
		productNetwork.IPAddress != edge.ProductIP || !runtimeFound ||
		guestRuntime.NetworkID != edge.RuntimeNetworkID ||
		guestRuntime.IPAddress != edge.GuestRuntimeIP ||
		len(guest.Networks) != 1+boolToIntSlice6(connected) ||
		guestFound != connected || (connected &&
		(guestProduct.NetworkID != edge.ProductNetworkID || guestProduct.IPAddress != edge.GuestIP)) {
		return slice6GuestRecoveryEdgeAction{}, errors.New("Guest isolation existing edge drift")
	}
	productObserved, output, inspectErr := slice6ReadGuestRecoveryActionNetwork(ctx, edge.Run.id, edge.ProductNetworkID)
	defer clear(output)
	if inspectErr != nil {
		return slice6GuestRecoveryEdgeAction{}, errors.New("Guest isolation network source unavailable")
	}
	_, productPresent := productObserved.Containers[edge.ProductID]
	_, guestPresent := productObserved.Containers[edge.GuestID]
	if productObserved.Name != edge.ProductNetworkName ||
		len(productObserved.Containers) != 1+boolToIntSlice6(connected) ||
		!productPresent || guestPresent != connected ||
		!slice6GuestRecoveryMemberAddress(productObserved.Containers[edge.ProductID].IPv4Address, edge.ProductIP) ||
		(connected && !slice6GuestRecoveryMemberAddress(productObserved.Containers[edge.GuestID].IPv4Address, edge.GuestIP)) {
		return slice6GuestRecoveryEdgeAction{}, errors.New("Guest isolation network member drift")
	}
	runtimeObserved, runtimeRaw, runtimeErr := slice6ReadGuestRecoveryActionNetwork(ctx, edge.Run.id, edge.RuntimeNetworkID)
	defer clear(runtimeRaw)
	if runtimeErr != nil {
		return slice6GuestRecoveryEdgeAction{}, errors.New("Guest isolation runtime network source unavailable")
	}
	if runtimeObserved.Name != edge.RuntimeNetworkName ||
		len(runtimeObserved.Containers) != 1 ||
		!slice6GuestRecoveryMemberAddress(runtimeObserved.Containers[edge.GuestID].IPv4Address, edge.GuestRuntimeIP) {
		return slice6GuestRecoveryEdgeAction{}, errors.New("Guest isolation retained runtime edge drift")
	}
	identity := edge.Run.id + "|" + edge.ProductID + "|" + edge.GuestID + "|" +
		strconv.Itoa(product.PID) + "|" + product.StartedAt + "|" +
		strconv.Itoa(guest.PID) + "|" + guest.StartedAt + "|" +
		edge.ProductNetworkID + "|" + edge.ProductIP + "|" + edge.GuestIP + "|" +
		edge.RuntimeNetworkID + "|" + edge.GuestRuntimeIP + "|" + strconv.FormatBool(connected)
	return slice6GuestRecoveryEdgeAction{RunID: edge.Run.id,
		ProductID: edge.ProductID, GuestID: edge.GuestID,
		ProductNetworkID: edge.ProductNetworkID,
		ProductPID:       product.PID, GuestPID: guest.PID,
		ProductStartedAt: product.StartedAt, GuestStartedAt: guest.StartedAt,
		GuestIP: edge.GuestIP, RuntimeIP: edge.GuestRuntimeIP,
		BeforeDigest: slice6ReceiptSHA256([]byte(identity)), BeforeProjection: identity,
		BeforeDocker: slice6GuestRecoveryDockerSnapshot{Product: bytes.Clone(productRaw),
			Peer: bytes.Clone(guestRaw), Network: bytes.Clone(output), Retained: bytes.Clone(runtimeRaw)},
		Disconnected: !connected}, nil
}

func boolToIntSlice6(value bool) int {
	if value {
		return 1
	}
	return 0
}

func slice6DetachGuestProductEdge(ctx context.Context,
	edge slice6GuestRecoveryEdge) (slice6GuestRecoveryEdgeAction, error) {
	return slice6DetachGuestProductEdgeWithCommand(ctx, edge, slice6GuestNetworkCommand)
}

type slice6NetworkCommand func(context.Context, ...string) ([]byte, error, bool)

// Cancellation may be bypassed only for bounded cleanup, never the caller's
// absolute deadline. A nested restore inherits this same deadline.
func slice6NetworkCleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(5 * time.Second)
	if parent != nil {
		if inherited, ok := parent.Deadline(); ok && inherited.Before(deadline) {
			deadline = inherited
		}
	}
	return context.WithDeadline(context.Background(), deadline)
}

func slice6GuestNetworkCommand(ctx context.Context, args ...string) ([]byte, error, bool) {
	return slice6DockerBounded(ctx, 128, nil, args...)
}

func slice6DetachGuestProductEdgeWithCommand(ctx context.Context,
	edge slice6GuestRecoveryEdge, command slice6NetworkCommand) (slice6GuestRecoveryEdgeAction, error) {
	return slice6DetachGuestProductEdgeWithProbe(ctx, edge, command, slice6CheckGuestEdgeSnapshot)
}

type slice6GuestEdgeProbe func(context.Context, slice6GuestRecoveryEdge, bool) (slice6GuestRecoveryEdgeAction, error)

func slice6DetachGuestProductEdgeWithProbe(ctx context.Context, edge slice6GuestRecoveryEdge,
	command slice6NetworkCommand, probe slice6GuestEdgeProbe) (slice6GuestRecoveryEdgeAction, error) {
	return slice6DetachGuestProductEdgeWithProbeRecorded(ctx, edge, command, probe, nil)
}

func slice6DetachGuestProductEdgeWithProbeRecorded(ctx context.Context, edge slice6GuestRecoveryEdge,
	command slice6NetworkCommand, probe slice6GuestEdgeProbe,
	recorder *slice6GuestRecoveryERecorder) (slice6GuestRecoveryEdgeAction, error) {
	if command == nil || probe == nil {
		return slice6GuestRecoveryEdgeAction{}, errors.New("Guest isolation command unavailable")
	}
	before, err := probe(ctx, edge, true)
	if err != nil {
		return slice6GuestRecoveryEdgeAction{}, err
	}
	if ctx.Err() != nil {
		return slice6GuestRecoveryEdgeAction{}, errors.New("Guest isolation action budget expired before mutation")
	}
	// Register one absolute deadline before the first mutation. A slow or
	// uncertain Docker response cannot start a fresh five-second readback.
	cleanup, stop := slice6NetworkCleanupContext(ctx)
	defer stop()
	deadline, _ := cleanup.Deadline()
	mutation, stopMutation := context.WithDeadline(ctx, deadline)
	defer stopMutation()
	started := time.Now().UTC()
	before.StartedUTC = started.Format(time.RFC3339Nano)
	if recorder != nil && recorder.record("guest_off_call",
		slice6GuestRecoveryActionRef(before.BeforeProjection, before.StartedUTC, before.BeforeDocker)) != nil {
		return before, errors.New("Guest isolation E call journal unavailable")
	}
	before.Attempted = true
	output, commandErr, overflow := command(mutation,
		"network", "disconnect", edge.ProductNetworkID, edge.GuestID)
	clear(output)
	// A failed CLI response is not evidence that Docker rejected the mutation.
	// Inspect using that same finite deadline even if the caller was canceled
	// after the request reached the daemon.
	if cleanup.Err() != nil {
		before.OutcomeUnknown = true
		return before, errors.New("Guest isolation original cleanup deadline exhausted")
	}
	after, err := probe(cleanup, edge, false)
	readbackUncertain := err != nil
	if err != nil && cleanup.Err() == nil {
		after, err = probe(cleanup, edge, false)
	}
	if err != nil {
		// A connected exact snapshot proves that this action did not detach.
		if cleanup.Err() == nil {
			if connected, connectedErr := probe(cleanup, edge, true); connectedErr == nil &&
				connected.GuestPID == before.GuestPID && connected.ProductPID == before.ProductPID &&
				connected.GuestStartedAt == before.GuestStartedAt && connected.ProductStartedAt == before.ProductStartedAt {
				return before, errors.New("Guest isolation disconnect not applied")
			}
		}
		before.OutcomeUnknown = true
		return before, errors.New("Guest isolation disconnect outcome unknown; exact stop required")
	}
	if err != nil || after.ProductPID != before.ProductPID || after.GuestPID != before.GuestPID ||
		after.ProductStartedAt != before.ProductStartedAt || after.GuestStartedAt != before.GuestStartedAt {
		before.OutcomeUnknown = true
		return before, errors.New("Guest isolation disconnect process/readback drift")
	}
	before.AfterDigest = after.BeforeDigest
	before.AfterProjection = after.BeforeProjection
	before.AfterDocker = after.BeforeDocker
	before.Disconnected = true
	before.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if commandErr != nil || overflow || readbackUncertain || ctx.Err() != nil || cleanup.Err() != nil {
		// No successful action receipt may be issued for an uncertain command.
		// The precise detached state permits only cleanup at the original IP.
		restored, restoreErr := slice6RestoreGuestProductEdge(cleanup, edge, before)
		if restoreErr != nil && (restored.Disconnected || restored.AfterDigest != before.BeforeDigest) {
			before.OutcomeUnknown = true
			return before, errors.New("Guest isolation disconnect response lost; exact restore unconfirmed")
		}
		before.Disconnected = false
		before.AfterDigest = before.BeforeDigest
		before.AfterProjection = before.BeforeProjection
		before.AfterDocker = before.BeforeDocker
		return before, errors.New("Guest isolation disconnect response lost; exact edge restored")
	}
	if recorder != nil && recorder.record("guest_off_observed",
		slice6GuestRecoveryActionRef(before.AfterProjection, before.FinishedUTC, before.AfterDocker)) != nil {
		before.OutcomeUnknown = true
		return before, errors.New("Guest isolation E observation journal unavailable")
	}
	return before, nil
}

func slice6RestoreGuestProductEdge(ctx context.Context,
	edge slice6GuestRecoveryEdge, detached slice6GuestRecoveryEdgeAction) (slice6GuestRecoveryEdgeAction, error) {
	return slice6RestoreGuestProductEdgeWithCommand(ctx, edge, detached, slice6GuestNetworkCommand)
}

func slice6RestoreGuestProductEdgeWithCommand(ctx context.Context,
	edge slice6GuestRecoveryEdge, detached slice6GuestRecoveryEdgeAction,
	command slice6NetworkCommand) (slice6GuestRecoveryEdgeAction, error) {
	return slice6RestoreGuestProductEdgeWithProbe(ctx, edge, detached, command, slice6CheckGuestEdgeSnapshot)
}

func slice6RestoreGuestProductEdgeWithProbe(ctx context.Context,
	edge slice6GuestRecoveryEdge, detached slice6GuestRecoveryEdgeAction,
	command slice6NetworkCommand, probe slice6GuestEdgeProbe) (slice6GuestRecoveryEdgeAction, error) {
	return slice6RestoreGuestProductEdgeWithProbeRecorded(ctx, edge, detached, command, probe, nil)
}

func slice6RestoreGuestProductEdgeWithProbeRecorded(ctx context.Context,
	edge slice6GuestRecoveryEdge, detached slice6GuestRecoveryEdgeAction,
	command slice6NetworkCommand, probe slice6GuestEdgeProbe,
	recorder *slice6GuestRecoveryERecorder) (slice6GuestRecoveryEdgeAction, error) {
	if ctx == nil || ctx.Err() != nil || detached.RunID != edge.Run.id || detached.ProductID != edge.ProductID ||
		detached.GuestID != edge.GuestID || detached.ProductNetworkID != edge.ProductNetworkID ||
		!detached.Disconnected || detached.AfterDigest == "" || command == nil || probe == nil {
		return slice6GuestRecoveryEdgeAction{}, errors.New("Guest isolation detach receipt unavailable")
	}
	budget, stop := slice6NetworkCleanupContext(ctx)
	defer stop()
	before, err := probe(budget, edge, false)
	if err != nil || before.BeforeDigest != detached.AfterDigest ||
		before.ProductPID != detached.ProductPID || before.GuestPID != detached.GuestPID ||
		before.ProductStartedAt != detached.ProductStartedAt || before.GuestStartedAt != detached.GuestStartedAt {
		return slice6GuestRecoveryEdgeAction{}, errors.New("Guest isolation pre-restore drift")
	}
	if budget.Err() != nil {
		return slice6GuestRecoveryEdgeAction{}, errors.New("Guest isolation restore budget expired before mutation")
	}
	started := time.Now().UTC()
	before.StartedUTC = started.Format(time.RFC3339Nano)
	if recorder != nil && recorder.record("guest_on_call",
		slice6GuestRecoveryActionRef(before.BeforeProjection, before.StartedUTC, before.BeforeDocker)) != nil {
		return before, errors.New("Guest isolation restore E call journal unavailable")
	}
	before.Attempted = true
	output, commandErr, overflow := command(budget,
		"network", "connect", "--ip", edge.GuestIP, edge.ProductNetworkID, edge.GuestID)
	clear(output)
	if budget.Err() != nil {
		before.OutcomeUnknown = true
		return before, errors.New("Guest isolation restore deadline exhausted after command")
	}
	after, err := probe(budget, edge, true)
	readbackUncertain := err != nil
	if err != nil && budget.Err() == nil {
		after, err = probe(budget, edge, true)
	}
	if err != nil || after.ProductPID != before.ProductPID || after.GuestPID != before.GuestPID ||
		after.ProductStartedAt != before.ProductStartedAt || after.GuestStartedAt != before.GuestStartedAt {
		before.OutcomeUnknown = true
		return before, errors.New("Guest isolation reconnect process/readback drift")
	}
	before.AfterDigest = after.BeforeDigest
	before.AfterProjection = after.BeforeProjection
	before.AfterDocker = after.BeforeDocker
	before.Disconnected = false
	before.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if commandErr != nil || overflow || readbackUncertain || ctx.Err() != nil || budget.Err() != nil {
		if budget.Err() != nil {
			before.OutcomeUnknown = true
		}
		return before, errors.New("Guest isolation reconnect response lost; exact original edge observed")
	}
	if recorder != nil && recorder.record("guest_on_observed",
		slice6GuestRecoveryActionRef(before.AfterProjection, before.FinishedUTC, before.AfterDocker)) != nil {
		return before, errors.New("Guest isolation restore E observation journal unavailable")
	}
	return before, nil
}
