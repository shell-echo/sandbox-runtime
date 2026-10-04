//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// E disconnects only Product's existing PostgreSQL service edge. PostgreSQL
// stays running on its nine source-bound service bridges; an E orchestration
// must separately check that formal source proof before accepting this action.
type slice6ProductPGFaultEdge struct {
	Run                       slice6DockerRun
	ProductID, PostgresID     string
	NetworkName, NetworkID    string
	ProductIP, PostgresIP     string
	PostgresImageID, ImageRef string
}

type slice6ProductPGFaultAction struct {
	RunID, ProductID, PostgresID, NetworkID string
	ProductPID, PostgresPID                 int
	ProductStartedAt, PostgresStartedAt     string
	ProductOtherNetworks, PostgresNetworks  string
	BeforeDigest, AfterDigest               string
	BeforeProjection, AfterProjection       string
	BeforeDocker, AfterDocker               slice6GuestRecoveryDockerSnapshot
	StartedUTC, FinishedUTC                 string
	Disconnected                            bool
	Attempted, OutcomeUnknown               bool
}

func (edge slice6ProductPGFaultEdge) valid() bool {
	if len(edge.Run.id) != 32 || !lowerHexSlice6(edge.Run.id) ||
		len(edge.ProductID) != 64 || !lowerHexSlice6(edge.ProductID) ||
		len(edge.PostgresID) != 64 || !lowerHexSlice6(edge.PostgresID) ||
		len(edge.NetworkID) != 64 || !lowerHexSlice6(edge.NetworkID) ||
		edge.ProductID == edge.PostgresID || !slice6GuestOperatorID(edge.NetworkName) ||
		!guestRevokeFixtureDigestGate(edge.PostgresImageID) || edge.ImageRef == "" {
		return false
	}
	for _, raw := range []string{edge.ProductIP, edge.PostgresIP} {
		ip, err := netip.ParseAddr(raw)
		if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() {
			return false
		}
	}
	return edge.ProductIP != edge.PostgresIP
}

func slice6ProductPGNetworkDigest(networks map[string]struct {
	NetworkID string `json:"NetworkID"`
	IPAddress string `json:"IPAddress"`
}, exclude string) string {
	items := make([]string, 0, len(networks))
	for name, network := range networks {
		if name == exclude {
			continue
		}
		items = append(items, name+"@"+network.NetworkID+"@"+network.IPAddress)
	}
	slices.Sort(items)
	return slice6ReceiptSHA256([]byte(strings.Join(items, "|")))
}

func slice6CheckProductPGFaultSnapshot(ctx context.Context, edge slice6ProductPGFaultEdge,
	connected bool) (slice6ProductPGFaultAction, error) {
	if ctx == nil || ctx.Err() != nil || !edge.valid() {
		return slice6ProductPGFaultAction{}, errors.New("Product PG fault edge invalid")
	}
	product, productRaw, err := slice6InspectGuestEdgeProcessRaw(ctx, edge.Run, edge.ProductID,
		"sr-p6-product-runtime-"+edge.Run.id)
	if err != nil {
		return slice6ProductPGFaultAction{}, err
	}
	defer clear(productRaw)
	postgres, postgresRaw, err := slice6InspectGuestEdgeProcessRaw(ctx, edge.Run, edge.PostgresID,
		"sr-p6-postgres-"+edge.Run.id)
	if err != nil {
		return slice6ProductPGFaultAction{}, err
	}
	defer clear(postgresRaw)
	productNetwork, productFound := product.Networks[edge.NetworkName]
	postgresNetwork, postgresFound := postgres.Networks[edge.NetworkName]
	if productFound != connected || (connected &&
		(productNetwork.NetworkID != edge.NetworkID || productNetwork.IPAddress != edge.ProductIP)) ||
		!postgresFound || postgresNetwork.NetworkID != edge.NetworkID ||
		postgresNetwork.IPAddress != edge.PostgresIP ||
		len(product.Networks) < 1+boolToIntSlice6(connected) {
		return slice6ProductPGFaultAction{}, errors.New("Product PG existing endpoint drift")
	}
	pgIdentity, inspectErr, overflow := slice6DockerBounded(ctx, 512, nil, "inspect", "--format",
		"{{.Id}}|{{.Image}}|{{.Config.Image}}|{{index .Config.Labels \""+slice6RunLabel+"\"}}|{{.State.Running}}|{{.State.Pid}}|{{.State.StartedAt}}", edge.PostgresID)
	parts := strings.Split(strings.TrimSuffix(string(pgIdentity), "\n"), "|")
	defer clear(pgIdentity)
	if inspectErr != nil || overflow || len(parts) != 7 || parts[0] != edge.PostgresID ||
		parts[1] != edge.PostgresImageID || parts[2] != edge.ImageRef ||
		parts[3] != edge.Run.id || parts[4] != "true" ||
		parts[5] != strconv.Itoa(postgres.PID) || parts[6] != postgres.StartedAt {
		return slice6ProductPGFaultAction{}, errors.New("Product PG selected image/process drift")
	}
	observedNetwork, raw, networkErr := slice6ReadGuestRecoveryActionNetwork(ctx, edge.Run.id, edge.NetworkID)
	defer clear(raw)
	if networkErr != nil {
		return slice6ProductPGFaultAction{}, errors.New("Product PG source network unavailable")
	}
	_, pgPresent := observedNetwork.Containers[edge.PostgresID]
	_, productPresent := observedNetwork.Containers[edge.ProductID]
	if observedNetwork.Name != edge.NetworkName ||
		len(observedNetwork.Containers) != 1+boolToIntSlice6(connected) ||
		!pgPresent || productPresent != connected ||
		!slice6GuestRecoveryMemberAddress(observedNetwork.Containers[edge.PostgresID].IPv4Address, edge.PostgresIP) ||
		(connected && !slice6GuestRecoveryMemberAddress(observedNetwork.Containers[edge.ProductID].IPv4Address, edge.ProductIP)) {
		return slice6ProductPGFaultAction{}, errors.New("Product PG network member drift")
	}
	productOther := slice6ProductPGNetworkDigest(product.Networks, edge.NetworkName)
	pgNetworks := slice6ProductPGNetworkDigest(postgres.Networks, "")
	identity := edge.Run.id + "|" + edge.ProductID + "|" + edge.PostgresID + "|" +
		strconv.Itoa(product.PID) + "|" + product.StartedAt + "|" +
		strconv.Itoa(postgres.PID) + "|" + postgres.StartedAt + "|" +
		edge.NetworkID + "|" + edge.ProductIP + "|" + edge.PostgresIP + "|" +
		productOther + "|" + pgNetworks + "|" + strconv.FormatBool(connected)
	return slice6ProductPGFaultAction{RunID: edge.Run.id,
		ProductID: edge.ProductID, PostgresID: edge.PostgresID, NetworkID: edge.NetworkID,
		ProductPID: product.PID, PostgresPID: postgres.PID,
		ProductStartedAt: product.StartedAt, PostgresStartedAt: postgres.StartedAt,
		ProductOtherNetworks: productOther, PostgresNetworks: pgNetworks,
		BeforeDigest: slice6ReceiptSHA256([]byte(identity)), BeforeProjection: identity,
		BeforeDocker: slice6GuestRecoveryDockerSnapshot{Product: bytes.Clone(productRaw),
			Peer: bytes.Clone(postgresRaw), Network: bytes.Clone(raw), Retained: bytes.Clone(pgIdentity)},
		Disconnected: !connected}, nil
}

func slice6DisconnectProductPGEdge(ctx context.Context,
	edge slice6ProductPGFaultEdge) (slice6ProductPGFaultAction, error) {
	return slice6DisconnectProductPGEdgeWithCommand(ctx, edge, slice6GuestNetworkCommand)
}

func slice6DisconnectProductPGEdgeWithCommand(ctx context.Context,
	edge slice6ProductPGFaultEdge, command slice6NetworkCommand) (slice6ProductPGFaultAction, error) {
	return slice6DisconnectProductPGEdgeWithProbe(ctx, edge, command, slice6CheckProductPGFaultSnapshot)
}

type slice6ProductPGFaultProbe func(context.Context, slice6ProductPGFaultEdge, bool) (slice6ProductPGFaultAction, error)

func slice6DisconnectProductPGEdgeWithProbe(ctx context.Context, edge slice6ProductPGFaultEdge,
	command slice6NetworkCommand, probe slice6ProductPGFaultProbe) (slice6ProductPGFaultAction, error) {
	return slice6DisconnectProductPGEdgeWithProbeRecorded(ctx, edge, command, probe, nil)
}

func slice6DisconnectProductPGEdgeWithProbeRecorded(ctx context.Context, edge slice6ProductPGFaultEdge,
	command slice6NetworkCommand, probe slice6ProductPGFaultProbe,
	recorder *slice6GuestRecoveryERecorder) (slice6ProductPGFaultAction, error) {
	if command == nil || probe == nil {
		return slice6ProductPGFaultAction{}, errors.New("Product PG fault command unavailable")
	}
	before, err := probe(ctx, edge, true)
	if err != nil {
		return slice6ProductPGFaultAction{}, err
	}
	if ctx.Err() != nil {
		return slice6ProductPGFaultAction{}, errors.New("Product PG fault budget expired before mutation")
	}
	cleanup, stop := slice6NetworkCleanupContext(ctx)
	defer stop()
	deadline, _ := cleanup.Deadline()
	mutation, stopMutation := context.WithDeadline(ctx, deadline)
	defer stopMutation()
	started := time.Now().UTC()
	before.StartedUTC = started.Format(time.RFC3339Nano)
	if recorder != nil && recorder.record("pg_down_call",
		slice6GuestRecoveryActionRef(before.BeforeProjection, before.StartedUTC, before.BeforeDocker)) != nil {
		return before, errors.New("Product PG fault E call journal unavailable")
	}
	before.Attempted = true
	output, commandErr, overflow := command(mutation,
		"network", "disconnect", edge.NetworkID, edge.ProductID)
	clear(output)
	if cleanup.Err() != nil {
		before.OutcomeUnknown = true
		return before, errors.New("Product PG original cleanup deadline exhausted")
	}
	after, err := probe(cleanup, edge, false)
	readbackUncertain := err != nil
	if err != nil && cleanup.Err() == nil {
		after, err = probe(cleanup, edge, false)
	}
	if err != nil {
		if cleanup.Err() == nil {
			if connected, connectedErr := probe(cleanup, edge, true); connectedErr == nil &&
				connected.ProductPID == before.ProductPID && connected.PostgresPID == before.PostgresPID &&
				connected.ProductStartedAt == before.ProductStartedAt && connected.PostgresStartedAt == before.PostgresStartedAt &&
				connected.ProductOtherNetworks == before.ProductOtherNetworks && connected.PostgresNetworks == before.PostgresNetworks {
				return before, errors.New("Product PG disconnect not applied")
			}
		}
		before.OutcomeUnknown = true
		return before, errors.New("Product PG disconnect outcome unknown; exact stop required")
	}
	if err != nil || after.ProductPID != before.ProductPID || after.PostgresPID != before.PostgresPID ||
		after.ProductStartedAt != before.ProductStartedAt ||
		after.PostgresStartedAt != before.PostgresStartedAt ||
		after.ProductOtherNetworks != before.ProductOtherNetworks ||
		after.PostgresNetworks != before.PostgresNetworks {
		before.OutcomeUnknown = true
		return before, errors.New("Product PG disconnect/readback drift")
	}
	before.AfterDigest = after.BeforeDigest
	before.AfterProjection = after.BeforeProjection
	before.AfterDocker = after.BeforeDocker
	before.Disconnected = true
	before.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if commandErr != nil || overflow || readbackUncertain || ctx.Err() != nil || cleanup.Err() != nil {
		restored, restoreErr := slice6RestoreProductPGEdge(cleanup, edge, before)
		if restoreErr != nil && (restored.Disconnected || restored.AfterDigest != before.BeforeDigest) {
			before.OutcomeUnknown = true
			return before, errors.New("Product PG disconnect response lost; exact restore unconfirmed")
		}
		before.Disconnected = false
		before.AfterDigest = before.BeforeDigest
		before.AfterProjection = before.BeforeProjection
		before.AfterDocker = before.BeforeDocker
		return before, errors.New("Product PG disconnect response lost; exact edge restored")
	}
	if recorder != nil && recorder.record("pg_down_observed",
		slice6GuestRecoveryActionRef(before.AfterProjection, before.FinishedUTC, before.AfterDocker)) != nil {
		before.OutcomeUnknown = true
		return before, errors.New("Product PG fault E observation journal unavailable")
	}
	return before, nil
}

func slice6RestoreProductPGEdge(ctx context.Context, edge slice6ProductPGFaultEdge,
	detached slice6ProductPGFaultAction) (slice6ProductPGFaultAction, error) {
	return slice6RestoreProductPGEdgeWithCommand(ctx, edge, detached, slice6GuestNetworkCommand)
}

func slice6RestoreProductPGEdgeWithCommand(ctx context.Context, edge slice6ProductPGFaultEdge,
	detached slice6ProductPGFaultAction, command slice6NetworkCommand) (slice6ProductPGFaultAction, error) {
	return slice6RestoreProductPGEdgeWithProbe(ctx, edge, detached, command, slice6CheckProductPGFaultSnapshot)
}

func slice6RestoreProductPGEdgeWithProbe(ctx context.Context, edge slice6ProductPGFaultEdge,
	detached slice6ProductPGFaultAction, command slice6NetworkCommand,
	probe slice6ProductPGFaultProbe) (slice6ProductPGFaultAction, error) {
	return slice6RestoreProductPGEdgeWithProbeRecorded(ctx, edge, detached, command, probe, nil)
}

func slice6RestoreProductPGEdgeWithProbeRecorded(ctx context.Context, edge slice6ProductPGFaultEdge,
	detached slice6ProductPGFaultAction, command slice6NetworkCommand,
	probe slice6ProductPGFaultProbe, recorder *slice6GuestRecoveryERecorder) (slice6ProductPGFaultAction, error) {
	if ctx == nil || ctx.Err() != nil || detached.RunID != edge.Run.id || detached.ProductID != edge.ProductID ||
		detached.PostgresID != edge.PostgresID || detached.NetworkID != edge.NetworkID ||
		!detached.Disconnected || detached.AfterDigest == "" || command == nil || probe == nil {
		return slice6ProductPGFaultAction{}, errors.New("Product PG detach receipt unavailable")
	}
	budget, stop := slice6NetworkCleanupContext(ctx)
	defer stop()
	before, err := probe(budget, edge, false)
	if err != nil || before.BeforeDigest != detached.AfterDigest ||
		before.ProductOtherNetworks != detached.ProductOtherNetworks ||
		before.PostgresNetworks != detached.PostgresNetworks ||
		before.ProductPID != detached.ProductPID || before.PostgresPID != detached.PostgresPID {
		return slice6ProductPGFaultAction{}, errors.New("Product PG pre-restore drift")
	}
	if budget.Err() != nil {
		return slice6ProductPGFaultAction{}, errors.New("Product PG restore budget expired before mutation")
	}
	started := time.Now().UTC()
	before.StartedUTC = started.Format(time.RFC3339Nano)
	if recorder != nil && recorder.record("pg_up_call",
		slice6GuestRecoveryActionRef(before.BeforeProjection, before.StartedUTC, before.BeforeDocker)) != nil {
		return before, errors.New("Product PG restore E call journal unavailable")
	}
	before.Attempted = true
	output, commandErr, overflow := command(budget,
		"network", "connect", "--ip", edge.ProductIP, edge.NetworkID, edge.ProductID)
	clear(output)
	if budget.Err() != nil {
		before.OutcomeUnknown = true
		return before, errors.New("Product PG restore deadline exhausted after command")
	}
	after, err := probe(budget, edge, true)
	readbackUncertain := err != nil
	if err != nil && budget.Err() == nil {
		after, err = probe(budget, edge, true)
	}
	if err != nil || after.ProductPID != before.ProductPID || after.PostgresPID != before.PostgresPID ||
		after.ProductStartedAt != before.ProductStartedAt ||
		after.PostgresStartedAt != before.PostgresStartedAt ||
		after.ProductOtherNetworks != before.ProductOtherNetworks ||
		after.PostgresNetworks != before.PostgresNetworks {
		before.OutcomeUnknown = true
		return before, errors.New("Product PG reconnect/readback drift")
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
		return before, errors.New("Product PG reconnect response lost; exact original edge observed")
	}
	if recorder != nil && recorder.record("pg_up_observed",
		slice6GuestRecoveryActionRef(before.AfterProjection, before.FinishedUTC, before.AfterDocker)) != nil {
		return before, errors.New("Product PG restore E observation journal unavailable")
	}
	return before, nil
}

// Production-candidate E may only use this wrapper with a previously observed
// full nine-network/PG source proof; the no-issuer drill intentionally uses
// the lower-level edge action and cannot satisfy this authority.
func slice6DisconnectProductPGEdgeFormal(ctx context.Context, edge slice6ProductPGFaultEdge,
	target slice6GuestOperatorTarget, source slice6GuestOperatorFormalSource,
	profileDigest string) (slice6ProductPGFaultAction, error) {
	return slice6DisconnectProductPGEdgeFormalCore(ctx, edge, target, source, profileDigest, nil)
}

// The E path keeps the full source/PG proof on both sides of the mutation,
// while emitting the call and observed events at the actual Docker action.
func slice6DisconnectProductPGEdgeFormalRecorded(ctx context.Context, edge slice6ProductPGFaultEdge,
	target slice6GuestOperatorTarget, source slice6GuestOperatorFormalSource,
	profileDigest string, recorder *slice6GuestRecoveryERecorder) (slice6ProductPGFaultAction, error) {
	if recorder == nil || recorder.runID != edge.Run.id {
		return slice6ProductPGFaultAction{}, errors.New("formal Product PG E recorder unavailable")
	}
	return slice6DisconnectProductPGEdgeFormalCore(ctx, edge, target, source, profileDigest, recorder)
}

func slice6DisconnectProductPGEdgeFormalCore(ctx context.Context, edge slice6ProductPGFaultEdge,
	target slice6GuestOperatorTarget, source slice6GuestOperatorFormalSource,
	profileDigest string, recorder *slice6GuestRecoveryERecorder) (slice6ProductPGFaultAction, error) {
	if !slice6ProductPGFaultSourceMatches(edge, target, source, profileDigest) {
		return slice6ProductPGFaultAction{}, errors.New("formal Product PG fault source unavailable")
	}
	before, err := slice6InspectGuestOperatorPG(ctx, target)
	if err != nil || before != source.pgFingerprint {
		return slice6ProductPGFaultAction{}, errors.New("formal Product PG source changed before fault")
	}
	action, err := slice6DisconnectProductPGEdgeWithProbeRecorded(ctx, edge,
		slice6GuestNetworkCommand, slice6CheckProductPGFaultSnapshot, recorder)
	if err != nil {
		return action, err
	}
	after, err := slice6InspectGuestOperatorPG(ctx, target)
	if err != nil || after != source.pgFingerprint {
		return action, errors.New("formal Product PG source changed during fault")
	}
	return action, nil
}

func slice6RestoreProductPGEdgeFormal(ctx context.Context, edge slice6ProductPGFaultEdge,
	target slice6GuestOperatorTarget, source slice6GuestOperatorFormalSource,
	profileDigest string, detached slice6ProductPGFaultAction) (slice6ProductPGFaultAction, error) {
	return slice6RestoreProductPGEdgeFormalCore(ctx, edge, target, source, profileDigest, detached, nil)
}

func slice6RestoreProductPGEdgeFormalRecorded(ctx context.Context, edge slice6ProductPGFaultEdge,
	target slice6GuestOperatorTarget, source slice6GuestOperatorFormalSource,
	profileDigest string, detached slice6ProductPGFaultAction,
	recorder *slice6GuestRecoveryERecorder) (slice6ProductPGFaultAction, error) {
	if recorder == nil || recorder.runID != edge.Run.id {
		return slice6ProductPGFaultAction{}, errors.New("formal Product PG E recorder unavailable")
	}
	return slice6RestoreProductPGEdgeFormalCore(ctx, edge, target, source, profileDigest, detached, recorder)
}

func slice6RestoreProductPGEdgeFormalCore(ctx context.Context, edge slice6ProductPGFaultEdge,
	target slice6GuestOperatorTarget, source slice6GuestOperatorFormalSource,
	profileDigest string, detached slice6ProductPGFaultAction,
	recorder *slice6GuestRecoveryERecorder) (slice6ProductPGFaultAction, error) {
	if !slice6ProductPGFaultSourceMatches(edge, target, source, profileDigest) {
		return slice6ProductPGFaultAction{}, errors.New("formal Product PG recovery source unavailable")
	}
	before, err := slice6InspectGuestOperatorPG(ctx, target)
	if err != nil || before != source.pgFingerprint {
		return slice6ProductPGFaultAction{}, errors.New("formal Product PG source changed before recovery")
	}
	action, err := slice6RestoreProductPGEdgeWithProbeRecorded(ctx, edge, detached,
		slice6GuestNetworkCommand, slice6CheckProductPGFaultSnapshot, recorder)
	if err != nil {
		return action, err
	}
	after, err := slice6InspectGuestOperatorPG(ctx, target)
	if err != nil || after != source.pgFingerprint {
		return action, errors.New("formal Product PG source changed during recovery")
	}
	return action, nil
}

func slice6ProductPGFaultSourceMatches(edge slice6ProductPGFaultEdge,
	target slice6GuestOperatorTarget, source slice6GuestOperatorFormalSource,
	profileDigest string) bool {
	endpoint, found := source.endpoints[edge.NetworkName]
	return edge.valid() && target.valid() &&
		guestRevokeFixtureDigestGate(profileDigest) && source.profileDigest == profileDigest &&
		source.runID == edge.Run.id && target.Run.id == edge.Run.id &&
		source.postgresID == edge.PostgresID && target.PostgresID == edge.PostgresID &&
		source.imageID == edge.PostgresImageID && target.ImageID == edge.PostgresImageID &&
		source.imageRef == edge.ImageRef && target.ImageRef == edge.ImageRef &&
		guestRevokeFixtureDigestGate(source.networkProofDigest) &&
		guestRevokeFixtureDigestGate(source.pgFingerprint) &&
		len(source.endpoints) == 9 && len(source.dialerIDs) == 9 &&
		found && endpoint.ID == edge.NetworkID && endpoint.IP == edge.PostgresIP &&
		source.dialerIDs[edge.NetworkName] == edge.ProductID
}
