//go:build phase6slice6gate

package productphase6gate

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

type slice6GuestRecoveryActionLedger struct {
	PGDown, PGUp      slice6ProductPGFaultAction
	GuestOff, GuestOn slice6GuestRecoveryEdgeAction
	RawProofDigest    string
}

type slice6GuestRecoveryDockerSnapshot struct {
	Product, Peer, Network, Retained []byte
}

func slice6CheckPGActionProjection(action slice6ProductPGFaultAction, beforeConnected bool) bool {
	parse := func(projection, digest string, connected bool) bool {
		if len(projection) < 32 || len(projection) > 1024 ||
			strings.ContainsAny(projection, "\n\r\x00") || slice6ReceiptSHA256([]byte(projection)) != digest {
			return false
		}
		parts := strings.Split(projection, "|")
		if len(parts) != 13 || parts[0] != action.RunID || parts[1] != action.ProductID ||
			parts[2] != action.PostgresID || parts[3] != strconv.Itoa(action.ProductPID) ||
			parts[4] != action.ProductStartedAt || parts[5] != strconv.Itoa(action.PostgresPID) ||
			parts[6] != action.PostgresStartedAt || parts[7] != action.NetworkID ||
			parts[11] != action.PostgresNetworks || parts[10] != action.ProductOtherNetworks ||
			parts[12] != strconv.FormatBool(connected) {
			return false
		}
		productIP, productErr := netip.ParseAddr(parts[8])
		postgresIP, postgresErr := netip.ParseAddr(parts[9])
		return productErr == nil && postgresErr == nil && productIP.Is4() && postgresIP.Is4() && productIP != postgresIP
	}
	return parse(action.BeforeProjection, action.BeforeDigest, beforeConnected) &&
		parse(action.AfterProjection, action.AfterDigest, !beforeConnected)
}

func slice6CheckGuestActionProjection(action slice6GuestRecoveryEdgeAction, beforeConnected bool) bool {
	parse := func(projection, digest string, connected bool) bool {
		if len(projection) < 32 || len(projection) > 1024 ||
			strings.ContainsAny(projection, "\n\r\x00") || slice6ReceiptSHA256([]byte(projection)) != digest {
			return false
		}
		parts := strings.Split(projection, "|")
		if len(parts) != 13 || parts[0] != action.RunID || parts[1] != action.ProductID ||
			parts[2] != action.GuestID || parts[3] != strconv.Itoa(action.ProductPID) ||
			parts[4] != action.ProductStartedAt || parts[5] != strconv.Itoa(action.GuestPID) ||
			parts[6] != action.GuestStartedAt || parts[7] != action.ProductNetworkID ||
			parts[9] != action.GuestIP || parts[11] != action.RuntimeIP ||
			len(parts[10]) != 64 || !lowerHexSlice6(parts[10]) ||
			parts[12] != strconv.FormatBool(connected) {
			return false
		}
		productIP, productErr := netip.ParseAddr(parts[8])
		guestIP, guestErr := netip.ParseAddr(parts[9])
		runtimeIP, runtimeErr := netip.ParseAddr(parts[11])
		return productErr == nil && guestErr == nil && runtimeErr == nil &&
			productIP.Is4() && guestIP.Is4() && runtimeIP.Is4()
	}
	return parse(action.BeforeProjection, action.BeforeDigest, beforeConnected) &&
		parse(action.AfterProjection, action.AfterDigest, !beforeConnected)
}

// This is a UTC consistency check, not yet a monotonic E event ledger. The
// formal merger must require same-run monotonic event/order receipts and raw
// action/source observations before it can promote this component.
func slice6VerifyGuestRecoveryActionLedger(runID, sourceDigest string,
	ledger slice6GuestRecoveryActionLedger, trigger slice6GuestRecoveryCloseTrigger,
	sql [4]slice6GuestOperatorRawBinding,
	process [4]slice6GuestRecoveryRawBinding) (string, error) {
	if len(runID) != 32 || !lowerHexSlice6(runID) ||
		!guestRevokeFixtureDigestGate(sourceDigest) ||
		trigger.RunID != runID ||
		ledger.PGDown.RunID != runID || ledger.PGUp.RunID != runID ||
		ledger.GuestOff.RunID != runID || ledger.GuestOn.RunID != runID ||
		ledger.PGDown.ProductID != process[0].ContainerID ||
		ledger.PGUp.ProductID != process[0].ContainerID ||
		ledger.GuestOff.ProductID != process[0].ContainerID ||
		ledger.GuestOn.ProductID != process[0].ContainerID ||
		ledger.GuestOff.GuestID != process[1].ContainerID ||
		ledger.GuestOn.GuestID != process[1].ContainerID ||
		ledger.PGDown.PostgresID != sql[0].PostgresID ||
		ledger.PGUp.PostgresID != sql[0].PostgresID ||
		ledger.PGDown.NetworkID != ledger.PGUp.NetworkID ||
		ledger.GuestOff.ProductNetworkID != ledger.GuestOn.ProductNetworkID ||
		ledger.PGDown.ProductPID != process[0].PID ||
		ledger.PGUp.ProductPID != process[0].PID ||
		ledger.GuestOff.ProductPID != process[0].PID ||
		ledger.GuestOn.ProductPID != process[0].PID ||
		ledger.GuestOff.GuestPID != process[1].PID ||
		ledger.GuestOn.GuestPID != process[1].PID ||
		ledger.PGDown.ProductStartedAt != process[0].StartedAt ||
		ledger.PGUp.ProductStartedAt != process[0].StartedAt ||
		ledger.GuestOff.ProductStartedAt != process[0].StartedAt ||
		ledger.GuestOn.ProductStartedAt != process[0].StartedAt ||
		ledger.GuestOff.GuestStartedAt != process[1].StartedAt ||
		ledger.GuestOn.GuestStartedAt != process[1].StartedAt ||
		ledger.PGDown.PostgresPID != ledger.PGUp.PostgresPID ||
		ledger.PGDown.PostgresStartedAt != ledger.PGUp.PostgresStartedAt ||
		ledger.PGDown.ProductOtherNetworks != ledger.PGUp.ProductOtherNetworks ||
		ledger.PGDown.PostgresNetworks != ledger.PGUp.PostgresNetworks ||
		ledger.GuestOff.GuestIP != ledger.GuestOn.GuestIP ||
		ledger.GuestOff.RuntimeIP != ledger.GuestOn.RuntimeIP ||
		!ledger.PGDown.Attempted || !ledger.PGUp.Attempted ||
		!ledger.GuestOff.Attempted || !ledger.GuestOn.Attempted ||
		ledger.PGDown.OutcomeUnknown || ledger.PGUp.OutcomeUnknown ||
		ledger.GuestOff.OutcomeUnknown || ledger.GuestOn.OutcomeUnknown ||
		!ledger.PGDown.Disconnected || ledger.PGUp.Disconnected ||
		!ledger.GuestOff.Disconnected || ledger.GuestOn.Disconnected ||
		ledger.PGDown.BeforeDigest == "" || ledger.GuestOff.BeforeDigest == "" ||
		ledger.PGDown.BeforeDigest == ledger.PGDown.AfterDigest ||
		ledger.GuestOff.BeforeDigest == ledger.GuestOff.AfterDigest ||
		ledger.PGUp.BeforeDigest != ledger.PGDown.AfterDigest ||
		ledger.PGUp.AfterDigest != ledger.PGDown.BeforeDigest ||
		ledger.GuestOn.BeforeDigest != ledger.GuestOff.AfterDigest ||
		ledger.GuestOn.AfterDigest != ledger.GuestOff.BeforeDigest ||
		ledger.PGDown.BeforeProjection != ledger.PGUp.AfterProjection ||
		ledger.PGDown.AfterProjection != ledger.PGUp.BeforeProjection ||
		ledger.GuestOff.BeforeProjection != ledger.GuestOn.AfterProjection ||
		ledger.GuestOff.AfterProjection != ledger.GuestOn.BeforeProjection ||
		!slice6CheckPGActionProjection(ledger.PGDown, true) ||
		!slice6CheckPGActionProjection(ledger.PGUp, false) ||
		!slice6CheckGuestActionProjection(ledger.GuestOff, true) ||
		!slice6CheckGuestActionProjection(ledger.GuestOn, false) {
		return "", errors.New("Guest recovery action identity/state drift")
	}
	for _, binding := range sql {
		if binding.RunID != runID || binding.SourceProofDigest != sourceDigest ||
			binding.ProfileDigest != process[0].ProfileDigest ||
			binding.PostgresID != ledger.PGDown.PostgresID {
			return "", errors.New("Guest recovery SQL/source binding drift")
		}
	}
	parse := func(value string) (time.Time, error) {
		observed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || observed.IsZero() {
			return time.Time{}, phase6guestreceipt.ErrUnavailable
		}
		return observed, nil
	}
	var actionStart, actionFinish [4]time.Time
	for index, pair := range [4][2]string{
		{ledger.PGDown.StartedUTC, ledger.PGDown.FinishedUTC},
		{ledger.GuestOff.StartedUTC, ledger.GuestOff.FinishedUTC},
		{ledger.PGUp.StartedUTC, ledger.PGUp.FinishedUTC},
		{ledger.GuestOn.StartedUTC, ledger.GuestOn.FinishedUTC},
	} {
		var err error
		actionStart[index], err = parse(pair[0])
		if err != nil {
			return "", err
		}
		actionFinish[index], err = parse(pair[1])
		if err != nil || !actionFinish[index].After(actionStart[index]) {
			return "", errors.New("Guest recovery action time nonmonotonic")
		}
	}
	triggerTime, err := parse(trigger.ObservedUTC)
	if err != nil {
		return "", err
	}
	var sqlStart, sqlFinish [4]time.Time
	for index, binding := range sql {
		sqlStart[index], err = parse(binding.ReadStartedUTC)
		if err != nil {
			return "", err
		}
		sqlFinish[index], err = parse(binding.SettingsFinishedUTC)
		if err != nil || !sqlFinish[index].After(sqlStart[index]) {
			return "", errors.New("Guest recovery SQL time nonmonotonic")
		}
	}
	var processStart, processFinish [4]time.Time
	for index, binding := range process {
		processStart[index], err = parse(binding.StartedAt)
		if err != nil {
			return "", err
		}
		processFinish[index], err = parse(binding.FinishedAt)
		if err != nil || !processFinish[index].After(processStart[index]) {
			return "", errors.New("Guest recovery PID1 time nonmonotonic")
		}
	}
	if !sqlStart[0].After(processStart[1]) ||
		!actionStart[0].After(sqlFinish[0]) ||
		!triggerTime.After(actionFinish[0]) ||
		!actionStart[1].After(triggerTime) ||
		!actionStart[2].After(actionFinish[1]) ||
		!sqlStart[1].After(actionFinish[2]) ||
		!actionStart[3].After(sqlFinish[1]) ||
		!sqlStart[2].After(actionFinish[3]) ||
		!processFinish[0].After(sqlFinish[2]) ||
		!processFinish[1].After(sqlFinish[2]) ||
		!sqlStart[3].After(processFinish[0]) ||
		!sqlStart[3].After(processFinish[1]) ||
		!processStart[2].After(sqlFinish[3]) ||
		!processStart[3].After(sqlFinish[3]) {
		return "", errors.New("Guest recovery E action/SQL/PID1 order drift")
	}
	lines := []string{runID, sourceDigest, ledger.RawProofDigest,
		ledger.PGDown.BeforeDigest, ledger.PGDown.AfterDigest,
		ledger.GuestOff.BeforeDigest, ledger.GuestOff.AfterDigest,
		ledger.PGUp.AfterDigest, ledger.GuestOn.AfterDigest,
		ledger.PGDown.StartedUTC, ledger.PGDown.FinishedUTC,
		ledger.GuestOff.StartedUTC, ledger.GuestOff.FinishedUTC,
		ledger.PGUp.StartedUTC, ledger.PGUp.FinishedUTC,
		ledger.GuestOn.StartedUTC, ledger.GuestOn.FinishedUTC,
		trigger.ObservedUTC}
	for _, binding := range sql {
		lines = append(lines, binding.Stage, binding.ReadExecID, binding.CheckExecID,
			binding.SettingsRecheckExecID, binding.RowSHA256)
	}
	for _, binding := range process {
		lines = append(lines, binding.Process, binding.ContainerID, binding.SHA256)
	}
	return slice6ReceiptSHA256([]byte(strings.Join(lines, "|"))), nil
}
