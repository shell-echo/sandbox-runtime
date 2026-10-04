//go:build phase6slice6gate

package productphase6gate

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func slice6SyntheticPGProjection(action slice6ProductPGFaultAction, productIP, postgresIP string,
	connected bool) string {
	return strings.Join([]string{action.RunID, action.ProductID, action.PostgresID,
		strconv.Itoa(action.ProductPID), action.ProductStartedAt, strconv.Itoa(action.PostgresPID),
		action.PostgresStartedAt, action.NetworkID, productIP, postgresIP,
		action.ProductOtherNetworks, action.PostgresNetworks, strconv.FormatBool(connected)}, "|")
}

func slice6SyntheticGuestProjection(action slice6GuestRecoveryEdgeAction, productIP,
	runtimeNetworkID string, connected bool) string {
	return strings.Join([]string{action.RunID, action.ProductID, action.GuestID,
		strconv.Itoa(action.ProductPID), action.ProductStartedAt, strconv.Itoa(action.GuestPID),
		action.GuestStartedAt, action.ProductNetworkID, productIP, action.GuestIP,
		runtimeNetworkID, action.RuntimeIP, strconv.FormatBool(connected)}, "|")
}

func slice6SyntheticActionProjections(ledger *slice6GuestRecoveryActionLedger,
	productPGIP, postgresIP, productGuestIP, runtimeNetworkID string) {
	pgConnected := slice6SyntheticPGProjection(ledger.PGDown, productPGIP, postgresIP, true)
	pgDisconnected := slice6SyntheticPGProjection(ledger.PGDown, productPGIP, postgresIP, false)
	guestConnected := slice6SyntheticGuestProjection(ledger.GuestOff, productGuestIP, runtimeNetworkID, true)
	guestDisconnected := slice6SyntheticGuestProjection(ledger.GuestOff, productGuestIP, runtimeNetworkID, false)
	ledger.PGDown.BeforeProjection, ledger.PGDown.AfterProjection = pgConnected, pgDisconnected
	ledger.PGUp.BeforeProjection, ledger.PGUp.AfterProjection = pgDisconnected, pgConnected
	ledger.GuestOff.BeforeProjection, ledger.GuestOff.AfterProjection = guestConnected, guestDisconnected
	ledger.GuestOn.BeforeProjection, ledger.GuestOn.AfterProjection = guestDisconnected, guestConnected
	ledger.PGDown.BeforeDigest, ledger.PGDown.AfterDigest = slice6ReceiptSHA256([]byte(pgConnected)), slice6ReceiptSHA256([]byte(pgDisconnected))
	ledger.PGUp.BeforeDigest, ledger.PGUp.AfterDigest = ledger.PGDown.AfterDigest, ledger.PGDown.BeforeDigest
	ledger.GuestOff.BeforeDigest, ledger.GuestOff.AfterDigest = slice6ReceiptSHA256([]byte(guestConnected)), slice6ReceiptSHA256([]byte(guestDisconnected))
	ledger.GuestOn.BeforeDigest, ledger.GuestOn.AfterDigest = ledger.GuestOff.AfterDigest, ledger.GuestOff.BeforeDigest
}

func TestSlice6GuestRecoveryActionLedgerMonotonicOrder(t *testing.T) {
	base := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	stamp := func(seconds int) string {
		return base.Add(time.Duration(seconds) * time.Second).Format(time.RFC3339Nano)
	}
	runID := strings.Repeat("a", 32)
	source := "sha256:" + strings.Repeat("b", 64)
	profile := "sha256:" + strings.Repeat("c", 64)
	productA, guestA := strings.Repeat("d", 64), strings.Repeat("e", 64)
	pgID := strings.Repeat("f", 64)
	process := [4]slice6GuestRecoveryRawBinding{
		{Process: "product-a", RunID: runID, ContainerID: productA, PID: 101,
			StartedAt: stamp(0), FinishedAt: stamp(20), ProfileDigest: profile},
		{Process: "guest-a", RunID: runID, ContainerID: guestA, PID: 102,
			StartedAt: stamp(1), FinishedAt: stamp(21), ProfileDigest: profile},
		{Process: "product-b", RunID: runID, ContainerID: strings.Repeat("1", 64), PID: 103,
			StartedAt: stamp(30), FinishedAt: stamp(50), ProfileDigest: profile},
		{Process: "guest-b", RunID: runID, ContainerID: strings.Repeat("2", 64), PID: 104,
			StartedAt: stamp(31), FinishedAt: stamp(51), ProfileDigest: profile},
	}
	var sql [4]slice6GuestOperatorRawBinding
	for index, item := range []struct {
		stage         string
		start, finish int
	}{
		{"initial", 2, 3}, {"released", 11, 12}, {"reconnected", 17, 18}, {"final_released", 22, 23},
	} {
		sql[index] = slice6GuestOperatorRawBinding{Stage: item.stage, RunID: runID,
			ProfileDigest: profile, SourceProofDigest: source, PostgresID: pgID,
			ReadStartedUTC: stamp(item.start), SettingsFinishedUTC: stamp(item.finish),
			ReadExecID:            strings.Repeat(string(rune('3'+index)), 64),
			CheckExecID:           strings.Repeat(string(rune('7'+index)), 64),
			SettingsRecheckExecID: strings.Repeat(string(rune('b'+index)), 64),
			RowSHA256:             "sha256:" + strings.Repeat(string(rune('3'+index)), 64)}
	}
	pg := slice6ProductPGFaultAction{RunID: runID, ProductID: productA,
		PostgresID: pgID, NetworkID: strings.Repeat("7", 64),
		ProductPID: 101, PostgresPID: 105, ProductStartedAt: stamp(0), PostgresStartedAt: stamp(-1),
		ProductOtherNetworks: "other", PostgresNetworks: "all", Attempted: true}
	guest := slice6GuestRecoveryEdgeAction{RunID: runID, ProductID: productA,
		GuestID: guestA, ProductNetworkID: strings.Repeat("8", 64),
		ProductPID: 101, GuestPID: 102, ProductStartedAt: stamp(0), GuestStartedAt: stamp(1),
		GuestIP: "10.77.0.4", RuntimeIP: "10.77.1.4", Attempted: true}
	ledger := slice6GuestRecoveryActionLedger{PGDown: pg, PGUp: pg,
		GuestOff: guest, GuestOn: guest}
	slice6SyntheticActionProjections(&ledger, "10.77.2.4", "10.77.2.5", "10.77.0.5", strings.Repeat("9", 64))
	ledger.PGDown.Disconnected = true
	ledger.PGDown.StartedUTC, ledger.PGDown.FinishedUTC = stamp(4), stamp(5)
	ledger.PGUp.StartedUTC, ledger.PGUp.FinishedUTC = stamp(9), stamp(10)
	ledger.GuestOff.Disconnected = true
	ledger.GuestOff.StartedUTC, ledger.GuestOff.FinishedUTC = stamp(7), stamp(8)
	ledger.GuestOn.StartedUTC, ledger.GuestOn.FinishedUTC = stamp(13), stamp(14)
	trigger := slice6GuestRecoveryCloseTrigger{RunID: runID, ObservedUTC: stamp(6)}
	check := func(actions slice6GuestRecoveryActionLedger, tr slice6GuestRecoveryCloseTrigger,
		stages [4]slice6GuestOperatorRawBinding, processes [4]slice6GuestRecoveryRawBinding) error {
		_, err := slice6VerifyGuestRecoveryActionLedger(runID, source, actions, tr, stages, processes)
		return err
	}
	if err := check(ledger, trigger, sql, process); err != nil {
		t.Fatalf("monotonic E ledger rejected: %v", err)
	}
	for _, test := range []struct {
		name string
		edit func(*slice6GuestRecoveryActionLedger, *slice6GuestRecoveryCloseTrigger,
			*[4]slice6GuestOperatorRawBinding, *[4]slice6GuestRecoveryRawBinding)
	}{
		{"unknown mutation", func(l *slice6GuestRecoveryActionLedger, _ *slice6GuestRecoveryCloseTrigger,
			_ *[4]slice6GuestOperatorRawBinding, _ *[4]slice6GuestRecoveryRawBinding) {
			l.PGDown.OutcomeUnknown = true
		}},
		{"PG restore before Guest isolation", func(l *slice6GuestRecoveryActionLedger, _ *slice6GuestRecoveryCloseTrigger,
			_ *[4]slice6GuestOperatorRawBinding, _ *[4]slice6GuestRecoveryRawBinding) {
			l.PGUp.StartedUTC = stamp(7)
		}},
		{"Guest isolation before observed close", func(l *slice6GuestRecoveryActionLedger, _ *slice6GuestRecoveryCloseTrigger,
			_ *[4]slice6GuestOperatorRawBinding, _ *[4]slice6GuestRecoveryRawBinding) {
			l.GuestOff.StartedUTC = stamp(5)
		}},
		{"wrong original IP restore", func(l *slice6GuestRecoveryActionLedger, _ *slice6GuestRecoveryCloseTrigger,
			_ *[4]slice6GuestOperatorRawBinding, _ *[4]slice6GuestRecoveryRawBinding) {
			l.GuestOn.GuestIP = "10.77.0.99"
		}},
		{"SQL release before PG restore", func(_ *slice6GuestRecoveryActionLedger, _ *slice6GuestRecoveryCloseTrigger,
			s *[4]slice6GuestOperatorRawBinding, _ *[4]slice6GuestRecoveryRawBinding) {
			s[1].ReadStartedUTC = stamp(9)
		}},
		{"B starts before A reconnect readback", func(_ *slice6GuestRecoveryActionLedger, _ *slice6GuestRecoveryCloseTrigger,
			_ *[4]slice6GuestOperatorRawBinding, p *[4]slice6GuestRecoveryRawBinding) {
			p[0].FinishedAt = stamp(17)
		}},
		{"only B-stop NULL snapshot", func(_ *slice6GuestRecoveryActionLedger, _ *slice6GuestRecoveryCloseTrigger,
			s *[4]slice6GuestOperatorRawBinding, _ *[4]slice6GuestRecoveryRawBinding) {
			s[3].ReadStartedUTC, s[3].SettingsFinishedUTC = stamp(52), stamp(53)
		}},
		{"B starts before A final NULL", func(_ *slice6GuestRecoveryActionLedger, _ *slice6GuestRecoveryCloseTrigger,
			_ *[4]slice6GuestOperatorRawBinding, p *[4]slice6GuestRecoveryRawBinding) {
			p[2].StartedAt = stamp(22)
		}},
		{"spliced source", func(_ *slice6GuestRecoveryActionLedger, _ *slice6GuestRecoveryCloseTrigger,
			s *[4]slice6GuestOperatorRawBinding, _ *[4]slice6GuestRecoveryRawBinding) {
			s[2].SourceProofDigest = "sha256:" + strings.Repeat("9", 64)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			wrongLedger, wrongTrigger, wrongSQL, wrongProcess := ledger, trigger, sql, process
			test.edit(&wrongLedger, &wrongTrigger, &wrongSQL, &wrongProcess)
			if check(wrongLedger, wrongTrigger, wrongSQL, wrongProcess) == nil {
				t.Fatal("nonmonotonic or spliced E action ledger accepted")
			}
		})
	}
}
