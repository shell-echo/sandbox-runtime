//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type slice6SyntheticEvent struct{ event, digest, reason string }

func slice6SyntheticGuestRecoveryPrecleanup(t *testing.T, run *slice6ReceiptEvidenceRun,
	source slice6GuestOperatorFormalSource, base time.Time, productID, pgID string) {
	t.Helper()
	stamp := func(seconds int) string {
		return base.Add(time.Duration(seconds) * time.Second).Format(time.RFC3339Nano)
	}
	profileDigest := source.profileDigest
	productConfig, guestConfig := "sha256:"+strings.Repeat("8", 64), "sha256:"+strings.Repeat("9", 64)
	initial, recovered, replacement := "sha256:"+strings.Repeat("a", 64),
		"sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64)
	productEvents := []slice6SyntheticEvent{
		{guestagent.ObservationProductAuthAccepted, initial, ""},
		{guestagent.ObservationProductWelcomeWritten, initial, ""},
		{guestagent.ObservationProductPeerInstalled, initial, ""},
		{guestagent.ObservationProductAuthorityDependencyLost, initial, ""},
		{guestagent.ObservationProductDisconnectPending, initial, ""},
		{guestagent.ObservationProductCloseCompleted, initial, "dependency_lost"},
		{guestagent.ObservationProductDisconnectResolved, initial, "released"},
		{guestagent.ObservationProductAuthAccepted, recovered, ""},
		{guestagent.ObservationProductWelcomeWritten, recovered, ""},
		{guestagent.ObservationProductPeerInstalled, recovered, ""},
		{guestagent.ObservationProductDisconnectPending, recovered, ""},
		{guestagent.ObservationProductCloseCompleted, recovered, "handler_shutdown"},
		{guestagent.ObservationProductDisconnectResolved, recovered, "released"},
	}
	guestEvents := []slice6SyntheticEvent{
		{guestagent.ObservationGuestHelloWritten, initial, ""},
		{guestagent.ObservationGuestWelcomeAccepted, initial, ""},
		{guestagent.ObservationGuestReadTerminated, initial, ""},
		{guestagent.ObservationGuestHelloWritten, recovered, ""},
		{guestagent.ObservationGuestWelcomeAccepted, recovered, ""},
		{guestagent.ObservationGuestReadTerminated, recovered, ""},
	}
	replacementProductEvents := []slice6SyntheticEvent{
		{guestagent.ObservationProductAuthAccepted, replacement, ""},
		{guestagent.ObservationProductWelcomeWritten, replacement, ""},
		{guestagent.ObservationProductPeerInstalled, replacement, ""},
		{guestagent.ObservationProductDisconnectPending, replacement, ""},
		{guestagent.ObservationProductCloseCompleted, replacement, "handler_shutdown"},
		{guestagent.ObservationProductDisconnectResolved, replacement, "released"},
	}
	replacementGuestEvents := []slice6SyntheticEvent{
		{guestagent.ObservationGuestHelloWritten, replacement, ""},
		{guestagent.ObservationGuestWelcomeAccepted, replacement, ""},
		{guestagent.ObservationGuestReadTerminated, replacement, ""},
	}
	encode := func(role, config string, events []slice6SyntheticEvent) ([]byte, int) {
		t.Helper()
		var raw []byte
		prefix := 0
		all := make([]slice6SyntheticEvent, 0, len(events)+2)
		all = append(all, slice6SyntheticEvent{event: "begin"})
		all = append(all, events...)
		all = append(all, slice6SyntheticEvent{event: "seal"})
		for index, item := range all {
			record := phase6guestreceipt.Record{Protocol: phase6guestreceipt.ProtocolV2,
				Role: role, Event: item.event, Sequence: uint64(index + 1),
				ElapsedNanos: int64(index), UnixMillis: base.UnixMilli()}
			switch item.event {
			case "begin":
				record.ProfileDigest, record.ConfigDigest = profileDigest, config
			case "seal":
				record.EventCount = uint64(len(events))
			default:
				record.AttemptDigest, record.BindingGeneration, record.Reason = item.digest, 1, item.reason
			}
			line, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, line...)
			raw = append(raw, '\n')
			if item.digest == initial && (item.event == guestagent.ObservationProductCloseCompleted ||
				item.event == guestagent.ObservationGuestReadTerminated) {
				prefix = len(raw)
			}
		}
		return raw, prefix
	}
	productARaw, productPrefix := encode("product", productConfig, productEvents)
	guestARaw, guestPrefix := encode("guest", guestConfig, guestEvents)
	productBRaw, _ := encode("product", productConfig, replacementProductEvents)
	guestBRaw, _ := encode("guest", guestConfig, replacementGuestEvents)
	guestA, productB, guestB := strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("f", 64)
	coreImage := "sha256:" + strings.Repeat("f", 64)
	var processes [4]slice6GuestRecoveryRawBinding
	for index, item := range []struct {
		name, role, id, config string
		pid, start, finish     int
		raw                    []byte
	}{
		{"product-a", "product", productID, productConfig, 123, 4, 44, productARaw},
		{"guest-a", "guest", guestA, guestConfig, 102, 9, 41, guestARaw},
		{"product-b", "product", productB, productConfig, 103, 50, 70, productBRaw},
		{"guest-b", "guest", guestB, guestConfig, 104, 51, 71, guestBRaw},
	} {
		name := slice6GuestRecoveryRawName(item.name)
		file, err := run.createV2RawFile(name)
		if err != nil {
			t.Fatal(err)
		}
		written, writeErr := file.Write(item.raw)
		if writeErr != nil || written != len(item.raw) || file.Sync() != nil || file.Close() != nil {
			t.Fatal("synthetic PID1 raw write unavailable")
		}
		processes[index] = slice6GuestRecoveryRawBinding{Process: item.name,
			Role: item.role, File: name, RunID: run.id, ContainerID: item.id, PID: item.pid,
			StartedAt: stamp(item.start), FinishedAt: stamp(item.finish),
			ImageID: coreImage, ImageRef: coreImage, ProfileDigest: profileDigest,
			ConfigDigest: item.config, SHA256: slice6ReceiptSHA256(item.raw), Bytes: len(item.raw),
			ExitCode: 0, CaptureStartUTC: stamp(item.start - 1), CaptureFinishUTC: stamp(item.finish + 1)}
		if index >= 2 {
			startRaw := []byte(strings.Join([]string{item.id, coreImage, coreImage, run.id,
				"none", "false", "true", strconv.Itoa(item.pid), stamp(item.start), "false"}, " ") + "\n")
			if err := run.writeV2BoundedPrivateFile(slice6GuestRecoveryStartInspectName(item.name),
				startRaw, 640, false); err != nil {
				t.Fatal(err)
			}
			processes[index].StartInspectSHA256 = slice6ReceiptSHA256(startRaw)
		}
	}
	settingsRaw := []byte("true|1791080000000000\n")
	var stages [4]slice6GuestOperatorRawBinding
	execHex := "123456789abc"
	for index, item := range []struct {
		stage string
		start int
		state string
	}{
		{"initial", 10, "connected"}, {"released", 21, "disconnected"},
		{"reconnected", 31, "connected"}, {"final_released", 46, "disconnected"},
	} {
		at := base.Add(time.Duration(item.start) * time.Second)
		ids := []string{strings.Repeat(string(execHex[index*3]), 64),
			strings.Repeat(string(execHex[index*3+1]), 64),
			strings.Repeat(string(execHex[index*3+2]), 64)}
		row := []byte(item.state + "|false|true|1791087000000000\n")
		if item.state == "disconnected" {
			row = []byte(item.state + "|true|true|1791087000000000\n")
		}
		read := slice6GuestOperatorReadback{RunID: run.id, ProfileDigest: profileDigest,
			SourceProofDigest: source.proofDigest(), SettingsRecheckExecID: ids[2],
			SettingsRecheckDigest: slice6ReceiptSHA256(settingsRaw),
			SettingsRecheckRaw:    settingsRaw, PostmasterStartMicros: 1791080000000000,
			TargetDigest: "sha256:" + strings.Repeat("7", 64),
			PostgresID:   pgID, PostgresFingerprint: source.pgFingerprint,
			OperationDigest: slice6ReceiptSHA256([]byte(item.stage)),
			ReadExecID:      ids[0], CheckExecID: ids[1],
			ReadExecStartedUTC:         at.Format(time.RFC3339Nano),
			ReadExecFinishedUTC:        at.Add(100 * time.Millisecond).Format(time.RFC3339Nano),
			CheckExecStartedUTC:        at.Add(200 * time.Millisecond).Format(time.RFC3339Nano),
			CheckExecFinishedUTC:       at.Add(300 * time.Millisecond).Format(time.RFC3339Nano),
			SettingsRecheckStartedUTC:  at.Add(400 * time.Millisecond).Format(time.RFC3339Nano),
			SettingsRecheckFinishedUTC: at.Add(500 * time.Millisecond).Format(time.RFC3339Nano),
			SQLDigest:                  slice6ReceiptSHA256([]byte(slice6GuestOperatorSelect)),
			BackendSQLDigest:           slice6ReceiptSHA256([]byte(slice6GuestOperatorBackendSelect)),
			OutputSHA256:               slice6ReceiptSHA256(row), RawRow: row, RawBackend: []byte("0\n"),
			State: item.state, NonceNull: item.state == "disconnected", DBTimeUnexpired: true,
			ExpiresUnixMicros: 1791087000000000}
		read.ReadExecExitRaw = slice6GuestOperatorExecExitReceipt(ids[0], pgID, read.ReadExecFinishedUTC)
		read.CheckExecExitRaw = slice6GuestOperatorExecExitReceipt(ids[1], pgID, read.CheckExecFinishedUTC)
		read.SettingsRecheckExitRaw = slice6GuestOperatorExecExitReceipt(ids[2], pgID, read.SettingsRecheckFinishedUTC)
		var err error
		stages[index], err = run.writeV2GuestOperatorRaw(item.stage, read)
		if err != nil {
			t.Fatalf("synthetic SQL stage %s unavailable: %v", item.stage, err)
		}
	}
	pgNetwork := source.endpoints["service-product-postgres"].ID
	pgRaw, err := source.evidence.readFile("guest-source-postgres.inspect", 16<<10)
	if err != nil {
		t.Fatal(err)
	}
	pgParts := strings.Split(strings.TrimSuffix(string(pgRaw), "\n"), "|")
	clear(pgRaw)
	var pgNetworks map[string]struct {
		NetworkID string `json:"NetworkID"`
		IPAddress string `json:"IPAddress"`
	}
	if len(pgParts) != 13 || json.Unmarshal([]byte(pgParts[12]), &pgNetworks) != nil {
		t.Fatal("source PG network raw invalid")
	}
	guestIP, err := phase6security.Slice6DesiredEndpointAddress("guest-product", "guest-runtime")
	if err != nil {
		t.Fatal(err)
	}
	runtimeIP, err := phase6security.Slice6DesiredEndpointAddress("network-guest-runtime", "guest-runtime")
	if err != nil {
		t.Fatal(err)
	}
	productPGIP, err := phase6security.Slice6DesiredFinalServiceEndpointAddress("service-product-postgres", "product-runtime")
	if err != nil {
		t.Fatal(err)
	}
	productGuestIP, err := phase6security.Slice6DesiredEndpointAddress("guest-product", "product-runtime")
	if err != nil {
		t.Fatal(err)
	}
	productNetworksRaw, err := source.evidence.readFile("guest-source-product-networks.inspect", 4096)
	if err != nil {
		t.Fatal(err)
	}
	productNetworks, err := slice6ParseGuestSourceProductNetworks(productNetworksRaw, run.id, productID)
	clear(productNetworksRaw)
	if err != nil {
		t.Fatal(err)
	}
	pg := slice6ProductPGFaultAction{RunID: run.id, ProductID: productID,
		PostgresID: pgID, NetworkID: pgNetwork, ProductPID: 123, PostgresPID: 321,
		ProductStartedAt: stamp(4), PostgresStartedAt: stamp(0),
		ProductOtherNetworks: slice6ProductPGNetworkDigest(productNetworks, "service-product-postgres"),
		PostgresNetworks:     slice6ProductPGNetworkDigest(pgNetworks, ""), Attempted: true}
	guest := slice6GuestRecoveryEdgeAction{RunID: run.id, ProductID: productID,
		GuestID: guestA, ProductNetworkID: strings.Repeat("6", 64),
		ProductPID: 123, GuestPID: 102, ProductStartedAt: stamp(4), GuestStartedAt: stamp(9),
		GuestIP: guestIP, RuntimeIP: runtimeIP, Attempted: true}
	actions := slice6GuestRecoveryActionLedger{PGDown: pg, PGUp: pg, GuestOff: guest, GuestOn: guest}
	slice6SyntheticActionProjections(&actions, productPGIP, source.endpoints["service-product-postgres"].IP,
		productGuestIP, strings.Repeat("9", 64))
	actions.PGDown.Disconnected, actions.PGDown.StartedUTC, actions.PGDown.FinishedUTC = true, stamp(12), stamp(13)
	actions.PGUp.StartedUTC, actions.PGUp.FinishedUTC = stamp(19), stamp(20)
	actions.GuestOff.Disconnected, actions.GuestOff.StartedUTC, actions.GuestOff.FinishedUTC = true, stamp(15), stamp(16)
	actions.GuestOn.StartedUTC, actions.GuestOn.FinishedUTC = stamp(23), stamp(24)
	processRaw := func(id, name string, pid int, started string, networks map[string]struct {
		NetworkID string `json:"NetworkID"`
		IPAddress string `json:"IPAddress"`
	}) []byte {
		t.Helper()
		encoded, err := json.Marshal(networks)
		if err != nil {
			t.Fatal(err)
		}
		return []byte(strings.Join([]string{id, "/" + name + "-" + run.id, run.id,
			"true", strconv.Itoa(pid), started, string(encoded)}, "|") + "\n")
	}
	networkRaw := func(name, id string, members map[string]map[string]string) []byte {
		t.Helper()
		memberIDs := make([]string, 0, len(members))
		for memberID := range members {
			memberIDs = append(memberIDs, memberID)
		}
		slices.Sort(memberIDs)
		var entries strings.Builder
		for _, memberID := range memberIDs {
			entries.WriteString(memberID + "=" + members[memberID]["IPv4Address"] + ",")
		}
		return []byte(strings.Join([]string{id, name, "bridge", "true", "isolated", run.id,
			entries.String()}, "|") + "\n")
	}
	productNetworksForPG := func(connected bool) map[string]struct {
		NetworkID string `json:"NetworkID"`
		IPAddress string `json:"IPAddress"`
	} {
		result := map[string]struct {
			NetworkID string `json:"NetworkID"`
			IPAddress string `json:"IPAddress"`
		}{"guest-product": productNetworks["guest-product"]}
		if connected {
			result["service-product-postgres"] = productNetworks["service-product-postgres"]
		}
		return result
	}
	pgSnapshot := func(connected bool) slice6GuestRecoveryDockerSnapshot {
		members := map[string]map[string]string{pgID: {"IPv4Address": source.endpoints["service-product-postgres"].IP + "/24"}}
		if connected {
			members[productID] = map[string]string{"IPv4Address": productPGIP + "/24"}
		}
		return slice6GuestRecoveryDockerSnapshot{
			Product: processRaw(productID, "sr-p6-product-runtime", 123, stamp(4), productNetworksForPG(connected)),
			Peer:    processRaw(pgID, "sr-p6-postgres", 321, stamp(0), pgNetworks),
			Network: networkRaw("service-product-postgres", pgNetwork, members),
			Retained: []byte(strings.Join([]string{pgID, source.imageID, source.imageRef, run.id,
				"true", "321", stamp(0)}, "|") + "\n"),
		}
	}
	guestSnapshot := func(connected bool) slice6GuestRecoveryDockerSnapshot {
		guestNetworks := map[string]struct {
			NetworkID string `json:"NetworkID"`
			IPAddress string `json:"IPAddress"`
		}{"network-guest-runtime": {NetworkID: strings.Repeat("9", 64), IPAddress: runtimeIP}}
		members := map[string]map[string]string{productID: {"IPv4Address": productGuestIP + "/24"}}
		if connected {
			guestNetworks["guest-product"] = struct {
				NetworkID string `json:"NetworkID"`
				IPAddress string `json:"IPAddress"`
			}{NetworkID: guest.ProductNetworkID, IPAddress: guestIP}
			members[guestA] = map[string]string{"IPv4Address": guestIP + "/24"}
		}
		return slice6GuestRecoveryDockerSnapshot{
			Product: processRaw(productID, "sr-p6-product-runtime", 123, stamp(4), productNetworks),
			Peer:    processRaw(guestA, "sr-p6-guest-runtime", 102, stamp(9), guestNetworks),
			Network: networkRaw("guest-product", guest.ProductNetworkID, members),
			Retained: networkRaw("network-guest-runtime", strings.Repeat("9", 64),
				map[string]map[string]string{guestA: {"IPv4Address": runtimeIP + "/24"}}),
		}
	}
	pgConnected, pgDisconnected := pgSnapshot(true), pgSnapshot(false)
	guestConnected, guestDisconnected := guestSnapshot(true), guestSnapshot(false)
	actions.PGDown.BeforeDocker, actions.PGDown.AfterDocker = pgConnected, pgDisconnected
	actions.PGUp.BeforeDocker, actions.PGUp.AfterDocker = pgDisconnected, pgConnected
	actions.GuestOff.BeforeDocker, actions.GuestOff.AfterDocker = guestConnected, guestDisconnected
	actions.GuestOn.BeforeDocker, actions.GuestOn.AfterDocker = guestDisconnected, guestConnected
	actionRawDigest, err := run.writeGuestRecoveryActionRaw(actions)
	if err != nil {
		t.Fatal(err)
	}
	actions.RawProofDigest = actionRawDigest
	trigger := slice6GuestRecoveryCloseTrigger{RunID: run.id,
		ProductID: productID, GuestID: guestA, ProductPID: 123, GuestPID: 102,
		ProductStart: stamp(4), GuestStart: stamp(9),
		ProductPrefixSHA256: slice6ReceiptSHA256(productARaw[:productPrefix]),
		GuestPrefixSHA256:   slice6ReceiptSHA256(guestARaw[:guestPrefix]),
		ProductPrefixBytes:  productPrefix, GuestPrefixBytes: guestPrefix,
		ObservedUTC: stamp(14)}
	created := slice6GuestRecoveryCreatedNetworks{
		Protocol: "sandbox-runtime.phase6-guest-created-networks.v1", RunID: run.id,
		GuestProductID: guest.ProductNetworkID, GuestRuntimeID: strings.Repeat("9", 64)}
	emptyNetworkRaw := func(name, id string) []byte {
		return []byte(strings.Join([]string{id, name, "bridge", "true", "isolated", run.id, "{}"}, "|") + "\n")
	}
	createdDigest, err := run.writeGuestRecoveryCreatedNetworks(created,
		emptyNetworkRaw("guest-product", created.GuestProductID),
		emptyNetworkRaw("network-guest-runtime", created.GuestRuntimeID))
	if err != nil {
		t.Fatal(err)
	}
	vaultID := strings.Repeat("f", 64)
	volumes := [2]string{strings.Repeat("d", 64), strings.Repeat("e", 64)}
	originCalls := 0
	originProbe := func(_ context.Context, _ int, _ []byte, command ...string) ([]byte, error, bool) {
		index := originCalls
		originCalls++
		if index == 0 && len(command) == 4 && command[0] == "inspect" && command[3] == vaultID {
			return []byte(vaultID + "|" + run.id + "\n" + volumes[0] + "|/vault/file\n" +
				volumes[1] + "|/vault/logs\n"), nil, false
		}
		if index == 1 || index == 2 {
			return []byte("{\"com.docker.volume.anonymous\":\"\"}\n"), nil, false
		}
		return nil, errors.New("unexpected synthetic Vault origin probe"), false
	}
	vaultOrigin, err := run.captureGuestRecoveryImplicitOriginWithProbe(t.Context(), vaultID, originProbe)
	if err != nil || originCalls != 3 {
		t.Fatalf("synthetic original Vault identity unavailable: %v", err)
	}
	input := slice6GuestRecoveryPrecleanupInput{Source: source, Process: processes,
		SQL: stages, Actions: actions, Trigger: trigger,
		CreatedNetworksDigest: createdDigest,
		VaultOrigin:           vaultOrigin,
		ProductConfigDigest:   productConfig, GuestConfigDigest: guestConfig,
		InitialAttemptDigest: initial, RecoveredAttemptDigest: recovered,
		ReplacementAttemptDigest: replacement, Generation: 1}
	productPrefixBytes := bytes.LastIndex(productARaw[:len(productARaw)-1], []byte{'\n'}) + 1
	if productPrefixBytes < 1 || productPrefixBytes >= len(productARaw) {
		t.Fatal("synthetic Product open prefix unavailable")
	}
	observedClose := slice6GuestRecoveryRecoveredClose{
		Protocol: "sandbox-runtime.phase6-guest-e-recovered-close.v1",
		RunID:    run.id, ProfileDigest: profileDigest,
		ProductID: processes[0].ContainerID, ProductPID: processes[0].PID,
		ProductStart: processes[0].StartedAt,
		GuestID:      processes[1].ContainerID, GuestPID: processes[1].PID,
		GuestStart:          processes[1].StartedAt,
		ProductConfigDigest: productConfig, GuestConfigDigest: guestConfig,
		ProductPrefixSHA256: slice6ReceiptSHA256(productARaw[:productPrefixBytes]),
		ProductPrefixBytes:  productPrefixBytes,
		GuestSealedSHA256:   processes[1].SHA256, GuestSealedBytes: processes[1].Bytes,
		GuestStopCallRef:     slice6GuestRecoveryStopCallRef(processes[1]),
		GuestExitRef:         slice6GuestRecoveryExitObservedRef(processes[1]),
		GuestSealRef:         slice6GuestRecoverySealRef(processes[1]),
		InitialAttemptDigest: initial, RecoveredAttemptDigest: recovered,
		Generation: 1, ObservedUTC: stamp(42),
	}
	input.RecoveredCloseDigest, err = run.writeGuestRecoveryRecoveredClose(observedClose)
	if err != nil || run.verifyGuestRecoveryRecoveredClose(input) != nil {
		t.Fatalf("synthetic recovered close observation unavailable: %v", err)
	}
	bBeforeSeal := input.Process[2]
	bBeforeSeal.SHA256 = ""
	bBeforeSeal.Bytes = 0
	if slice6GuestRecoveryStartCallRef(bBeforeSeal) != slice6GuestRecoveryStartCallRef(input.Process[2]) ||
		slice6GuestRecoveryStartObservedRef(bBeforeSeal) != slice6GuestRecoveryStartObservedRef(input.Process[2]) {
		t.Fatal("B start event predicted a future sealed PID1 SHA")
	}
	expectedEvents := slice6GuestRecoveryExpectedEvents(input)
	eventSeconds := [slice6GuestRecoveryEventCount]int{9, 10, 11, 12, 13, 14, 15, 16, 19, 20,
		21, 22, 23, 24, 31, 32, 39, 41, 42, 42, 43, 44, 45, 46, 47, 49, 50, 50, 51}
	journal := slice6GuestRecoveryEJournal{Protocol: "sandbox-runtime.phase6-guest-e-events.v1",
		RunID: run.id, Events: make([]slice6GuestRecoveryEEvent, slice6GuestRecoveryEventCount)}
	for index, expected := range expectedEvents {
		journal.Events[index] = slice6GuestRecoveryEEvent{Kind: expected.kind,
			ReferenceDigest: expected.ref, Sequence: uint64(index + 1),
			ElapsedNanos: int64(index+1) * int64(time.Second), UTC: stamp(eventSeconds[index])}
	}
	journalDigest, err := run.writeGuestRecoveryEventJournal(journal)
	if err != nil {
		t.Fatal(err)
	}
	input.EventJournalDigest = journalDigest
	for _, variant := range []string{"duplicate-sequence", "same-elapsed", "wrong-reference",
		"missing-observation", "missing-a-seal", "missing-final-null"} {
		wrongJournal := journal
		wrongJournal.Events = append([]slice6GuestRecoveryEEvent(nil), journal.Events...)
		switch variant {
		case "duplicate-sequence":
			wrongJournal.Events[7].Sequence = wrongJournal.Events[6].Sequence
		case "same-elapsed":
			wrongJournal.Events[7].ElapsedNanos = wrongJournal.Events[6].ElapsedNanos
		case "wrong-reference":
			wrongJournal.Events[7].ReferenceDigest = "sha256:" + strings.Repeat("0", 64)
		case "missing-observation":
			wrongJournal.Events = append(wrongJournal.Events[:8], wrongJournal.Events[9:]...)
		case "missing-a-seal":
			wrongJournal.Events = append(wrongJournal.Events[:21], wrongJournal.Events[22:]...)
		case "missing-final-null":
			wrongJournal.Events = append(wrongJournal.Events[:23], wrongJournal.Events[24:]...)
		}
		if slice6CheckGuestRecoveryEJournal(wrongJournal, input, run.id) == nil {
			t.Fatalf("synthetic E journal accepted %s", variant)
		}
	}
	wallRollback := journal
	wallRollback.Events = append([]slice6GuestRecoveryEEvent(nil), journal.Events...)
	wallRollback.Events[7].UTC = stamp(1)
	if err := slice6CheckGuestRecoveryEJournal(wallRollback, input, run.id); err != nil {
		t.Fatalf("valid monotonic E journal relied on wall clock ordering: %v", err)
	}
	beforeB := input
	beforeB.Process[2] = slice6GuestRecoveryRawBinding{}
	beforeB.Process[3] = slice6GuestRecoveryRawBinding{}
	beforeBDigest, beforeBErr := run.checkGuestRecoveryBeforeBCore(beforeB,
		journal.Events[:slice6GuestRecoveryBeforeBEventCount])
	if beforeBErr != nil ||
		!guestRevokeFixtureDigestGate(beforeBDigest) {
		t.Fatalf("synthetic sealed A/final NULL pre-B admission unavailable: %v", beforeBErr)
	}
	if _, err := run.checkGuestRecoveryBeforeBCore(input,
		journal.Events[:slice6GuestRecoveryBeforeBEventCount]); err == nil {
		t.Fatal("pre-B admission accepted already-started B bindings")
	}
	wrongBeforeB := beforeB
	wrongBeforeB.SQL[3].NonceNull = false
	if _, err := run.checkGuestRecoveryBeforeBCore(wrongBeforeB,
		journal.Events[:slice6GuestRecoveryBeforeBEventCount]); err == nil {
		t.Fatal("pre-B admission accepted unproved final old-nonce NULL")
	}
	if _, err := run.checkGuestRecoveryBeforeBCore(beforeB,
		journal.Events[:slice6GuestRecoveryBeforeBEventCount-1]); err == nil {
		t.Fatal("pre-B admission accepted a missing final SQL observation")
	}
	if err := run.writeV2BoundedPrivateFile(slice6GuestRecoveryBeforeBFile,
		[]byte(beforeBDigest+"\n"), 96, false); err != nil {
		t.Fatal(err)
	}
	beforeBRecorder, err := newSlice6GuestRecoveryERecorder(run.id)
	if err != nil {
		t.Fatal(err)
	}
	beforeBRecorder.events = append(beforeBRecorder.events,
		journal.Events[:slice6GuestRecoveryBeforeBEventCount]...)
	if err := run.checkGuestRecoveryReplacementStart("product-b", beforeBDigest, beforeBRecorder); err != nil {
		t.Fatalf("admitted first replacement start rejected: %v", err)
	}
	if run.checkGuestRecoveryReplacementStart("guest-b", beforeBDigest, beforeBRecorder) == nil ||
		run.checkGuestRecoveryReplacementStart("product-b", "sha256:"+strings.Repeat("0", 64), beforeBRecorder) == nil {
		t.Fatal("B start admitted missing Product-B observation or wrong admission digest")
	}
	beforeBRecorder.events = append(beforeBRecorder.events, journal.Events[25:27]...)
	if err := run.checkGuestRecoveryReplacementStart("guest-b", beforeBDigest, beforeBRecorder); err != nil {
		t.Fatalf("admitted second replacement start rejected: %v", err)
	}
	beforeBRecorder.events[26].Kind = "guest_b_start_observed"
	if run.checkGuestRecoveryReplacementStart("guest-b", beforeBDigest, beforeBRecorder) == nil {
		t.Fatal("Guest-B start admitted missing Product-B running observation")
	}
	input.BeforeBAdmissionDigest = beforeBDigest
	if digest, err := run.verifyGuestRecoveryPrecleanupCore(input); err != nil ||
		!guestRevokeFixtureDigestGate(digest) {
		t.Fatalf("synthetic source→SQL→action→four PID1 precleanup merger unavailable: %v", err)
	}
	precleanupDigest, err := run.verifyGuestRecoveryPrecleanupCore(input)
	if err != nil {
		t.Fatal(err)
	}
	zeroCalls := 0
	zeroProbe := func(_ context.Context, _ int, _ []byte, command ...string) ([]byte, error, bool) {
		index := zeroCalls
		zeroCalls++
		if index < 3 {
			return nil, nil, false
		}
		return []byte("Error: no such volume: " + command[2] + "\n"), errors.New("not found"), false
	}
	dockerZero, err := run.proveGuestRecoveryDockerZeroWithProbe(t.Context(), precleanupDigest,
		vaultOrigin, zeroProbe)
	if err != nil || zeroCalls != 5 {
		t.Fatalf("synthetic original-volume Docker zero unavailable: %v", err)
	}
	originalIDs := [3]string{created.GuestProductID, created.GuestRuntimeID, vaultID}
	exactCalls := 0
	exactProbe := func(_ context.Context, _ int, _ []byte, command ...string) ([]byte, error, bool) {
		index := exactCalls
		exactCalls++
		if index < 2 && len(command) == 3 && command[0] == "network" && command[2] == originalIDs[index] {
			return []byte("[]\nError response from daemon: network " + command[2] + " not found\n"),
				errors.New("not found"), false
		}
		if index == 2 && len(command) == 2 && command[0] == "inspect" && command[1] == vaultID {
			return []byte("[]\nerror: no such object: " + vaultID + "\n"), errors.New("not found"), false
		}
		return nil, errors.New("wrong exact-origin target"), false
	}
	wrongExactProbe := func(_ context.Context, _ int, _ []byte, _ ...string) ([]byte, error, bool) {
		return []byte("[]\nError response from daemon: network " + strings.Repeat("0", 64) + " not found\n"),
			errors.New("not found"), false
	}
	if _, err := run.proveGuestRecoveryExactOriginZero(t.Context(), input, dockerZero,
		wrongExactProbe); err == nil {
		t.Fatal("exact original zero accepted a different network ID")
	}
	exactZero, err := run.proveGuestRecoveryExactOriginZero(t.Context(), input, dockerZero, exactProbe)
	if err != nil || exactCalls != 3 ||
		run.verifyGuestRecoveryExactOriginZeroRaw(input, dockerZero, exactZero) != nil {
		t.Fatalf("synthetic exact original network/Vault zero unavailable: %v", err)
	}
	exactRawPath := filepath.Join(run.root.path, run.id, slice6GuestRecoveryExactOriginZeroRawNames[0])
	file, err := os.OpenFile(exactRawPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("!"), 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if run.verifyGuestRecoveryExactOriginZeroRaw(input, dockerZero, exactZero) == nil {
		t.Fatal("exact original zero accepted same-inode absence raw tamper")
	}
	file, err = os.OpenFile(exactRawPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("["), 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run.verifyGuestRecoveryExactOriginZeroRaw(input, dockerZero, exactZero); err != nil {
		t.Fatalf("restored exact original zero raw unavailable: %v", err)
	}
	if _, err := run.verifyGuestRecoveryPrecleanup(t.Context(), input); err == nil {
		t.Fatal("synthetic subset Profile bypassed formal frozen-source admission")
	}
	wrong := input
	wrong.Actions.PGUp.StartedUTC = stamp(15)
	if _, err := run.verifyGuestRecoveryPrecleanupCore(wrong); err == nil {
		t.Fatal("merged E evidence accepted PG restore before Guest isolation")
	}
	wrong = input
	wrong.Process[2].ContainerID = wrong.Process[0].ContainerID
	if _, err := run.verifyGuestRecoveryPrecleanupCore(wrong); err == nil {
		t.Fatal("merged E evidence accepted A/B PID1 replay")
	}
	wrong = input
	wrong.GuestConfigDigest = productConfig
	if _, err := run.verifyGuestRecoveryPrecleanupCore(wrong); err == nil {
		t.Fatal("merged E evidence accepted role startup config splice")
	}
	wrong = input
	wrong.SQL[2].SourceProofDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := run.verifyGuestRecoveryPrecleanupCore(wrong); err == nil {
		t.Fatal("merged E evidence accepted SQL source splice")
	}
	wrong = input
	wrong.Actions.PGDown.NetworkID = strings.Repeat("9", 64)
	wrong.Actions.PGUp.NetworkID = wrong.Actions.PGDown.NetworkID
	if _, err := run.verifyGuestRecoveryPrecleanupCore(wrong); err == nil {
		t.Fatal("merged E evidence accepted self-consistent wrong PG network")
	}
	wrong = input
	wrong.Actions.PGDown.PostgresPID++
	wrong.Actions.PGUp.PostgresPID = wrong.Actions.PGDown.PostgresPID
	if _, err := run.verifyGuestRecoveryPrecleanupCore(wrong); err == nil {
		t.Fatal("merged E evidence accepted self-consistent wrong PostgreSQL PID")
	}
	wrong = input
	wrong.Actions.GuestOff.GuestIP = "10.77.0.99"
	wrong.Actions.GuestOn.GuestIP = wrong.Actions.GuestOff.GuestIP
	if _, err := run.verifyGuestRecoveryPrecleanupCore(wrong); err == nil {
		t.Fatal("merged E evidence accepted self-consistent wrong Guest IP")
	}
	wrong = input
	wrong.SQL[0].ReadStartedUTC = stamp(6)
	if _, err := run.verifyGuestRecoveryPrecleanupCore(wrong); err == nil {
		t.Fatal("merged E evidence accepted action before source completion")
	}
	wrong = input
	wrong.SQL[3].ReadStartedUTC = stamp(72)
	wrong.SQL[3].SettingsFinishedUTC = stamp(73)
	if _, err := run.verifyGuestRecoveryPrecleanupCore(wrong); err == nil {
		t.Fatal("merged E evidence accepted only a B-stop old-nonce NULL snapshot")
	}
	for _, variant := range []string{"paired-PG-network", "paired-PG-PID", "paired-Guest-network", "paired-Guest-IP", "paired-retained-edge"} {
		wrongActions := input.Actions
		switch variant {
		case "paired-PG-network":
			wrongActions.PGDown.NetworkID, wrongActions.PGUp.NetworkID = strings.Repeat("9", 64), strings.Repeat("9", 64)
		case "paired-PG-PID":
			wrongActions.PGDown.PostgresPID++
			wrongActions.PGUp.PostgresPID++
		case "paired-Guest-network":
			wrongActions.GuestOff.ProductNetworkID, wrongActions.GuestOn.ProductNetworkID = strings.Repeat("8", 64), strings.Repeat("8", 64)
		case "paired-Guest-IP":
			wrongActions.GuestOff.GuestIP, wrongActions.GuestOn.GuestIP = "10.77.0.99", "10.77.0.99"
		case "paired-retained-edge":
			wrongActions.PGDown.ProductOtherNetworks, wrongActions.PGUp.ProductOtherNetworks =
				slice6ReceiptSHA256([]byte("wrong-retained-edge")), slice6ReceiptSHA256([]byte("wrong-retained-edge"))
		}
		slice6SyntheticActionProjections(&wrongActions, productPGIP, source.endpoints["service-product-postgres"].IP,
			productGuestIP, strings.Repeat("9", 64))
		if err := slice6VerifyGuestRecoveryActionSourceIdentity(source, wrongActions, processes, stages); err == nil {
			t.Fatalf("independent source-action replay accepted %s with internally rebuilt projections", variant)
		}
	}
	wrong = input
	wrong.EventJournalDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := run.verifyGuestRecoveryPrecleanupCore(wrong); err == nil {
		t.Fatal("merged E evidence accepted spliced monotonic E journal")
	}
	wrong = input
	wrong.BeforeBAdmissionDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := run.verifyGuestRecoveryPrecleanupCore(wrong); err == nil {
		t.Fatal("merged E evidence accepted spliced pre-B admission")
	}
	wrong = input
	wrong.CreatedNetworksDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := run.verifyGuestRecoveryPrecleanupCore(wrong); err == nil {
		t.Fatal("merged E evidence accepted spliced original creation identity")
	}
	wrong = input
	wrong.Actions.GuestOff.ProductNetworkID = strings.Repeat("8", 64)
	wrong.Actions.GuestOn.ProductNetworkID = wrong.Actions.GuestOff.ProductNetworkID
	if run.verifyGuestRecoveryCreatedNetworks(wrong) == nil {
		t.Fatal("original creation receipt accepted a same-labeled replacement Guest edge")
	}
	createdRawPath := filepath.Join(run.root.path, run.id, slice6GuestRecoveryCreatedProductRaw)
	file, err = os.OpenFile(createdRawPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("!"), 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if run.verifyGuestRecoveryCreatedNetworks(input) == nil {
		t.Fatal("original creation receipt accepted same-inode raw tamper")
	}
	file, err = os.OpenFile(createdRawPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("6"), 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run.verifyGuestRecoveryCreatedNetworks(input); err != nil {
		t.Fatalf("restored original creation raw unavailable: %v", err)
	}
	originalDockerPath := filepath.Join(run.root.path, run.id,
		slice6GuestRecoveryActionDockerRawNames(0)[2])
	file, err = os.OpenFile(originalDockerPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("!"), 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := run.verifyGuestRecoveryPrecleanupCore(input); err == nil {
		t.Fatal("merged E evidence accepted tampered same-inode original Docker network raw")
	}
	file, err = os.OpenFile(originalDockerPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(input.Actions.PGDown.BeforeDocker.Network[:1], 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := run.verifyGuestRecoveryPrecleanupCore(input); err != nil {
		t.Fatalf("untampered original Docker raw did not recover: %v", err)
	}
	actionRawPath := filepath.Join(run.root.path, run.id, slice6GuestRecoveryActionRawNames[0])
	file, err = os.OpenFile(actionRawPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("!"), 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := run.verifyGuestRecoveryPrecleanupCore(input); err == nil {
		t.Fatal("merged E evidence accepted tampered same-inode action raw")
	}
}
