//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
	"golang.org/x/sys/unix"
)

const slice6EConvergenceFile = "guest-e-helper-convergence.json"
const slice6EConvergenceProtocol = "sandbox-runtime.phase6-guest-e-helper-convergence.v1"
const slice6EConvergenceLimit = 12 << 10

type slice6EConvergenceStage struct {
	Kind          string   `json:"kind"`
	Slot          string   `json:"slot"`
	Sequence      int      `json:"sequence"`
	ElapsedNanos  int64    `json:"elapsed_nanos"`
	Result        string   `json:"result"`
	ContainerIDs  []string `json:"container_ids"`
	OutcomeDigest string   `json:"outcome_digest"`
}

type slice6EConvergenceReceipt struct {
	Protocol, RunID, ProfileDigest, RRevision, TerminalBinaryDigest string
	PrecleanupDigest, TerminalBindingDigest, DockerZeroDigest       string
	ExactOriginZeroDigest, PrivateSiblingZeroDigest                 string
	ControllerDrainClass                                            string
	Stages                                                          []slice6EConvergenceStage
}

type slice6EConvergenceCollector struct {
	runID, profileDigest, rRevision, terminalBinaryDigest string
	started                                               time.Time
	stages                                                []slice6EConvergenceStage
	seen                                                  map[string]bool
	ids                                                   map[string]bool
}

var slice6EConvergenceSlots = map[string]string{
	"tls/guest-tls-agent":                      "physical_converged",
	"tls/guest-agent-tls-agent":                "physical_converged",
	"tls/product-postgres-tls-agent":           "physical_converged",
	"tls/product-runtime-agent-tls-agent":      "physical_converged",
	"tls/product-tls-agent":                    "physical_converged",
	"tls/product-migration-postgres-tls-agent": "physical_converged",
	"tls/product-migration-agent-tls-agent":    "physical_converged",
	"material/guest-agent":                     "stopped",
	"material/product-runtime-agent":           "stopped",
	"material/product-migration-agent":         "natural_exit",
	"controller/credential":                    "physical_converged",
	"controller/certificate":                   "certificate_drain",
	"controller/breakglass":                    "physical_converged",
	"capacity/monitor":                         "clean_join",
}

func slice6NewEConvergenceCollector(runID, profileDigest, rRevision, binaryDigest string) (*slice6EConvergenceCollector, error) {
	if len(runID) != 32 || !lowerHexSlice6(runID) || !guestRevokeFixtureDigestGate(profileDigest) ||
		len(rRevision) != 40 || !lowerHexSlice6(rRevision) ||
		!guestRevokeFixtureDigestGate(binaryDigest) {
		return nil, phase6guestreceipt.ErrUnavailable
	}
	return &slice6EConvergenceCollector{runID: runID, profileDigest: profileDigest,
		rRevision: rRevision, terminalBinaryDigest: binaryDigest,
		started: time.Now(), stages: make([]slice6EConvergenceStage, 0, 14),
		seen: make(map[string]bool, 14), ids: make(map[string]bool, 16)}, nil
}

func slice6EOutcomeDigest(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	defer clear(raw)
	sum := sha256.Sum256(append([]byte("sandbox-runtime/phase6-guest-e-helper-outcome/v1\x00"), raw...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (collector *slice6EConvergenceCollector) record(kind, slot, result string, ids []string, outcome any) error {
	if collector == nil || collector.started.IsZero() || collector.seen == nil || collector.ids == nil ||
		len(collector.stages) >= len(slice6EConvergenceSlots) {
		return phase6guestreceipt.ErrUnavailable
	}
	key := kind + "/" + slot
	want, known := slice6EConvergenceSlots[key]
	wantIDs := 1
	if key == "controller/breakglass" {
		wantIDs = 3
	}
	if !known || collector.seen[key] || (want != result && !(key == "controller/certificate" &&
		(result == "clean_exit" || result == "sticky_credential_revoke"))) ||
		len(ids) != wantIDs {
		return phase6guestreceipt.ErrUnavailable
	}
	for _, id := range ids {
		if len(id) != 64 || !lowerHexSlice6(id) || collector.ids[id] {
			return phase6guestreceipt.ErrUnavailable
		}
	}
	digest := slice6EOutcomeDigest(outcome)
	if !guestRevokeFixtureDigestGate(digest) {
		return phase6guestreceipt.ErrUnavailable
	}
	elapsed := time.Since(collector.started).Nanoseconds()
	if elapsed < 0 || (len(collector.stages) > 0 &&
		elapsed < collector.stages[len(collector.stages)-1].ElapsedNanos) {
		return phase6guestreceipt.ErrUnavailable
	}
	collector.stages = append(collector.stages, slice6EConvergenceStage{Kind: kind, Slot: slot,
		Sequence: len(collector.stages) + 1, ElapsedNanos: elapsed, Result: result,
		ContainerIDs: append([]string(nil), ids...), OutcomeDigest: digest})
	collector.seen[key] = true
	for _, id := range ids {
		collector.ids[id] = true
	}
	return nil
}

func (collector *slice6EConvergenceCollector) tls(slot string, outcome *slice6OrdinaryTLSOutcome) error {
	if outcome == nil || !outcome.validForRun(collector.runID, collector.profileDigest, slot) {
		return phase6guestreceipt.ErrUnavailable
	}
	return collector.record("tls", slot, "physical_converged", []string{outcome.ContainerID}, outcome)
}

func (collector *slice6EConvergenceCollector) material(slot string, outcome *slice6EMaterialOutcome) error {
	if outcome == nil || !outcome.validForRun(collector.runID, collector.profileDigest, slot) {
		return phase6guestreceipt.ErrUnavailable
	}
	return collector.record("material", slot, outcome.ExitClass, []string{outcome.ContainerID}, outcome)
}

func (collector *slice6EConvergenceCollector) credential(outcome *slice6CredentialControllerOutcome) error {
	if outcome == nil || !outcome.validForRun(collector.runID, collector.profileDigest) {
		return phase6guestreceipt.ErrUnavailable
	}
	return collector.record("controller", "credential", "physical_converged", []string{outcome.ContainerID}, outcome)
}

func (collector *slice6EConvergenceCollector) certificate(outcome *slice6CertificateControllerOutcome) error {
	if outcome == nil || !outcome.validForRun(collector.runID, collector.profileDigest) {
		return phase6guestreceipt.ErrUnavailable
	}
	return collector.record("controller", "certificate", string(outcome.DrainClass), []string{outcome.ContainerID}, outcome)
}

func (collector *slice6EConvergenceCollector) breakglass(outcome *slice6BreakGlassRunOutcome) error {
	if outcome == nil || !outcome.validForRun(collector.runID, collector.profileDigest) {
		return phase6guestreceipt.ErrUnavailable
	}
	return collector.record("controller", "breakglass", "physical_converged", outcome.InstanceIDs, outcome)
}

func (collector *slice6EConvergenceCollector) capacity(monitorID string, joined bool) error {
	if !joined {
		return phase6guestreceipt.ErrUnavailable
	}
	return collector.record("capacity", "monitor", "clean_join", []string{monitorID},
		struct{ RunID, ProfileDigest, MonitorID, Result string }{collector.runID,
			collector.profileDigest, monitorID, "clean_join"})
}

func slice6VerifyEConvergenceReceipt(raw []byte, expected slice6EConvergenceReceipt) error {
	if len(raw) < 2 || len(raw) > slice6EConvergenceLimit ||
		!guestRevokeFixtureDigestGate(expected.ProfileDigest) ||
		!guestRevokeFixtureDigestGate(expected.TerminalBinaryDigest) ||
		!guestRevokeFixtureDigestGate(expected.PrecleanupDigest) ||
		!guestRevokeFixtureDigestGate(expected.TerminalBindingDigest) ||
		!guestRevokeFixtureDigestGate(expected.DockerZeroDigest) ||
		!guestRevokeFixtureDigestGate(expected.ExactOriginZeroDigest) ||
		!guestRevokeFixtureDigestGate(expected.PrivateSiblingZeroDigest) {
		return phase6guestreceipt.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var actual slice6EConvergenceReceipt
	if decoder.Decode(&actual) != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return phase6guestreceipt.ErrUnavailable
	}
	canonical, err := json.Marshal(actual)
	if err != nil || !bytes.Equal(canonical, raw) || actual.Protocol != slice6EConvergenceProtocol ||
		actual.RunID != expected.RunID || actual.ProfileDigest != expected.ProfileDigest ||
		actual.RRevision != expected.RRevision ||
		actual.TerminalBinaryDigest != expected.TerminalBinaryDigest ||
		actual.PrecleanupDigest != expected.PrecleanupDigest ||
		actual.TerminalBindingDigest != expected.TerminalBindingDigest ||
		actual.DockerZeroDigest != expected.DockerZeroDigest ||
		actual.ExactOriginZeroDigest != expected.ExactOriginZeroDigest ||
		actual.PrivateSiblingZeroDigest != expected.PrivateSiblingZeroDigest ||
		actual.ControllerDrainClass != expected.ControllerDrainClass ||
		len(actual.Stages) != 14 {
		return phase6guestreceipt.ErrUnavailable
	}
	if actual.ControllerDrainClass != "clean_exit" && actual.ControllerDrainClass != "sticky_credential_revoke" {
		return phase6guestreceipt.ErrUnavailable
	}
	seen, ids := make(map[string]int, 14), make(map[string]bool, 16)
	previous := int64(-1)
	for index, stage := range actual.Stages {
		key := stage.Kind + "/" + stage.Slot
		want, found := slice6EConvergenceSlots[key]
		wantIDs := 1
		if key == "controller/breakglass" {
			wantIDs = 3
		}
		if !found || seen[key] != 0 || stage.Sequence != index+1 ||
			stage.ElapsedNanos < 0 || stage.ElapsedNanos < previous ||
			!guestRevokeFixtureDigestGate(stage.OutcomeDigest) ||
			(want != stage.Result && !(key == "controller/certificate" &&
				(stage.Result == "clean_exit" || stage.Result == "sticky_credential_revoke"))) ||
			len(stage.ContainerIDs) != wantIDs {
			return phase6guestreceipt.ErrUnavailable
		}
		for _, id := range stage.ContainerIDs {
			if len(id) != 64 || !lowerHexSlice6(id) || ids[id] {
				return phase6guestreceipt.ErrUnavailable
			}
			ids[id] = true
		}
		if key == "controller/certificate" && stage.Result != actual.ControllerDrainClass {
			return phase6guestreceipt.ErrUnavailable
		}
		seen[key], previous = index+1, stage.ElapsedNanos
	}
	if len(seen) != len(slice6EConvergenceSlots) ||
		!slice6EConvergenceBefore(seen, "tls/guest-tls-agent", "material/guest-agent") ||
		!slice6EConvergenceBefore(seen, "material/guest-agent", "tls/guest-agent-tls-agent") ||
		!slice6EConvergenceBefore(seen, "tls/product-postgres-tls-agent", "material/product-runtime-agent") ||
		!slice6EConvergenceBefore(seen, "material/product-runtime-agent", "tls/product-runtime-agent-tls-agent") ||
		!slice6EConvergenceBefore(seen, "tls/product-runtime-agent-tls-agent", "tls/product-tls-agent") ||
		!slice6EConvergenceBefore(seen, "tls/product-tls-agent", "controller/breakglass") ||
		!slice6EConvergenceBefore(seen, "material/product-migration-agent", "tls/product-migration-postgres-tls-agent") ||
		!slice6EConvergenceBefore(seen, "tls/product-migration-postgres-tls-agent", "tls/product-migration-agent-tls-agent") ||
		!slice6EConvergenceBefore(seen, "tls/product-migration-agent-tls-agent", "controller/breakglass") ||
		!slice6EConvergenceBefore(seen, "controller/breakglass", "controller/certificate") ||
		!slice6EConvergenceBefore(seen, "controller/certificate", "controller/credential") ||
		!slice6EConvergenceBefore(seen, "controller/credential", "capacity/monitor") {
		return phase6guestreceipt.ErrUnavailable
	}
	return nil
}

func slice6EConvergenceBefore(seen map[string]int, first, second string) bool {
	return seen[first] > 0 && seen[second] > seen[first]
}

func (collector *slice6EConvergenceCollector) receipt(precleanup, terminal, dockerZero,
	exactZero, privateZero, drainClass string) ([]byte, slice6EConvergenceReceipt, error) {
	if collector == nil || len(collector.stages) != 14 {
		return nil, slice6EConvergenceReceipt{}, phase6guestreceipt.ErrUnavailable
	}
	receipt := slice6EConvergenceReceipt{Protocol: slice6EConvergenceProtocol,
		RunID: collector.runID, ProfileDigest: collector.profileDigest,
		RRevision: collector.rRevision, TerminalBinaryDigest: collector.terminalBinaryDigest,
		PrecleanupDigest: precleanup, TerminalBindingDigest: terminal,
		DockerZeroDigest: dockerZero, ExactOriginZeroDigest: exactZero,
		PrivateSiblingZeroDigest: privateZero, ControllerDrainClass: drainClass,
		Stages: append([]slice6EConvergenceStage(nil), collector.stages...)}
	raw, err := json.Marshal(receipt)
	if err != nil || slice6VerifyEConvergenceReceipt(raw, receipt) != nil {
		clear(raw)
		return nil, slice6EConvergenceReceipt{}, phase6guestreceipt.ErrUnavailable
	}
	return raw, receipt, nil
}

func (run *slice6ReceiptEvidenceRun) captureEConvergence(collector *slice6EConvergenceCollector,
	precleanup, terminal, privateZero string, dockerZero slice6GuestRecoveryDockerZeroReceipt,
	exactZero slice6GuestRecoveryExactOriginZeroReceipt, drainClass string) (slice6EConvergenceReceipt, string, error) {
	if run == nil || run.check() != nil || collector == nil || run.id != collector.runID {
		return slice6EConvergenceReceipt{}, "", phase6guestreceipt.ErrUnavailable
	}
	dockerRaw, err := json.Marshal(dockerZero)
	if err != nil {
		return slice6EConvergenceReceipt{}, "", phase6guestreceipt.ErrUnavailable
	}
	defer clear(dockerRaw)
	exactRaw, err := json.Marshal(exactZero)
	if err != nil {
		return slice6EConvergenceReceipt{}, "", phase6guestreceipt.ErrUnavailable
	}
	defer clear(exactRaw)
	raw, expected, err := collector.receipt(precleanup, terminal,
		slice6ReceiptSHA256(dockerRaw), slice6ReceiptSHA256(exactRaw), privateZero, drainClass)
	if err != nil || run.writeV2BoundedPrivateFile(slice6EConvergenceFile, raw,
		slice6EConvergenceLimit, false) != nil {
		clear(raw)
		return slice6EConvergenceReceipt{}, "", phase6guestreceipt.ErrUnavailable
	}
	defer clear(raw)
	retained, err := run.readFile(slice6EConvergenceFile, slice6EConvergenceLimit)
	defer clear(retained)
	if err != nil || !bytes.Equal(retained, raw) ||
		slice6VerifyEConvergenceReceipt(retained, expected) != nil {
		return slice6EConvergenceReceipt{}, "", phase6guestreceipt.ErrUnavailable
	}
	return expected, slice6ReceiptSHA256(retained), nil
}

// Reopen the private root and the exact run without the writer's inode map.
// This proves retained bytes and digest integrity, not historical OS events.
func slice6VerifyEConvergenceFile(rootPath, runID, expectedDigest string,
	expected slice6EConvergenceReceipt) (result error) {
	if !guestRevokeFixtureDigestGate(expectedDigest) || expected.RunID != runID {
		return phase6guestreceipt.ErrUnavailable
	}
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		return err
	}
	defer func() {
		if root.close() != nil {
			result = phase6guestreceipt.ErrUnavailable
		}
	}()
	run, err := root.openRun(runID)
	if err != nil {
		return err
	}
	defer func() {
		if unix.Close(run.fd) != nil {
			result = phase6guestreceipt.ErrUnavailable
		}
	}()
	var stat unix.Stat_t
	if unix.Fstatat(run.fd, slice6EConvergenceFile, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 ||
		stat.Uid != uint32(os.Getuid()) || stat.Ino == 0 {
		return phase6guestreceipt.ErrUnavailable
	}
	run.files[slice6EConvergenceFile] = stat
	raw, err := run.readFile(slice6EConvergenceFile, slice6EConvergenceLimit)
	defer clear(raw)
	if err != nil || slice6ReceiptSHA256(raw) != expectedDigest ||
		slice6VerifyEConvergenceReceipt(raw, expected) != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	return nil
}
