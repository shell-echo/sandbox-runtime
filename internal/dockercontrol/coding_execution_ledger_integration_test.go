//go:build integration && linux

package dockercontrol

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// Run inside the explicitly provisioned high-UID Linux local-volume fixture.
// This tests real filesystem/owner behavior, with synthetic completion and
// effect callbacks. It is not a Coding workload or physical completion gate.
func TestCodingExecutionLedgerLinuxVolumeComponent(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_CONTROL_LEDGER_VOLUME_TEST") != "1" {
		t.Skip("explicit isolated Linux volume fixture required")
	}
	if os.Geteuid() != 57000 || os.Getegid() != 58000 || os.Getenv("TMPDIR") != "/receipt-tests" {
		t.Fatal("fixture owner or volume root drift")
	}
	var root, data unix.Statfs_t
	if unix.Statfs("/", &root) != nil || root.Flags&unix.ST_RDONLY == 0 || unix.Statfs("/receipt-tests", &data) != nil || data.Flags&unix.ST_RDONLY != 0 {
		t.Fatal("expected read-only root and separate writable receipt volume")
	}
	for name, test := range map[string]func(*testing.T){
		"durable-and-restart":     TestCodingExecutionLedgerDurableUnknownAndRestart,
		"late-arrival":            TestCodingExecutionLedgerClosureAndRetirementWinBeforeLateArrival,
		"retirement-and-owner":    TestCodingExecutionLedgerRetirementDoesNotWaitForCommandAndCloseRetainsOwner,
		"completion-cas":          TestCodingExecutionLedgerCompletionRequiresCurrentNewObservation,
		"publication-uncertainty": TestCodingExecutionLedgerUncertainWriteNeverDispatchesOrReplays,
		"binding-and-state":       TestCodingExecutionLedgerRejectsMissingStateBindingDriftAndNoncanonicalState,
		"capacity":                TestCodingExecutionLedgerCapacityRetainsClosureHistory,
		"closure-fence":           TestCodingExecutionLedgerClosedClaimAdvancesFence,
		"four-volume-observer":    TestExecutionObserverCompleteFourVolumeBoundedSDKChain,
		"observer-drift":          TestExecutionObserverRejectsDriftAndLegacyTopology,
		"observer-resources":      TestExecutionObserverSecondaryResourcesFailClosed,
		"observer-stream":         TestExecutionObserverSocketAndCancellationCoverResponseBody,
		"observer-retained-proof": TestExecutionObserverRetainedProofRecheckedNotJustResealed,
	} {
		t.Run(name, test)
	}
}
