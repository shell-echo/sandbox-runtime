//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func slice6GuestEFinalBindingFixture() slice6GuestEFinalBinding {
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	return slice6GuestEFinalBinding{Protocol: slice6GuestEFinalBindingProtocol,
		Disposition: "guest_e_component_verified", RunID: strings.Repeat("a", 32),
		ProfileDigest: digest("1"), Sources: slice6GuestESourceIdentity{
			ERevision: strings.Repeat("b", 40), ETree: digest("2"),
			RRevision: strings.Repeat("c", 40), RTree: digest("3"),
			FRevision: strings.Repeat("d", 40), FTree: digest("4")},
		PrecleanupDigest: digest("5"), TerminalZeroDigest: digest("6"),
		TerminalV3BindingDigest: digest("7"), ConvergenceDigest: digest("8"),
		FileInventoryDigest: digest("9"), TerminalBinaryDigest: digest("a"),
		TerminalOperatorID:   strings.Repeat("e", 64),
		ControllerDrainClass: "sticky_credential_revoke", ControllerDrainOpen: true,
		RecordedUTC: time.Now().UTC().Format(time.RFC3339Nano)}
}

func TestSlice6GuestEFinalBindingClosedSourceAndNonCleanStateNoIssuer(t *testing.T) {
	expected := slice6GuestEFinalBindingFixture()
	raw, err := json.Marshal(expected)
	if err != nil || slice6VerifyGuestEFinalBindingDocument(raw, expected) != nil {
		t.Fatalf("closed final binding rejected: %v", err)
	}
	mutate := func(change func(*slice6GuestEFinalBinding)) []byte {
		copy := expected
		change(&copy)
		encoded, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	for name, document := range map[string][]byte{
		"wrong E revision": mutate(func(value *slice6GuestEFinalBinding) {
			value.Sources.ERevision = strings.Repeat("f", 40)
		}),
		"R substituted for E": mutate(func(value *slice6GuestEFinalBinding) {
			value.Sources.ERevision = value.Sources.RRevision
		}),
		"wrong F tree": mutate(func(value *slice6GuestEFinalBinding) {
			value.Sources.FTree = "sha256:" + strings.Repeat("f", 64)
		}),
		"wrong convergence": mutate(func(value *slice6GuestEFinalBinding) {
			value.ConvergenceDigest = "sha256:" + strings.Repeat("f", 64)
		}),
		"wrong inventory": mutate(func(value *slice6GuestEFinalBinding) {
			value.FileInventoryDigest = "sha256:" + strings.Repeat("f", 64)
		}),
		"sticky washed green": mutate(func(value *slice6GuestEFinalBinding) {
			value.ControllerDrainOpen = false
		}),
		"release disposition": mutate(func(value *slice6GuestEFinalBinding) {
			value.Disposition = "slice6_accepted"
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if slice6VerifyGuestEFinalBindingDocument(document, expected) == nil {
				t.Fatal("mutated final E binding accepted")
			}
		})
	}
	unknown := append([]byte(`{"extra":"forbidden",`), raw[1:]...)
	if slice6VerifyGuestEFinalBindingDocument(unknown, expected) == nil {
		t.Fatal("unknown final E field accepted")
	}
	duplicate := bytes.Replace(raw, []byte(`"RunID":`), []byte(`"RunID":"x","RunID":`), 1)
	if slice6VerifyGuestEFinalBindingDocument(duplicate, expected) == nil {
		t.Fatal("duplicate final E field accepted")
	}
}

func TestSlice6GuestEFinalFileInventoryRejectsPendingOrIncompleteNoIssuer(t *testing.T) {
	rootPath := slice6ReceiptTestRoot(t)
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	run, err := root.newRun(strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !run.closed {
			_ = run.closeV2Incomplete()
		}
	})
	limits := slice6GuestRecoveryEFileLimits()
	for _, name := range slice6GuestRecoveryExpectedNames(limits, false) {
		if err := run.writeV2BoundedPrivateFile(name, []byte("component fixture\n"), limits[name], false); err != nil {
			t.Fatal(err)
		}
	}
	inventory, err := run.captureGuestRecoveryEFileInventory()
	if err != nil {
		t.Fatal(err)
	}
	if err := run.writeV2BoundedPrivateFile(slice6GuestEFinalBindingPendingFile,
		[]byte("pending fixture\n"), 128, false); err != nil {
		t.Fatal(err)
	}
	if slice6VerifyGuestRecoveryEFinalFileInventory(rootPath, run.id, inventory) == nil {
		t.Fatal("pending publisher file accepted as final binding")
	}
	if err := run.unlinkFile(run.fd, slice6GuestEFinalBindingPendingFile, 0); err != nil {
		t.Fatal(err)
	}
	delete(run.files, slice6GuestEFinalBindingPendingFile)
	if err := run.syncDir(run.fd); err != nil {
		t.Fatal(err)
	}
	if err := run.writeV2BoundedPrivateFile(slice6GuestEFinalBindingFile,
		[]byte("final fixture\n"), 128, false); err != nil {
		t.Fatal(err)
	}
	if slice6VerifyGuestRecoveryEFinalFileInventory(rootPath, run.id, inventory) != nil ||
		slice6VerifyGuestRecoveryEFileInventory(rootPath, run.id, inventory) == nil {
		t.Fatal("exact final-only inventory mode drifted")
	}
	if err := run.closeV2Incomplete(); err != nil ||
		slice6VerifyGuestRecoveryEFinalFileInventory(rootPath, run.id, inventory) == nil {
		t.Fatal("incomplete E result accepted a final-looking file")
	}
}

func TestSlice6GuestEFinalPublisherLateSyncRollsBackNoIssuer(t *testing.T) {
	rootPath := slice6ReceiptTestRoot(t)
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	run, err := root.newRun(strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		run.syncFile = (*os.File).Sync
		_ = run.closeV2Incomplete()
	}()
	limits := slice6GuestRecoveryEFileLimits()
	for _, name := range slice6GuestRecoveryExpectedNames(limits, false) {
		if err := run.writeV2BoundedPrivateFile(name, []byte("component fixture\n"), limits[name], false); err != nil {
			t.Fatal(err)
		}
	}
	inventory, err := run.captureGuestRecoveryEFileInventory()
	if err != nil {
		t.Fatal(err)
	}
	binding := slice6GuestEFinalBindingFixture()
	binding.FileInventoryDigest = inventory
	_, convergence, _ := slice6EConvergenceFixture(t)
	run.syncFile = func(*os.File) error { return errors.New("late final publisher sync") }
	if _, err := run.publishGuestEFinalBinding(binding, convergence); err == nil || run.complete {
		t.Fatal("late final publisher sync exposed a completed E binding")
	}
	for _, name := range [...]string{slice6GuestEFinalBindingPendingFile, slice6GuestEFinalBindingFile} {
		var observed unix.Stat_t
		if !errors.Is(unix.Fstatat(run.fd, name, &observed, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT) {
			t.Fatalf("failed final publisher left %s", name)
		}
	}
}
