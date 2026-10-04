//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
	"github.com/shell-echo/sandbox-runtime/internal/phase6profilebuilder"
	"golang.org/x/sys/unix"
)

const slice6GuestEFinalBindingFile = "guest-e-final-binding.json"
const slice6GuestEFinalBindingPendingFile = "guest-e-final-binding.pending"
const slice6GuestEFinalBindingProtocol = "sandbox-runtime.phase6-guest-e-final-binding.v1"
const slice6GuestEFinalBindingLimit = 4096

type slice6GuestESourceIdentity struct {
	ERevision, ETree, RRevision, RTree, FRevision, FTree string
}

type slice6GuestEFinalBinding struct {
	Protocol, Disposition, RunID, ProfileDigest string
	Sources                                     slice6GuestESourceIdentity
	PrecleanupDigest, TerminalZeroDigest        string
	TerminalV3BindingDigest                     string
	ConvergenceDigest, FileInventoryDigest      string
	TerminalBinaryDigest, TerminalOperatorID    string
	ControllerDrainClass                        string
	ControllerDrainOpen                         bool
	RecordedUTC                                 string
}

// E is the executing clean checkout; R is the runtime/image source; F is the
// independent fixture source. The terminal binary is built from R and cannot
// reuse an older R after phase6terminalcleanup production code changes.
func slice6FreezeGuestESources(ctx context.Context, static slice6VaultStaticInputs,
	images phase6profilebuilder.ImageSupply, fixture slice6GuestBindingFixtureArtifact) (slice6GuestESourceIdentity, error) {
	if ctx == nil || ctx.Err() != nil || images.RuntimeRevision != static.sourceRevision ||
		!guestRevokeFixtureDigestGate(images.RuntimeTreeDigest) || images.VerifySources(ctx) != nil {
		return slice6GuestESourceIdentity{}, phase6guestreceipt.ErrUnavailable
	}
	eRoot, err := filepath.Abs("..")
	if err != nil {
		return slice6GuestESourceIdentity{}, phase6guestreceipt.ErrUnavailable
	}
	eRevision := os.Getenv(slice6ProductObserverRevisionEnv)
	fRoot, fRevision := os.Getenv(slice6GuestFixtureSourceRootEnv), fixture.SourceRevision
	if len(eRevision) != 40 || !lowerHexSlice6(eRevision) ||
		len(static.sourceRevision) != 40 || !lowerHexSlice6(static.sourceRevision) ||
		len(fRevision) != 40 || !lowerHexSlice6(fRevision) ||
		verifyCleanSlice6Source(ctx, eRoot, eRevision) != nil ||
		verifyCleanSlice6Source(ctx, static.sourceRoot, static.sourceRevision) != nil ||
		verifyCleanSlice6Source(ctx, fRoot, fRevision) != nil {
		return slice6GuestESourceIdentity{}, phase6guestreceipt.ErrUnavailable
	}
	eTree, eErr := desktopcandidate.SourceTreeDigestAtRevision(eRoot, eRevision)
	rTree, rErr := desktopcandidate.SourceTreeDigestAtRevision(static.sourceRoot, static.sourceRevision)
	fTree, fErr := desktopcandidate.SourceTreeDigestAtRevision(fRoot, fRevision)
	if eErr != nil || rErr != nil || fErr != nil || rTree != images.RuntimeTreeDigest ||
		!guestRevokeFixtureDigestGate(eTree) || !guestRevokeFixtureDigestGate(fTree) {
		return slice6GuestESourceIdentity{}, phase6guestreceipt.ErrUnavailable
	}
	return slice6GuestESourceIdentity{ERevision: eRevision, ETree: eTree,
		RRevision: static.sourceRevision, RTree: rTree,
		FRevision: fRevision, FTree: fTree}, nil
}

func slice6VerifyGuestEFinalBindingDocument(raw []byte, expected slice6GuestEFinalBinding) error {
	if len(raw) < 2 || len(raw) > slice6GuestEFinalBindingLimit ||
		expected.Protocol != slice6GuestEFinalBindingProtocol ||
		expected.Disposition != "guest_e_component_verified" ||
		len(expected.RunID) != 32 || !lowerHexSlice6(expected.RunID) ||
		!guestRevokeFixtureDigestGate(expected.ProfileDigest) ||
		!guestRevokeFixtureDigestGate(expected.Sources.ETree) ||
		!guestRevokeFixtureDigestGate(expected.Sources.RTree) ||
		!guestRevokeFixtureDigestGate(expected.Sources.FTree) ||
		len(expected.Sources.ERevision) != 40 || !lowerHexSlice6(expected.Sources.ERevision) ||
		len(expected.Sources.RRevision) != 40 || !lowerHexSlice6(expected.Sources.RRevision) ||
		len(expected.Sources.FRevision) != 40 || !lowerHexSlice6(expected.Sources.FRevision) ||
		!guestRevokeFixtureDigestGate(expected.PrecleanupDigest) ||
		!guestRevokeFixtureDigestGate(expected.TerminalZeroDigest) ||
		!guestRevokeFixtureDigestGate(expected.TerminalV3BindingDigest) ||
		!guestRevokeFixtureDigestGate(expected.ConvergenceDigest) ||
		!guestRevokeFixtureDigestGate(expected.FileInventoryDigest) ||
		!guestRevokeFixtureDigestGate(expected.TerminalBinaryDigest) ||
		len(expected.TerminalOperatorID) != 64 || !lowerHexSlice6(expected.TerminalOperatorID) ||
		(expected.ControllerDrainClass != "clean_exit" &&
			expected.ControllerDrainClass != "sticky_credential_revoke") ||
		expected.ControllerDrainOpen != (expected.ControllerDrainClass == "sticky_credential_revoke") {
		return phase6guestreceipt.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var actual slice6GuestEFinalBinding
	if decoder.Decode(&actual) != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return phase6guestreceipt.ErrUnavailable
	}
	canonical, err := json.Marshal(actual)
	if err != nil || !bytes.Equal(canonical, raw) || actual != expected {
		return phase6guestreceipt.ErrUnavailable
	}
	when, err := time.Parse(time.RFC3339Nano, actual.RecordedUTC)
	if err != nil || when.IsZero() || actual.RecordedUTC != when.UTC().Format(time.RFC3339Nano) {
		return phase6guestreceipt.ErrUnavailable
	}
	return nil
}

// This verifier is deliberately independent of the writer's inode map.
// expected is supplied by the reviewed freeze and previously verified chain,
// never copied from the candidate final-binding file itself.
func slice6VerifyGuestEFinalBinding(rootPath, runID, expectedDigest string,
	finalIdentity unix.Stat_t, expected slice6GuestEFinalBinding,
	convergence slice6EConvergenceReceipt) (result error) {
	if expected.RunID != runID || !guestRevokeFixtureDigestGate(expectedDigest) ||
		slice6VerifyGuestRecoveryEFinalFileInventory(rootPath, runID, expected.FileInventoryDigest) != nil ||
		slice6VerifyEConvergenceFile(rootPath, runID, expected.ConvergenceDigest, convergence) != nil ||
		convergence.RunID != runID || convergence.ProfileDigest != expected.ProfileDigest ||
		convergence.RRevision != expected.Sources.RRevision ||
		convergence.TerminalBinaryDigest != expected.TerminalBinaryDigest ||
		convergence.PrecleanupDigest != expected.PrecleanupDigest ||
		convergence.TerminalBindingDigest != expected.TerminalV3BindingDigest ||
		convergence.ControllerDrainClass != expected.ControllerDrainClass ||
		slice6GuestRecoveryTerminalZeroDigest(runID, convergence.PrecleanupDigest,
			convergence.TerminalBindingDigest, convergence.DockerZeroDigest,
			convergence.ExactOriginZeroDigest, convergence.PrivateSiblingZeroDigest) != expected.TerminalZeroDigest {
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
	if unix.Fstatat(run.fd, slice6GuestEFinalBindingFile, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 ||
		stat.Uid != uint32(os.Getuid()) || stat.Ino == 0 ||
		!slice6SameInode(stat, finalIdentity) {
		return phase6guestreceipt.ErrUnavailable
	}
	run.files[slice6GuestEFinalBindingFile] = stat
	for _, name := range []string{slice6TerminalV3BindingFile, slice6TerminalV3PlanFile,
		slice6TerminalV3EvidenceFile, slice6TerminalLedgerProjectionFile} {
		var entry unix.Stat_t
		if unix.Fstatat(run.fd, name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			entry.Mode&unix.S_IFMT != unix.S_IFREG || entry.Mode&0o7777 != 0o600 ||
			entry.Uid != uint32(os.Getuid()) || entry.Ino == 0 {
			return phase6guestreceipt.ErrUnavailable
		}
		run.files[name] = entry
	}
	if run.verifyTerminalV3Binding(expected.TerminalV3BindingDigest,
		expected.PrecleanupDigest, expected.TerminalBinaryDigest,
		expected.TerminalOperatorID) != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	raw, err := run.readFile(slice6GuestEFinalBindingFile, slice6GuestEFinalBindingLimit)
	defer clear(raw)
	if err != nil || slice6ReceiptSHA256(raw) != expectedDigest ||
		slice6VerifyGuestEFinalBindingDocument(raw, expected) != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	return nil
}

func (run *slice6ReceiptEvidenceRun) rollbackGuestEFinalBinding() error {
	if run == nil || run.check() != nil {
		return errSlice6ReceiptPublishUncertain
	}
	uncertain := false
	for _, name := range [...]string{slice6GuestEFinalBindingFile, slice6GuestEFinalBindingPendingFile} {
		wanted, known := run.files[name]
		if !known {
			var unknown unix.Stat_t
			if !errors.Is(unix.Fstatat(run.fd, name, &unknown, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT) {
				uncertain = true // never unlink an inode the E publisher did not create
			}
			continue
		}
		var observed unix.Stat_t
		err := unix.Fstatat(run.fd, name, &observed, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			delete(run.files, name)
			continue
		}
		if err != nil || !slice6SameInode(wanted, observed) ||
			observed.Mode&unix.S_IFMT != unix.S_IFREG || observed.Uid != uint32(os.Getuid()) ||
			run.unlinkFile(run.fd, name, 0) != nil {
			uncertain = true
			continue
		}
		delete(run.files, name)
	}
	for _, name := range [...]string{slice6GuestEFinalBindingFile, slice6GuestEFinalBindingPendingFile} {
		var residual unix.Stat_t
		if !errors.Is(unix.Fstatat(run.fd, name, &residual, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT) {
			uncertain = true
		}
	}
	if run.syncDir(run.fd) != nil || uncertain {
		return errSlice6ReceiptPublishUncertain
	}
	return nil
}

// This E-only component publisher runs only after the existing precleanup,
// v3, Docker/origin/private-zero and 14-slot verifiers have succeeded. It
// cannot publish a Slice 6 release manifest or cleanse a sticky controller.
func (run *slice6ReceiptEvidenceRun) publishGuestEFinalBinding(expected slice6GuestEFinalBinding,
	convergence slice6EConvergenceReceipt) (digest string, resultErr error) {
	if run == nil || run.check() != nil || run.complete || expected.RunID != run.id ||
		slice6VerifyGuestRecoveryEFileInventory(run.root.path, run.id,
			expected.FileInventoryDigest) != nil {
		return "", phase6guestreceipt.ErrUnavailable
	}
	raw, err := json.Marshal(expected)
	if err != nil || slice6VerifyGuestEFinalBindingDocument(raw, expected) != nil {
		clear(raw)
		return "", phase6guestreceipt.ErrUnavailable
	}
	defer clear(raw)
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, run.rollbackGuestEFinalBinding())
		}
	}()
	if run.writeV2BoundedPrivateFile(slice6GuestEFinalBindingPendingFile,
		raw, slice6GuestEFinalBindingLimit, false) != nil {
		return "", phase6guestreceipt.ErrUnavailable
	}
	pending, known := run.files[slice6GuestEFinalBindingPendingFile]
	var observed unix.Stat_t
	if !known || unix.Fstatat(run.fd, slice6GuestEFinalBindingPendingFile,
		&observed, unix.AT_SYMLINK_NOFOLLOW) != nil || !slice6SameInode(pending, observed) ||
		observed.Mode&unix.S_IFMT != unix.S_IFREG || observed.Mode&0o7777 != 0o600 ||
		observed.Uid != uint32(os.Getuid()) ||
		!errors.Is(unix.Fstatat(run.fd, slice6GuestEFinalBindingFile,
			&observed, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT) {
		return "", phase6guestreceipt.ErrUnavailable
	}
	if run.linkFile(run.fd, slice6GuestEFinalBindingPendingFile,
		run.fd, slice6GuestEFinalBindingFile, 0) != nil {
		return "", phase6guestreceipt.ErrUnavailable
	}
	run.files[slice6GuestEFinalBindingFile] = pending
	if run.syncDir(run.fd) != nil ||
		run.unlinkFile(run.fd, slice6GuestEFinalBindingPendingFile, 0) != nil {
		return "", phase6guestreceipt.ErrUnavailable
	}
	delete(run.files, slice6GuestEFinalBindingPendingFile)
	if run.syncDir(run.fd) != nil {
		return "", phase6guestreceipt.ErrUnavailable
	}
	digest = slice6ReceiptSHA256(raw)
	if slice6VerifyGuestEFinalBinding(run.root.path, run.id, digest, pending, expected, convergence) != nil {
		return "", phase6guestreceipt.ErrUnavailable
	}
	return digest, nil
}

func slice6RollbackGuestEFinalAfterClose(rootPath, runID string,
	rootIdentity, runIdentity unix.Stat_t, finalIdentity unix.Stat_t) (resultErr error) {
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		return errSlice6ReceiptPublishUncertain
	}
	defer func() { resultErr = errors.Join(resultErr, root.close()) }()
	if !slice6SameInode(root.stat, rootIdentity) {
		return errSlice6ReceiptPublishUncertain
	}
	run, err := root.openRun(runID)
	if err != nil {
		return errSlice6ReceiptPublishUncertain
	}
	if !slice6SameInode(run.stat, runIdentity) {
		return errors.Join(errSlice6ReceiptPublishUncertain, unix.Close(run.fd))
	}
	run.files[slice6GuestEFinalBindingFile] = finalIdentity
	rollbackErr := run.rollbackGuestEFinalBinding()
	incompleteErr := run.closeV2Incomplete()
	return errors.Join(rollbackErr, incompleteErr)
}

// The final E result is returned only after both owned directory descriptors
// close and a fresh read-only verifier reopens the exact retained run. A late
// close failure rolls back the original final inode and leaves incomplete.
type slice6GuestEFinishOps struct {
	closeRun  func(int) error
	closeRoot func(*slice6ReceiptEvidenceRoot) error
	verify    func(string, string, string, unix.Stat_t, slice6GuestEFinalBinding, slice6EConvergenceReceipt) error
}

func (run *slice6ReceiptEvidenceRun) finishGuestEFinalBinding(expected slice6GuestEFinalBinding,
	convergence slice6EConvergenceReceipt) (string, error) {
	return run.finishGuestEFinalBindingWith(expected, convergence, slice6GuestEFinishOps{
		closeRun: unix.Close, closeRoot: (*slice6ReceiptEvidenceRoot).close,
		verify: slice6VerifyGuestEFinalBinding})
}

func (run *slice6ReceiptEvidenceRun) finishGuestEFinalBindingWith(expected slice6GuestEFinalBinding,
	convergence slice6EConvergenceReceipt, ops slice6GuestEFinishOps) (string, error) {
	if run == nil || run.check() != nil || run.complete {
		return "", phase6guestreceipt.ErrUnavailable
	}
	if ops.closeRun == nil || ops.closeRoot == nil || ops.verify == nil {
		return "", phase6guestreceipt.ErrUnavailable
	}
	digest, err := run.publishGuestEFinalBinding(expected, convergence)
	if err != nil {
		return "", err
	}
	finalIdentity, ok := run.files[slice6GuestEFinalBindingFile]
	if !ok {
		return "", errSlice6ReceiptPublishUncertain
	}
	rootPath, runID := run.root.path, run.id
	rootIdentity, runIdentity := run.root.stat, run.stat
	closeRunErr := ops.closeRun(run.fd)
	run.fd, run.closed = -1, true
	closeRootErr := ops.closeRoot(run.root)
	if closeRunErr != nil || closeRootErr != nil {
		rollbackErr := slice6RollbackGuestEFinalAfterClose(rootPath, runID,
			rootIdentity, runIdentity, finalIdentity)
		return "", errors.Join(phase6guestreceipt.ErrUnavailable, closeRunErr, closeRootErr, rollbackErr)
	}
	if ops.verify(rootPath, runID, digest, finalIdentity, expected, convergence) != nil {
		rollbackErr := slice6RollbackGuestEFinalAfterClose(rootPath, runID,
			rootIdentity, runIdentity, finalIdentity)
		return "", errors.Join(phase6guestreceipt.ErrUnavailable, rollbackErr)
	}
	run.complete = true
	return digest, nil
}
