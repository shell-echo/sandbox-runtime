//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6terminalcleanup"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
	"golang.org/x/sys/unix"
)

type slice6FinalFixtureRemote struct {
	observed  map[string]phase6terminalcleanup.TokenObservation
	absent    map[string]bool
	issuerDER []byte
	crlDER    []byte
}

func (remote *slice6FinalFixtureRemote) LookupAccessor(_ context.Context, accessor string) (phase6terminalcleanup.TokenObservation, error) {
	if remote.absent[accessor] {
		return phase6terminalcleanup.TokenObservation{}, phase6terminalcleanup.ErrAccessorAbsent
	}
	return remote.observed[accessor], nil
}
func (remote *slice6FinalFixtureRemote) RevokeAccessor(_ context.Context, accessor string) error {
	remote.absent[accessor] = true
	return nil
}
func (*slice6FinalFixtureRemote) RevokeCertificate(context.Context, string) error { return nil }
func (remote *slice6FinalFixtureRemote) ReadCompleteCRL(context.Context, string) ([]byte, []byte, error) {
	return append([]byte(nil), remote.issuerDER...), append([]byte(nil), remote.crlDER...), nil
}
func (*slice6FinalFixtureRemote) RevokeSelf(context.Context) error { return nil }

func slice6FinalTargetDigest(kind, value string) string {
	sum := sha256.Sum256([]byte("sandbox-runtime/phase6-terminal-cleanup-target/v1\x00" + kind + "\x00" + value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func slice6FinalV3Fixture(t *testing.T) (phase6terminalcleanup.Plan, []byte, []byte) {
	t.Helper()
	plan, certificateRaw, credentialRaw, issuerKey, issuerDER := slice6TerminalProjectionFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]x509.RevocationListEntry, 0, len(plan.Certificates))
	for _, target := range plan.Certificates {
		decoded, err := hex.DecodeString(strings.ReplaceAll(target.Serial, ":", ""))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: new(big.Int).SetBytes(decoded),
			RevocationTime: now.Add(-time.Minute)})
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(10 * time.Minute),
		RevokedCertificateEntries: entries}, issuer, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	remote := &slice6FinalFixtureRemote{observed: make(map[string]phase6terminalcleanup.TokenObservation),
		absent: make(map[string]bool), issuerDER: issuerDER, crlDER: crlDER}
	for _, token := range plan.Tokens {
		observation := phase6terminalcleanup.TokenObservation{Accessor: token.Accessor,
			Policies: []string{token.BackendPolicy}, Type: "service", TTLSeconds: 300}
		if token.Kind == "certificate-controller" {
			observation.Role = workloadcredential.Phase6TokenRole(token.BackendPolicy)
			observation.Metadata = map[string]string{"subject_id": "certificate_controller",
				"subject_digest": token.PrincipalDigest, "policy_id": "credential-certificate-controller",
				"policy_digest": token.PolicyDigest, "binding_digest": token.BindingDigest,
				"purpose": "workload_credential", "lease_id": token.LeaseID}
		} else {
			observation.Orphan = true
			observation.Metadata = map[string]string{"run_id": plan.RunID,
				"profile_digest": plan.ProfileDigest, "owner_digest": token.PrincipalDigest}
		}
		remote.observed[token.Accessor] = observation
	}
	receipt, err := phase6terminalcleanup.Execute(context.Background(), plan, remote, func() time.Time { return now })
	if err != nil {
		t.Fatalf("synthetic terminal execution: %v", err)
	}
	evidence := phase6terminalcleanup.EvidenceV3{Protocol: phase6terminalcleanup.EvidenceV3Protocol,
		RunID: plan.RunID, ProfileDigest: plan.ProfileDigest, PlanDigest: plan.Digest,
		CRLVerifiedUTC: now.Format(time.RFC3339Nano), IssuerDER: issuerDER, CRLDER: crlDER, Receipt: receipt}
	add := func(kind, target string, status int, media string) *phase6terminalcleanup.EvidenceV3Event {
		evidence.Events = append(evidence.Events, phase6terminalcleanup.EvidenceV3Event{
			Kind: kind, TargetDigest: target, Status: status, MediaType: media})
		return &evidence.Events[len(evidence.Events)-1]
	}
	for _, target := range plan.Tokens {
		observed := remote.observed[target.Accessor]
		digest := slice6FinalTargetDigest("token", target.Accessor)
		event := add("lookup-preflight", digest, 200, "application/json")
		event.ObservedDigest = digest
		event.Token = &phase6terminalcleanup.EvidenceV3Token{Policies: observed.Policies,
			Metadata: observed.Metadata, Role: observed.Role, Type: observed.Type,
			Orphan: observed.Orphan, Renewable: observed.Renewable, TTLSeconds: observed.TTLSeconds}
	}
	for _, target := range plan.Certificates {
		kind := "certificate"
		if target.Kind == "external-postgres-server" {
			kind = target.Kind
		}
		event := add("certificate-revoke", slice6FinalTargetDigest(kind, target.Serial), 200, "application/json")
		event.RevocationState = "revoked"
		event.RevocationUnix = now.Add(-time.Second).Unix()
		event.RevocationRFC3339 = now.Add(-time.Second).Format(time.RFC3339Nano)
	}
	issuerSum, crlSum := sha256.Sum256(issuerDER), sha256.Sum256(crlDER)
	add("issuer-read", plan.GeneralIssuerDigest, 200, "application/pkix-cert").ObservedDigest = "sha256:" + hex.EncodeToString(issuerSum[:])
	add("crl-config", plan.GeneralIssuerDigest, 200, "application/json").CRLConfig = &phase6terminalcleanup.EvidenceV3CRLConfig{}
	add("issuer-reread", plan.GeneralIssuerDigest, 200, "application/pkix-cert").ObservedDigest = "sha256:" + hex.EncodeToString(issuerSum[:])
	add("crl-read", plan.GeneralIssuerDigest, 200, "application/pkix-crl").ObservedDigest = "sha256:" + hex.EncodeToString(crlSum[:])
	for _, target := range plan.Tokens {
		digest := slice6FinalTargetDigest("token", target.Accessor)
		add("accessor-revoke", digest, 204, "")
		add("lookup-post-revoke", digest, 400, "application/json").InvalidAccessorError = "invalid accessor"
	}
	add("self-revoke", plan.Digest, 204, "")
	if err := phase6terminalcleanup.VerifyEvidenceV3(plan, evidence); err != nil {
		list, parseErr := x509.ParseRevocationList(crlDER)
		var crlErr error
		if parseErr == nil {
			_, crlErr = workloadpki.VerifyCRLForIssuer(workloadpki.RevocationSnapshot{
				DER: crlDER, ThisUpdate: list.ThisUpdate, NextUpdate: list.NextUpdate}, issuerDER, now)
		}
		t.Fatalf("synthetic private v3 evidence invalid: %v (plan=%v receipt=%v crlparse=%v crl=%v derlen=%d derprefix=%x)",
			err, plan.ValidateAt(now), phase6terminalcleanup.VerifyReceipt(plan, receipt), parseErr, crlErr, len(crlDER), crlDER[:min(16, len(crlDER))])
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	return plan, append(encoded, '\n'), mustSlice6FinalProjection(t, plan, certificateRaw, credentialRaw)
}

func mustSlice6FinalProjection(t *testing.T, plan phase6terminalcleanup.Plan, certRaw, credRaw []byte) []byte {
	t.Helper()
	projection, err := slice6ProjectTerminalLedgers(plan, certRaw, credRaw)
	if err != nil {
		t.Fatal(err)
	}
	return projection
}

func TestSlice6FinalV3FixtureOfflineReplayNoIssuer(t *testing.T) {
	plan, evidenceRaw, projection := slice6FinalV3Fixture(t)
	evidence, err := phase6terminalcleanup.DecodeEvidenceV3(evidenceRaw)
	if err != nil || phase6terminalcleanup.VerifyEvidenceV3(plan, evidence) != nil ||
		slice6VerifyTerminalLedgerProjection(plan, projection) != nil {
		t.Fatalf("synthetic no-issuer v3 replay failed: %v", err)
	}
}

type slice6FinalPublisherFixture struct {
	rootPath    string
	run         *slice6ReceiptEvidenceRun
	binding     slice6GuestEFinalBinding
	convergence slice6EConvergenceReceipt
}

func slice6NewFinalPublisherFixture(t *testing.T) slice6FinalPublisherFixture {
	t.Helper()
	plan, evidenceRaw, projectionRaw := slice6FinalV3Fixture(t)
	rootPath := slice6ReceiptTestRoot(t)
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if root.fd >= 0 {
			if err := root.close(); err != nil {
				t.Error(err)
			}
		}
	})
	run, err := root.newRun(plan.RunID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !run.closed {
			if err := run.closeV2Incomplete(); err != nil {
				t.Error(err)
			}
		}
	})
	_, convergence, _ := slice6EConvergenceFixture(t)
	precleanup := "sha256:" + strings.Repeat("5", 64)
	operatorID := strings.Repeat("e", 64)
	sink := &slice6TerminalV3Sink{Run: run, PrecleanupDigest: precleanup, verifiedPrecleanup: true}
	started := time.Now().UTC()
	if err := sink.persist(plan, evidenceRaw, operatorID,
		convergence.TerminalBinaryDigest, started, started, projectionRaw); err != nil {
		t.Fatalf("no-issuer v3 sink fixture: %v", err)
	}
	convergence.PrecleanupDigest = precleanup
	convergence.TerminalBindingDigest = sink.EvidenceDigest
	convergenceRaw, err := json.Marshal(convergence)
	if err != nil || slice6VerifyEConvergenceReceipt(convergenceRaw, convergence) != nil ||
		run.writeV2BoundedPrivateFile(slice6EConvergenceFile,
			convergenceRaw, slice6EConvergenceLimit, false) != nil {
		t.Fatalf("no-issuer convergence fixture: %v", err)
	}
	limits := slice6GuestRecoveryEFileLimits()
	for _, name := range slice6GuestRecoveryExpectedNames(limits, false) {
		if _, exists := run.files[name]; exists {
			continue
		}
		if err := run.writeV2BoundedPrivateFile(name, []byte("component fixture\n"), limits[name], false); err != nil {
			t.Fatalf("no-issuer inventory file %s: %v", name, err)
		}
	}
	inventory, err := run.captureGuestRecoveryEFileInventory()
	if err != nil {
		t.Fatal(err)
	}
	binding := slice6GuestEFinalBindingFixture()
	binding.RunID = plan.RunID
	binding.ProfileDigest = plan.ProfileDigest
	binding.Sources.RRevision = convergence.RRevision
	binding.PrecleanupDigest = precleanup
	binding.TerminalV3BindingDigest = sink.EvidenceDigest
	binding.ConvergenceDigest = slice6ReceiptSHA256(convergenceRaw)
	binding.FileInventoryDigest = inventory
	binding.TerminalBinaryDigest = convergence.TerminalBinaryDigest
	binding.TerminalOperatorID = operatorID
	binding.ControllerDrainClass = convergence.ControllerDrainClass
	binding.ControllerDrainOpen = convergence.ControllerDrainClass == "sticky_credential_revoke"
	binding.TerminalZeroDigest = slice6GuestRecoveryTerminalZeroDigest(plan.RunID,
		precleanup, sink.EvidenceDigest, convergence.DockerZeroDigest,
		convergence.ExactOriginZeroDigest, convergence.PrivateSiblingZeroDigest)
	if slice6VerifyGuestRecoveryEFileInventory(rootPath, plan.RunID, inventory) != nil ||
		run.verifyTerminalV3Binding(sink.EvidenceDigest, precleanup,
			convergence.TerminalBinaryDigest, operatorID) != nil {
		t.Fatal("no-issuer E fixture did not replay before publication")
	}
	return slice6FinalPublisherFixture{rootPath: rootPath, run: run,
		binding: binding, convergence: convergence}
}

func TestSlice6GuestEFinalPublisherCompletePathNoIssuer(t *testing.T) {
	fixture := slice6NewFinalPublisherFixture(t)
	digest, err := fixture.run.finishGuestEFinalBinding(fixture.binding, fixture.convergence)
	if err != nil || !fixture.run.complete || !fixture.run.closed || fixture.run.root.fd >= 0 ||
		slice6VerifyGuestEFinalBinding(fixture.rootPath, fixture.binding.RunID,
			digest, fixture.run.files[slice6GuestEFinalBindingFile], fixture.binding, fixture.convergence) != nil {
		t.Fatalf("E final publisher did not complete and independently reopen: %v", err)
	}
}

func TestSlice6GuestEFinalPublisherFailureMatrixNoIssuer(t *testing.T) {
	for _, name := range []string{"link", "no-replace race", "post-link sync", "pending unlink", "independent reopen",
		"replacement inode", "rollback unlink uncertain", "rollback sync uncertain"} {
		t.Run(name, func(t *testing.T) {
			fixture := slice6NewFinalPublisherFixture(t)
			run := fixture.run
			var heldFD = -1
			t.Cleanup(func() {
				if heldFD >= 0 {
					_ = unix.Close(heldFD)
				}
			})
			syncCalls := 0
			switch name {
			case "link":
				run.linkFile = func(int, string, int, string, int) error { return errors.New("injected link failure") }
			case "no-replace race":
				run.linkFile = func(oldFD int, oldName string, newFD int, newName string, flags int) error {
					foreignFD, err := unix.Openat(newFD, newName,
						unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
					if err != nil {
						return err
					}
					if err := unix.Close(foreignFD); err != nil {
						return err
					}
					return unix.Linkat(oldFD, oldName, newFD, newName, flags)
				}
			case "pending unlink":
				failed := false
				run.unlinkFile = func(fd int, path string, flags int) error {
					if path == slice6GuestEFinalBindingPendingFile && !failed {
						failed = true
						return errors.New("injected pending unlink failure")
					}
					return unix.Unlinkat(fd, path, flags)
				}
			case "post-link sync", "independent reopen", "replacement inode",
				"rollback unlink uncertain", "rollback sync uncertain":
				run.syncDir = func(fd int) error {
					syncCalls++
					if syncCalls == 2 && (name == "post-link sync" || name == "rollback unlink uncertain" ||
						name == "rollback sync uncertain") {
						return errors.New("injected post-link sync failure")
					}
					if syncCalls == 3 && name == "rollback sync uncertain" {
						return errors.New("injected rollback sync failure")
					}
					if syncCalls == 3 && name == "independent reopen" {
						if err := unix.Fchmodat(fd, slice6GuestEFinalBindingFile, 0o640, 0); err != nil {
							return err
						}
					}
					if syncCalls == 3 && name == "replacement inode" {
						original, err := run.readFile(slice6GuestEFinalBindingFile, slice6GuestEFinalBindingLimit)
						if err != nil {
							return err
						}
						heldFD, err = unix.Openat(fd, slice6GuestEFinalBindingFile,
							unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
						if err != nil {
							return err
						}
						if err := unix.Unlinkat(fd, slice6GuestEFinalBindingFile, 0); err != nil {
							return err
						}
						newFD, err := unix.Openat(fd, slice6GuestEFinalBindingFile,
							unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
						if err != nil {
							return err
						}
						file := os.NewFile(uintptr(newFD), "injected-replacement")
						_, writeErr := file.Write(original)
						syncErr, closeErr := file.Sync(), file.Close()
						clear(original)
						if writeErr != nil || syncErr != nil || closeErr != nil {
							return errors.Join(writeErr, syncErr, closeErr)
						}
					}
					return unix.Fsync(fd)
				}
				if name == "rollback unlink uncertain" {
					run.unlinkFile = func(fd int, path string, flags int) error {
						if path == slice6GuestEFinalBindingFile {
							return errors.New("injected rollback unlink failure")
						}
						return unix.Unlinkat(fd, path, flags)
					}
				}
			}
			_, err := run.publishGuestEFinalBinding(fixture.binding, fixture.convergence)
			if err == nil || run.complete {
				t.Fatal("injected publisher failure returned component success")
			}
			if (name == "no-replace race" || name == "rollback unlink uncertain" || name == "rollback sync uncertain" ||
				name == "replacement inode") != errors.Is(err, errSlice6ReceiptPublishUncertain) {
				t.Fatalf("rollback certainty misclassified: %v", err)
			}
			if name == "no-replace race" {
				var observed unix.Stat_t
				if unix.Fstatat(run.fd, slice6GuestEFinalBindingFile, &observed,
					unix.AT_SYMLINK_NOFOLLOW) != nil || observed.Ino == 0 {
					t.Fatal("foreign no-replace inode was removed")
				}
			} else if name == "replacement inode" {
				var observed unix.Stat_t
				if unix.Fstatat(run.fd, slice6GuestEFinalBindingFile, &observed,
					unix.AT_SYMLINK_NOFOLLOW) != nil ||
					slice6SameInode(observed, run.files[slice6GuestEFinalBindingFile]) {
					t.Fatal("replacement inode was removed or accepted")
				}
			} else if name != "rollback unlink uncertain" {
				for _, file := range [...]string{slice6GuestEFinalBindingFile, slice6GuestEFinalBindingPendingFile} {
					var observed unix.Stat_t
					if !errors.Is(unix.Fstatat(run.fd, file, &observed, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT) {
						t.Fatalf("failed publisher left %s", file)
					}
				}
			}
		})
	}
}

func TestSlice6GuestEFinalPublisherLateCloseAndReopenFailClosedNoIssuer(t *testing.T) {
	for _, name := range []string{"run close", "root close", "post-close reopen"} {
		t.Run(name, func(t *testing.T) {
			fixture := slice6NewFinalPublisherFixture(t)
			ops := slice6GuestEFinishOps{closeRun: unix.Close,
				closeRoot: (*slice6ReceiptEvidenceRoot).close, verify: slice6VerifyGuestEFinalBinding}
			switch name {
			case "run close":
				ops.closeRun = func(fd int) error {
					if err := unix.Close(fd); err != nil {
						return err
					}
					return errors.New("injected late run close failure")
				}
			case "root close":
				ops.closeRoot = func(root *slice6ReceiptEvidenceRoot) error {
					if err := root.close(); err != nil {
						return err
					}
					return errors.New("injected late root close failure")
				}
			case "post-close reopen":
				ops.verify = func(rootPath, runID, digest string, identity unix.Stat_t,
					binding slice6GuestEFinalBinding, receipt slice6EConvergenceReceipt) error {
					if err := os.Chmod(rootPath, 0o500); err != nil {
						return err
					}
					err := slice6VerifyGuestEFinalBinding(rootPath, runID,
						digest, identity, binding, receipt)
					if restoreErr := os.Chmod(rootPath, 0o700); restoreErr != nil {
						return errors.Join(err, restoreErr)
					}
					if err == nil {
						return errors.New("independent reopen unexpectedly accepted inaccessible root")
					}
					return err
				}
			}
			_, err := fixture.run.finishGuestEFinalBindingWith(fixture.binding, fixture.convergence, ops)
			if err == nil || fixture.run.complete || !fixture.run.closed || fixture.run.root.fd >= 0 {
				t.Fatalf("late failure exposed E success or open descriptors: %v", err)
			}
			for _, file := range [...]string{slice6GuestEFinalBindingFile, slice6GuestEFinalBindingPendingFile} {
				var observed unix.Stat_t
				if !errors.Is(unix.Fstatat(unix.AT_FDCWD,
					fixture.rootPath+"/"+fixture.binding.RunID+"/"+file,
					&observed, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT) {
					t.Fatalf("late failure left %s", file)
				}
			}
			if slice6VerifyGuestRecoveryEIncompleteFileInventory(fixture.rootPath,
				fixture.binding.RunID, fixture.binding.FileInventoryDigest) != nil {
				t.Fatal("late failure did not retain incomplete E evidence")
			}
		})
	}
}
