//go:build phase6slice6gate

package productphase6gate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
	"golang.org/x/sys/unix"
)

func TestSlice6GuestEvidenceOverflowAndDurabilityFailureRemainIncomplete(t *testing.T) {
	rootPath := slice6ReceiptTestRoot(t)
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	for index, name := range []string{"overflow", "file_sync", "directory_sync"} {
		run, err := root.newRun(strings.Repeat(string(rune('d'+index)), 32))
		if err != nil {
			t.Fatal(err)
		}
		switch name {
		case "overflow":
			file, err := run.createFile("guest-pid1.stdout")
			if err != nil {
				t.Fatal(err)
			}
			output := &slice6ReceiptBoundedFile{file: file}
			if _, err := output.Write(make([]byte, phase6guestreceipt.MaxTotalBytes+1)); err == nil || !output.overflow {
				t.Fatal("raw stdout overflow accepted")
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		case "file_sync":
			run.syncFile = func(*os.File) error { return errors.New("injected file sync failure") }
			if run.writeDocument("mutation-receipt.json", map[string]string{"probe": "file"}) == nil {
				t.Fatal("file sync failure accepted")
			}
			run.syncFile = (*os.File).Sync
		case "directory_sync":
			run.syncDir = func(int) error { return errors.New("injected directory sync failure") }
			if run.writeDocument("mutation-receipt.json", map[string]string{"probe": "directory"}) == nil {
				t.Fatal("directory sync failure accepted")
			}
			run.syncDir = func(fd int) error { return unix.Fsync(fd) }
		}
		if err := run.close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(rootPath, run.id, "binding.json")); !os.IsNotExist(err) {
			t.Fatal("failed writer published success binding")
		}
		if _, err := os.Stat(filepath.Join(rootPath, run.id, "incomplete.json")); err != nil {
			t.Fatal("failed writer did not retain incomplete marker")
		}
	}
}

func slice6ReceiptTestRoot(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func slice6ReceiptTestStream(t *testing.T, role, profile, config string) []byte {
	t.Helper()
	first, second := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	events := []struct{ event, digest, reason string }{}
	if role == "product" {
		events = []struct{ event, digest, reason string }{
			{"product_auth_accepted", first, ""}, {"product_welcome_written", first, ""},
			{"product_peer_installed", first, ""}, {"product_authority_stale", first, ""},
			{"product_close_completed", first, "authority_stale"}, {"product_validated_revoked", second, ""},
		}
	} else {
		events = []struct{ event, digest, reason string }{
			{"guest_hello_written", first, ""}, {"guest_welcome_accepted", first, ""},
			{"guest_read_terminated", first, ""}, {"guest_hello_written", second, ""},
		}
	}
	records := []phase6guestreceipt.Record{{Protocol: phase6guestreceipt.Protocol, Role: role,
		Event: "begin", ProfileDigest: profile, ConfigDigest: config}}
	for _, value := range events {
		records = append(records, phase6guestreceipt.Record{Protocol: phase6guestreceipt.Protocol,
			Role: role, Event: value.event, AttemptDigest: value.digest,
			BindingGeneration: 1, Reason: value.reason})
	}
	records = append(records, phase6guestreceipt.Record{Protocol: phase6guestreceipt.Protocol,
		Role: role, Event: "seal", EventCount: uint64(len(events))})
	var document []byte
	for i := range records {
		records[i].Sequence = uint64(i + 1)
		records[i].ElapsedNanos = int64(i + 1)
		records[i].UnixMillis = 1_700_000_000_000 + int64(i)
		line, err := json.Marshal(records[i])
		if err != nil {
			t.Fatal(err)
		}
		document = append(append(document, line...), '\n')
	}
	if _, err := phase6guestreceipt.Verify(document, role, profile, config); err != nil {
		t.Fatal(err)
	}
	return document
}

func TestSlice6GuestEvidenceIndependentRereadRejectsTamperAndIdentityDrift(t *testing.T) {
	rootPath := slice6ReceiptTestRoot(t)
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	id := strings.Repeat("c", 32)
	run, err := root.newRun(id)
	if err != nil {
		t.Fatal(err)
	}
	defer run.close()
	profile, productConfig, guestConfig := "sha256:"+strings.Repeat("1", 64),
		"sha256:"+strings.Repeat("2", 64), "sha256:"+strings.Repeat("3", 64)
	image := "sha256:" + strings.Repeat("4", 64)
	verifiedAt := time.Now().UTC()
	bindings := make(map[string]slice6ReceiptRawBinding)
	for _, item := range []struct{ role, config, container string }{
		{"product", productConfig, strings.Repeat("5", 64)},
		{"guest", guestConfig, strings.Repeat("6", 64)},
	} {
		document := slice6ReceiptTestStream(t, item.role, profile, item.config)
		name := slice6ReceiptRawName(item.role)
		file, err := run.createFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := file.Write(document); err != nil || n != len(document) {
			t.Fatal("write synthetic canonical raw receipt")
		}
		if err := file.Sync(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		binding := slice6ReceiptRawBinding{Role: item.role, File: name, SHA256: slice6ReceiptSHA256(document),
			Bytes: len(document), ProfileDigest: profile, ConfigDigest: item.config,
			SelectedImage: image, ActualImage: image, ContainerID: item.container,
			CaptureStartUTC:  verifiedAt.Add(-time.Second).Format(time.RFC3339Nano),
			CaptureFinishUTC: verifiedAt.Add(time.Second).Format(time.RFC3339Nano)}
		if item.role == "guest" {
			binding.DockerExitCode = 1
		}
		if err := run.recordRaw(binding); err != nil {
			t.Fatal(err)
		}
		bindings[item.role] = binding
	}
	mutation := slice6GuestRevokeFixtureReceipt{Protocol: slice6GuestRevokeFixtureProtocol,
		RunID: id, ProfileDigest: profile, ProductContainerID: bindings["product"].ContainerID,
		BindingGeneration: 1, MutationOutcome: "confirmed", BeforeConnected: true,
		AfterRevoked: true, NonceCleared: true}
	mutationJSON, err := json.Marshal(mutation)
	if err != nil {
		t.Fatal(err)
	}
	artifact := slice6ReceiptArtifact{ManifestDigest: profile, ArchiveDigest: profile,
		SelectedManifestDigest: profile, ConfigDigest: profile, ImageID: image}
	expected := slice6ReceiptExpectedIdentity{ERevision: strings.Repeat("a", 40),
		ETree: profile, RRevision: strings.Repeat("b", 40), RTree: profile,
		FRevision: strings.Repeat("c", 40), FTree: profile, ProfileDigest: profile,
		ProductConfigDigest: productConfig, GuestConfigDigest: guestConfig,
		ProductArtifact: artifact, GuestArtifact: artifact,
		ProductContainerID: bindings["product"].ContainerID,
		GuestContainerID:   bindings["guest"].ContainerID,
		ProductImageID:     image, GuestImageID: image}
	binding := slice6ReceiptEvidenceBinding{Protocol: "sandbox-runtime.phase6-guest-receipt-evidence.v1",
		Disposition: "component_verified", RunID: id,
		ERevision: expected.ERevision, ETree: expected.ETree, RRevision: expected.RRevision,
		RTree: expected.RTree, FRevision: expected.FRevision, FTree: expected.FTree,
		ProfileDigest: profile, Product: bindings["product"], Guest: bindings["guest"],
		ProductArtifact: artifact, GuestArtifact: artifact,
		MutationReceiptSHA256: slice6ReceiptSHA256(append(mutationJSON, '\n')), MutationGeneration: 1,
		MutationVerifiedUTC: verifiedAt.Format(time.RFC3339Nano)}
	if err := run.finish(binding, mutation, expected); err != nil {
		t.Fatal(err)
	}
	mutationOnDisk, err := os.ReadFile(filepath.Join(rootPath, id, "mutation-receipt.json"))
	if err != nil || slice6ReceiptSHA256(mutationOnDisk) != binding.MutationReceiptSHA256 {
		t.Fatal("binding does not hash exact mutation receipt file bytes", err)
	}
	if err := slice6VerifyPersistentGuestEvidence(rootPath, id, expected); err != nil {
		t.Fatal("independent reread rejected exact evidence", err)
	}
	bad := expected
	bad.ERevision = strings.Repeat("d", 40)
	if slice6VerifyPersistentGuestEvidence(rootPath, id, bad) == nil {
		t.Fatal("E revision drift accepted")
	}
	bad = expected
	bad.RRevision = strings.Repeat("d", 40)
	if slice6VerifyPersistentGuestEvidence(rootPath, id, bad) == nil {
		t.Fatal("R revision drift accepted")
	}
	bad = expected
	bad.GuestConfigDigest = profile
	if slice6VerifyPersistentGuestEvidence(rootPath, id, bad) == nil {
		t.Fatal("config drift accepted")
	}
	for _, drift := range []struct {
		name  string
		apply func(*slice6ReceiptExpectedIdentity)
	}{
		{"archive", func(x *slice6ReceiptExpectedIdentity) { x.ProductArtifact.ArchiveDigest = guestConfig }},
		{"selected manifest", func(x *slice6ReceiptExpectedIdentity) { x.GuestArtifact.SelectedManifestDigest = guestConfig }},
		{"OCI config", func(x *slice6ReceiptExpectedIdentity) { x.ProductArtifact.ConfigDigest = guestConfig }},
		{"image", func(x *slice6ReceiptExpectedIdentity) { x.GuestImageID = guestConfig }},
		{"container", func(x *slice6ReceiptExpectedIdentity) { x.ProductContainerID = strings.Repeat("7", 64) }},
	} {
		bad = expected
		drift.apply(&bad)
		if slice6VerifyPersistentGuestEvidence(rootPath, id, bad) == nil {
			t.Fatal("legal-shape external expected identity drift accepted:", drift.name)
		}
	}
	if slice6VerifyPersistentGuestEvidence(rootPath, strings.Repeat("d", 32), expected) == nil {
		t.Fatal("run drift accepted")
	}
	path := filepath.Join(rootPath, id, "guest-pid1.stdout")
	if err := os.WriteFile(path, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if slice6VerifyPersistentGuestEvidence(rootPath, id, expected) == nil {
		t.Fatal("raw tamper accepted")
	}
}

// Publication failures are injected after a complete pair of canonical raw
// receipts, so each case exercises the binding transaction rather than an
// unrelated parsing failure.
func slice6ReceiptPublicationFixture(t *testing.T) (*slice6ReceiptEvidenceRun,
	slice6ReceiptEvidenceBinding, slice6GuestRevokeFixtureReceipt, slice6ReceiptExpectedIdentity) {
	t.Helper()
	rootPath := slice6ReceiptTestRoot(t)
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.close() })
	id := strings.Repeat("e", 32)
	run, err := root.newRun(id)
	if err != nil {
		t.Fatal(err)
	}
	profile := "sha256:" + strings.Repeat("1", 64)
	productConfig := "sha256:" + strings.Repeat("2", 64)
	guestConfig := "sha256:" + strings.Repeat("3", 64)
	image := "sha256:" + strings.Repeat("4", 64)
	now := time.Now().UTC()
	bindings := make(map[string]slice6ReceiptRawBinding)
	for _, value := range []struct{ role, config, container string }{
		{"product", productConfig, strings.Repeat("5", 64)},
		{"guest", guestConfig, strings.Repeat("6", 64)},
	} {
		data := slice6ReceiptTestStream(t, value.role, profile, value.config)
		name := slice6ReceiptRawName(value.role)
		file, err := run.createFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := file.Write(data); err != nil || n != len(data) {
			t.Fatal("write raw receipt", err)
		}
		if err := file.Sync(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		binding := slice6ReceiptRawBinding{Role: value.role, File: name,
			SHA256: slice6ReceiptSHA256(data), Bytes: len(data), ProfileDigest: profile,
			ConfigDigest: value.config, SelectedImage: image, ActualImage: image,
			ContainerID:      value.container,
			CaptureStartUTC:  now.Add(-time.Second).Format(time.RFC3339Nano),
			CaptureFinishUTC: now.Add(time.Second).Format(time.RFC3339Nano)}
		if value.role == "guest" {
			binding.DockerExitCode = 1
		}
		if err := run.recordRaw(binding); err != nil {
			t.Fatal(err)
		}
		bindings[value.role] = binding
	}
	mutation := slice6GuestRevokeFixtureReceipt{Protocol: slice6GuestRevokeFixtureProtocol,
		RunID: id, ProfileDigest: profile, ProductContainerID: bindings["product"].ContainerID,
		BindingGeneration: 1, MutationOutcome: "confirmed", BeforeConnected: true,
		AfterRevoked: true, NonceCleared: true}
	mutationData, err := json.Marshal(mutation)
	if err != nil {
		t.Fatal(err)
	}
	artifact := slice6ReceiptArtifact{ManifestDigest: profile, ArchiveDigest: profile,
		SelectedManifestDigest: profile, ConfigDigest: profile, ImageID: image}
	expected := slice6ReceiptExpectedIdentity{ERevision: strings.Repeat("a", 40), ETree: profile,
		RRevision: strings.Repeat("b", 40), RTree: profile,
		FRevision: strings.Repeat("c", 40), FTree: profile, ProfileDigest: profile,
		ProductConfigDigest: productConfig, GuestConfigDigest: guestConfig,
		ProductArtifact: artifact, GuestArtifact: artifact,
		ProductContainerID: bindings["product"].ContainerID,
		GuestContainerID:   bindings["guest"].ContainerID,
		ProductImageID:     image, GuestImageID: image}
	binding := slice6ReceiptEvidenceBinding{Protocol: "sandbox-runtime.phase6-guest-receipt-evidence.v1",
		Disposition: "component_verified", RunID: id,
		ERevision: expected.ERevision, ETree: expected.ETree,
		RRevision: expected.RRevision, RTree: expected.RTree,
		FRevision: expected.FRevision, FTree: expected.FTree,
		ProfileDigest: profile, Product: bindings["product"], Guest: bindings["guest"],
		ProductArtifact: artifact, GuestArtifact: artifact,
		MutationReceiptSHA256: slice6ReceiptSHA256(append(mutationData, '\n')),
		MutationGeneration:    1, MutationVerifiedUTC: now.Format(time.RFC3339Nano)}
	return run, binding, mutation, expected
}

func TestSlice6GuestEvidenceBindingPublicationFailures(t *testing.T) {
	for _, name := range []string{"pending_sync", "pending_readback", "link", "publish_sync", "rollback_unlink"} {
		t.Run(name, func(t *testing.T) {
			run, binding, mutation, expected := slice6ReceiptPublicationFixture(t)
			originalSync := run.syncDir
			switch name {
			case "pending_sync":
				run.syncFile = func(file *os.File) error {
					if file.Name() == "binding.pending" {
						return errors.New("injected pending file sync failure")
					}
					return file.Sync()
				}
			case "pending_readback":
				run.afterWrite = func(file string) error {
					if file == "binding.pending" {
						return errors.New("injected pending readback failure")
					}
					return nil
				}
			case "link":
				run.linkFile = func(int, string, int, string, int) error {
					return errors.New("injected no-replace publish failure")
				}
			case "publish_sync", "rollback_unlink":
				run.syncDir = func(fd int) error {
					if _, exists := run.files["binding.json"]; exists {
						return errors.New("injected publish directory sync failure")
					}
					return originalSync(fd)
				}
				if name == "rollback_unlink" {
					run.unlinkFile = func(fd int, file string, flags int) error {
						if file == "binding.json" {
							return errors.New("injected final binding rollback unlink failure")
						}
						return unix.Unlinkat(fd, file, flags)
					}
				}
			}
			finishErr := run.finish(binding, mutation, expected)
			if finishErr == nil {
				t.Fatal("binding publication failure accepted")
			}
			if name == "rollback_unlink" && !errors.Is(finishErr, errSlice6ReceiptPublishUncertain) {
				t.Fatal("rollback uncertainty was hidden", finishErr)
			}
			if name != "rollback_unlink" {
				for _, file := range []string{"binding.pending", "binding.json"} {
					if _, err := os.Stat(filepath.Join(run.root.path, run.id, file)); !os.IsNotExist(err) {
						t.Fatal("failed publish left binding", file, err)
					}
				}
			} else if _, err := os.Stat(filepath.Join(run.root.path, run.id, "binding.pending")); !os.IsNotExist(err) {
				t.Fatal("rollback failed to remove the separately removable pending entry", err)
			}
			run.syncFile = (*os.File).Sync
			run.syncDir = originalSync
			run.afterWrite = nil
			if err := run.close(); err != nil {
				t.Fatal("incomplete marker persistence", err)
			}
			if _, err := os.Stat(filepath.Join(run.root.path, run.id, "incomplete.json")); err != nil {
				t.Fatal("incomplete marker absent", err)
			}
			if slice6VerifyPersistentGuestEvidence(run.root.path, run.id, expected) == nil {
				t.Fatal("failed publication independently accepted")
			}
		})
	}
}

func TestSlice6GuestEvidenceRootRejectsUnsafeInputs(t *testing.T) {
	root := slice6ReceiptTestRoot(t)
	if _, err := slice6OpenReceiptEvidenceRoot(root + "-absent"); err == nil {
		t.Fatal("missing evidence root accepted")
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := slice6OpenReceiptEvidenceRoot(root); err == nil {
		t.Fatal("permissive evidence root accepted")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(root), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := slice6OpenReceiptEvidenceRoot(link); err == nil {
		t.Fatal("symlink evidence root accepted")
	}
	var wrongOwner uint32 = uint32(os.Getuid()) + 1
	opened, err := slice6OpenReceiptEvidenceRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.close()
	copyStat := opened.stat
	copyStat.Uid = wrongOwner
	if slice6PrivateDir(copyStat) {
		t.Fatal("foreign owner evidence root accepted")
	}
}

func TestSlice6GuestEvidenceExclusiveRunAndReplacement(t *testing.T) {
	rootPath := slice6ReceiptTestRoot(t)
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	id := strings.Repeat("a", 32)
	run, err := root.newRun(id)
	if err != nil {
		t.Fatal(err)
	}
	defer run.close()
	if _, err := root.newRun(id); err == nil {
		t.Fatal("duplicate run ID accepted")
	}
	file, err := run.createFile("guest-pid1.stdout")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := run.createFile("guest-pid1.stdout"); err == nil {
		t.Fatal("duplicate raw file accepted")
	}
	rawPath := filepath.Join(rootPath, id, "guest-pid1.stdout")
	if err := os.Rename(rawPath, rawPath+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rawPath, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run.readFile("guest-pid1.stdout", 128<<10); err == nil {
		t.Fatal("replaced raw capture accepted")
	}
	runPath := filepath.Join(rootPath, id)
	if err := os.Rename(runPath, runPath+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(runPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if run.check() == nil || run.writeDocument("binding.json", map[string]string{"fake": "yes"}) == nil {
		t.Fatal("replaced run directory accepted")
	}
}

func TestSlice6GuestEvidenceRootReplacementAndIncomplete(t *testing.T) {
	rootPath := slice6ReceiptTestRoot(t)
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	id := strings.Repeat("b", 32)
	run, err := root.newRun(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := run.close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(rootPath, id, "incomplete.json"))
	if err != nil || !strings.Contains(string(data), `"disposition":"incomplete"`) {
		t.Fatal("failed component run did not retain bounded incomplete marker")
	}
	if _, err := os.Stat(filepath.Join(rootPath, id, "binding.json")); !os.IsNotExist(err) {
		t.Fatal("incomplete component run produced success binding")
	}
	if err := os.Rename(rootPath, rootPath+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	_, createErr := root.newRun(strings.Repeat("c", 32))
	if root.check() == nil || createErr == nil {
		t.Fatal("replaced root accepted")
	}
}
