//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
	"github.com/shell-echo/sandbox-runtime/internal/phase6profilebuilder"
	"github.com/shell-echo/sandbox-runtime/internal/phase6rolecandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"golang.org/x/sys/unix"
)

func TestSlice6ReceiptFrozenCoreArtifactNoIssuer(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_RECEIPT_FROZEN_CORE_NO_ISSUER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_RECEIPT_FROZEN_CORE_NO_ISSUER=1 for source-bound core mapping")
	}
	static := slice6VaultStaticInputsFromEnvironment()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	images, err := phase6profilebuilder.LoadImageSupply(ctx, static.sourceRoot, static.sourceRevision,
		static.roleCandidates, static.desktopCandidate, static.browserArchive)
	if err != nil {
		t.Fatal("frozen source-bound image supply unavailable")
	}
	core, ok := images.LocalRoleTargets["core"]
	if !ok || core.Kind != phase6security.ImageIdentityOCIManifest ||
		core.SelectedManifestDigest != "" {
		t.Fatal("frozen core is not the reviewed single-manifest candidate")
	}
	artifact, err := slice6ReceiptRoleArtifact(images, core.Digest)
	if err != nil || artifact.ImageID != core.Digest || artifact.SelectedManifestDigest != core.Digest ||
		artifact.ConfigDigest != core.ConfigDigest {
		t.Fatal("receipt evidence rejected the frozen single-manifest core mapping")
	}
}

func TestSlice6ReceiptRoleArtifactKindAndIdentityMapping(t *testing.T) {
	digest := func(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }
	root, child, config := digest("1"), digest("2"), digest("3")
	revision, tree := strings.Repeat("a", 40), digest("b")
	base := func(kind string) phase6profilebuilder.ImageSupply {
		selected := ""
		manifest := root
		if kind == phase6security.ImageIdentityOCIIndex {
			selected, manifest = child, child
		}
		return phase6profilebuilder.ImageSupply{RuntimeRevision: revision,
			RuntimeTreeDigest: tree, Platform: "linux/arm64/v8",
			LocalRoleTargets: map[string]phase6profilebuilder.ImageBinding{"core": {
				Reference: root, Digest: root, Location: "local", Kind: kind,
				Platform: "linux/arm64/v8", SelectedManifestDigest: selected, ConfigDigest: config,
			}},
			RoleArtifacts: []phase6rolecandidate.VerifiedArtifact{{Manifest: phase6rolecandidate.Manifest{
				Source: phase6rolecandidate.SourceInputs{BuildTarget: "core", Platform: "linux/arm64/v8",
					SourceRevision: revision, SourceTreeDigest: tree},
				ImageIdentityKind: kind, RuntimeStoreImageID: root,
				RuntimeStoreDescriptor:     phase6security.ImageDescriptor{Digest: root},
				SelectedManifestDescriptor: phase6security.ImageDescriptor{Digest: manifest},
				OCIConfigDigest:            config, ManifestDigest: digest("4"), ArchiveDigest: digest("5"),
			}}},
		}
	}
	for _, kind := range []string{phase6security.ImageIdentityOCIManifest, phase6security.ImageIdentityOCIIndex} {
		t.Run(kind, func(t *testing.T) {
			images := base(kind)
			artifact, err := slice6ReceiptRoleArtifact(images, root)
			wantSelected := root
			if kind == phase6security.ImageIdentityOCIIndex {
				wantSelected = child
			}
			if err != nil || artifact.ImageID != root || artifact.SelectedManifestDigest != wantSelected ||
				artifact.ConfigDigest != config {
				t.Fatal("canonical role artifact mapping rejected or selected the wrong manifest")
			}
		})
	}
	for _, test := range []struct {
		name  string
		kind  string
		image string
		alter func(*phase6profilebuilder.ImageSupply)
	}{
		{"wrong actual image", phase6security.ImageIdentityOCIManifest, child, func(*phase6profilebuilder.ImageSupply) {}},
		{"manifest with index child", phase6security.ImageIdentityOCIManifest, root, func(s *phase6profilebuilder.ImageSupply) {
			binding := s.LocalRoleTargets["core"]
			binding.SelectedManifestDigest = child
			s.LocalRoleTargets["core"] = binding
		}},
		{"index missing child", phase6security.ImageIdentityOCIIndex, root, func(s *phase6profilebuilder.ImageSupply) {
			binding := s.LocalRoleTargets["core"]
			binding.SelectedManifestDigest = ""
			s.LocalRoleTargets["core"] = binding
		}},
		{"index child is root", phase6security.ImageIdentityOCIIndex, root, func(s *phase6profilebuilder.ImageSupply) {
			binding := s.LocalRoleTargets["core"]
			binding.SelectedManifestDigest = root
			s.LocalRoleTargets["core"] = binding
		}},
		{"index child mismatch", phase6security.ImageIdentityOCIIndex, root, func(s *phase6profilebuilder.ImageSupply) {
			binding := s.LocalRoleTargets["core"]
			binding.SelectedManifestDigest = digest("6")
			s.LocalRoleTargets["core"] = binding
		}},
		{"candidate kind mismatch", phase6security.ImageIdentityOCIIndex, root, func(s *phase6profilebuilder.ImageSupply) {
			s.RoleArtifacts[0].Manifest.ImageIdentityKind = phase6security.ImageIdentityOCIManifest
		}},
		{"unknown binding kind", phase6security.ImageIdentityOCIManifest, root, func(s *phase6profilebuilder.ImageSupply) {
			binding := s.LocalRoleTargets["core"]
			binding.Kind = "unknown"
			s.LocalRoleTargets["core"] = binding
		}},
		{"candidate root mismatch", phase6security.ImageIdentityOCIManifest, root, func(s *phase6profilebuilder.ImageSupply) {
			s.RoleArtifacts[0].Manifest.RuntimeStoreImageID = child
		}},
		{"root descriptor mismatch", phase6security.ImageIdentityOCIManifest, root, func(s *phase6profilebuilder.ImageSupply) {
			s.RoleArtifacts[0].Manifest.RuntimeStoreDescriptor.Digest = child
		}},
		{"config mismatch", phase6security.ImageIdentityOCIManifest, root, func(s *phase6profilebuilder.ImageSupply) {
			s.RoleArtifacts[0].Manifest.OCIConfigDigest = child
		}},
		{"source revision mismatch", phase6security.ImageIdentityOCIManifest, root, func(s *phase6profilebuilder.ImageSupply) {
			s.RoleArtifacts[0].Manifest.Source.SourceRevision = strings.Repeat("c", 40)
		}},
		{"source tree mismatch", phase6security.ImageIdentityOCIManifest, root, func(s *phase6profilebuilder.ImageSupply) {
			s.RoleArtifacts[0].Manifest.Source.SourceTreeDigest = digest("d")
		}},
		{"candidate selected mismatch", phase6security.ImageIdentityOCIManifest, root, func(s *phase6profilebuilder.ImageSupply) {
			s.RoleArtifacts[0].Manifest.SelectedManifestDescriptor.Digest = child
		}},
		{"binding reference mismatch", phase6security.ImageIdentityOCIManifest, root, func(s *phase6profilebuilder.ImageSupply) {
			binding := s.LocalRoleTargets["core"]
			binding.Reference = child
			s.LocalRoleTargets["core"] = binding
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			images := base(test.kind)
			test.alter(&images)
			if _, err := slice6ReceiptRoleArtifact(images, test.image); !errors.Is(err, errSlice6ReceiptEvidence) {
				t.Fatal("drifted candidate, descriptor or running-image identity was accepted")
			}
		})
	}
}

// This uses source-verified image identities but deliberately synthetic PID1
// streams, container IDs and mutation facts. It exercises the complete E-only
// evidence publication path without Docker, PostgreSQL or a Vault issuer.
func TestSlice6GuestReceiptFinishFixtureNoIssuer(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_RECEIPT_FINISH_FIXTURE_NO_ISSUER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_RECEIPT_FINISH_FIXTURE_NO_ISSUER=1 for private finish fixture")
	}
	static := slice6VaultStaticInputsFromEnvironment()
	fixtureRoot := os.Getenv(slice6GuestFixtureSourceRootEnv)
	fixtureRevision := os.Getenv(slice6GuestFixtureSourceRevisionEnv)
	eRevision := os.Getenv(slice6ProductObserverRevisionEnv)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	if slice6VerifyGuestFixtureSourcePair(ctx, static.sourceRoot, static.sourceRevision,
		fixtureRoot, fixtureRevision) != nil {
		t.Fatal("reviewed R/F source pair unavailable for synthetic finish fixture")
	}
	images, err := phase6profilebuilder.LoadImageSupply(ctx, static.sourceRoot, static.sourceRevision,
		static.roleCandidates, static.desktopCandidate, static.browserArchive)
	if err != nil {
		t.Fatal("reviewed candidate identity supply unavailable for synthetic finish fixture")
	}
	core, ok := images.LocalRoleTargets["core"]
	if !ok || core.Kind != phase6security.ImageIdentityOCIManifest {
		t.Fatal("reviewed core candidate kind unavailable")
	}
	rootPath := slice6ReceiptTestRoot(t)
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	run, err := root.newRun(strings.Repeat("c", 32))
	if err != nil {
		t.Fatal(err)
	}
	defer run.close()
	profile := "sha256:" + strings.Repeat("9", 64)
	verifiedAt := time.Now().UTC()
	productID, guestID := strings.Repeat("6", 64), strings.Repeat("7", 64)
	productConfig, guestConfig := "sha256:"+strings.Repeat("8", 64), "sha256:"+strings.Repeat("5", 64)
	for _, item := range []struct {
		role, config, container string
		exitCode                int
	}{
		{"product", productConfig, productID, 0},
		{"guest", guestConfig, guestID, 1},
	} {
		document := slice6ReceiptTestStream(t, item.role, profile, item.config)
		file, err := run.createFile(slice6ReceiptRawName(item.role))
		if err != nil {
			t.Fatal(err)
		}
		bounded := &slice6ReceiptBoundedFile{file: file}
		n, writeErr := bounded.Write(document)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || n != len(document) || bounded.overflow || syncErr != nil || closeErr != nil {
			t.Fatal("synthetic PID1 fixture did not pass bounded collector storage")
		}
		if _, err := phase6guestreceipt.Verify(document, item.role, profile, item.config); err != nil {
			t.Fatal("synthetic PID1 fixture raw stream rejected")
		}
		if err := run.recordRaw(slice6ReceiptRawBinding{Role: item.role,
			File: slice6ReceiptRawName(item.role), SHA256: slice6ReceiptSHA256(document),
			Bytes: len(document), ProfileDigest: profile, ConfigDigest: item.config,
			SelectedImage: core.Digest, ActualImage: core.Digest,
			ContainerID: item.container, DockerExitCode: item.exitCode,
			CaptureStartUTC:  verifiedAt.Add(-time.Second).Format(time.RFC3339Nano),
			CaptureFinishUTC: verifiedAt.Add(time.Second).Format(time.RFC3339Nano)}); err != nil {
			t.Fatal("synthetic PID1 fixture collector record rejected")
		}
	}
	mutation := slice6GuestRevokeFixtureReceipt{Protocol: slice6GuestRevokeFixtureProtocol,
		RunID: run.id, ProfileDigest: profile, ProductContainerID: productID,
		BindingGeneration: 1, MutationOutcome: "confirmed", BeforeConnected: true,
		AfterRevoked: true, NonceCleared: true}
	if err := slice6FinishGuestReceiptEvidence(ctx, run, static, images,
		slice6GuestBindingFixtureArtifact{SourceRevision: fixtureRevision},
		profile, mutation, verifiedAt, productID, guestID); err != nil {
		t.Fatalf("synthetic finish fixture rejected source-bound evidence wiring: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rootPath, run.id, "mutation-receipt.json")); err != nil {
		t.Fatal("synthetic mutation receipt was not persisted")
	}
	if _, err := os.Stat(filepath.Join(rootPath, run.id, "binding.json")); err != nil {
		t.Fatal("synthetic source/image/stream binding was not published")
	}
	if err := run.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(rootPath, run.id, "incomplete.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("completed synthetic fixture retained an incomplete marker")
	}
	eRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	eTree, eErr := desktopcandidate.SourceTreeDigestAtRevision(eRoot, eRevision)
	fTree, fErr := desktopcandidate.SourceTreeDigestAtRevision(fixtureRoot, fixtureRevision)
	artifact, artifactErr := slice6ReceiptRoleArtifact(images, core.Digest)
	if eErr != nil || fErr != nil || artifactErr != nil {
		t.Fatal("independent synthetic identity expectations unavailable")
	}
	expected := slice6ReceiptExpectedIdentity{ERevision: eRevision, ETree: eTree,
		RRevision: images.RuntimeRevision, RTree: images.RuntimeTreeDigest,
		FRevision: fixtureRevision, FTree: fTree, ProfileDigest: profile,
		ProductConfigDigest: productConfig, GuestConfigDigest: guestConfig,
		ProductArtifact: artifact, GuestArtifact: artifact,
		ProductContainerID: productID, GuestContainerID: guestID,
		ProductImageID: core.Digest, GuestImageID: core.Digest}
	if err := slice6VerifyPersistentGuestEvidence(rootPath, run.id, expected); err != nil {
		t.Fatal("independent synthetic reader rejected persisted source/image/stream binding")
	}
	bad := expected
	bad.ProductImageID = "sha256:" + strings.Repeat("0", 64)
	if slice6VerifyPersistentGuestEvidence(rootPath, run.id, bad) == nil {
		t.Fatal("independent synthetic reader accepted an actual image mismatch")
	}
	incomplete, err := root.newRun(strings.Repeat("d", 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := incomplete.close(); err != nil {
		t.Fatal(err)
	}
	if slice6VerifyPersistentGuestEvidence(rootPath, incomplete.id, expected) == nil {
		t.Fatal("independent synthetic reader accepted an incomplete run")
	}
	t.Log("synthetic no-issuer fixture only: two bounded streams, source-bound artifact map, mutation publication and independent reread passed; no live Docker/PG claim")
}

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
