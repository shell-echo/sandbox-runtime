package product

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"
)

func TestDevelopmentServiceMaterializesAndPersistsReady(t *testing.T) {
	content := []byte("hello development\n")
	template := testDevelopmentTemplate()
	environment := testDevelopmentEnvironment(template)
	materialization := RevisionMaterialization{RevisionID: environment.RevisionID, ManifestDigest: testDevelopmentDigest("manifest"), Entries: []RevisionManifestEntry{{Path: "README.md", Type: "file", Mode: 0o640, SizeBytes: int64(len(content)), Digest: testDevelopmentDigest(string(content))}}}
	store := &developmentStoreStub{environment: environment, materialization: materialization}
	guest := &developmentGuestStub{authority: authorityOf(environment), template: template, revisionID: materialization.RevisionID}
	service, err := NewDevelopmentService(store, developmentCatalogStub{template: template}, guest, developmentContentStub{content: content}, &developmentIDs{})
	if err != nil {
		t.Fatal(err)
	}
	result, replay, err := service.Start(context.Background(), environment.TenantID, ActorRef{Type: ActorHuman, ID: "owner"}, environment.WorkspaceID, "development-start", StartDevelopmentRequest{TemplateID: DevelopmentTemplateID, RevisionID: environment.RevisionID, StartupTimeoutSeconds: 5})
	if err != nil || replay || result.State != "ready" || store.completed != 1 || guest.prepared != 1 || guest.committed != 1 || guest.finalized != 1 || guest.rolledBack != 0 {
		t.Fatalf("result=%+v replay=%v err=%v store=%+v guest=%+v", result, replay, err, store, guest)
	}
	if !bytes.Equal(guest.written, content) {
		t.Fatalf("written=%q want=%q", guest.written, content)
	}
}

func TestDevelopmentServiceFailsClosedAndRollsBackDigestMismatch(t *testing.T) {
	template := testDevelopmentTemplate()
	environment := testDevelopmentEnvironment(template)
	materialization := RevisionMaterialization{RevisionID: environment.RevisionID, ManifestDigest: testDevelopmentDigest("manifest"), Entries: []RevisionManifestEntry{{Path: "main.go", Type: "file", Mode: 0o600, SizeBytes: 4, Digest: testDevelopmentDigest("good")}}}
	store := &developmentStoreStub{environment: environment, materialization: materialization}
	guest := &developmentGuestStub{authority: authorityOf(environment), template: template, revisionID: materialization.RevisionID}
	service, _ := NewDevelopmentService(store, developmentCatalogStub{template: template}, guest, developmentContentStub{content: []byte("evil")}, &developmentIDs{})
	result, _, err := service.Start(context.Background(), environment.TenantID, ActorRef{Type: ActorHuman, ID: "owner"}, environment.WorkspaceID, "development-fail", StartDevelopmentRequest{TemplateID: DevelopmentTemplateID, RevisionID: environment.RevisionID, StartupTimeoutSeconds: 5})
	if !errors.Is(err, ErrInvalid) || result.State != "failed" || result.ErrorCode != "workspace_integrity_failed" || guest.rolledBack != 1 || store.failed != 1 || store.completed != 0 {
		t.Fatalf("result=%+v err=%v store=%+v guest=%+v", result, err, store, guest)
	}
}

func TestDevelopmentServiceRollsBackWhenReadyPersistenceFails(t *testing.T) {
	template := testDevelopmentTemplate()
	environment := testDevelopmentEnvironment(template)
	materialization := RevisionMaterialization{RevisionID: environment.RevisionID, ManifestDigest: testDevelopmentDigest("manifest")}
	store := &developmentStoreStub{environment: environment, materialization: materialization, completeErr: ErrStoreUnavailable}
	guest := &developmentGuestStub{authority: authorityOf(environment), template: template, revisionID: materialization.RevisionID}
	service, _ := NewDevelopmentService(store, developmentCatalogStub{template: template}, guest, developmentContentStub{}, &developmentIDs{})
	result, _, err := service.Start(context.Background(), environment.TenantID, ActorRef{Type: ActorHuman, ID: "owner"}, environment.WorkspaceID, "development-store-fail", StartDevelopmentRequest{TemplateID: DevelopmentTemplateID, RevisionID: environment.RevisionID, StartupTimeoutSeconds: 5})
	if !errors.Is(err, ErrStoreUnavailable) || result.State != "failed" || store.completed != 1 || store.failed != 1 || guest.committed != 1 || guest.rolledBack != 1 || guest.finalized != 0 {
		t.Fatalf("result=%+v err=%v store=%+v guest=%+v", result, err, store, guest)
	}
}

func testDevelopmentTemplate() DevelopmentTemplate {
	return DevelopmentTemplate{
		ID: DevelopmentTemplateID, Revision: testDevelopmentDigest("template"), RuntimeProfileID: "sandbox-runtime-coding-shell-v1",
		Image:      "ghcr.io/example/coding-shell@" + testDevelopmentDigest("image"),
		Mounts:     []DevelopmentMount{{Path: "/inputs", Mode: "ro"}, {Path: "/workspace", Mode: "rw"}, {Path: "/outputs", Mode: "rw"}, {Path: "/tmp", Mode: "rw"}},
		Toolchains: []DevelopmentToolchain{{ID: "posix-shell", Version: "test-1", Digest: testDevelopmentDigest("toolchain"), Executable: "/bin/sh"}},
	}
}

func testDevelopmentEnvironment(template DevelopmentTemplate) DevelopmentEnvironment {
	return DevelopmentEnvironment{ID: "dev-test", TenantID: "tenant-test", WorkspaceID: "wrk-test", SlotKey: PrimarySlotKey, GuestID: "gst-test", SlotGeneration: 1, BindingGeneration: 2, TemplateID: template.ID, TemplateRevision: template.Revision, RevisionID: "rev-test", State: "materializing", Attempt: 1, StartedAt: time.Now(), UpdatedAt: time.Now()}
}

func testDevelopmentDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

type developmentCatalogStub struct{ template DevelopmentTemplate }

func (s developmentCatalogStub) Get(context.Context, string) (DevelopmentTemplate, error) {
	return s.template, nil
}

type developmentStoreStub struct {
	environment       DevelopmentEnvironment
	materialization   RevisionMaterialization
	completed, failed int
	completeErr       error
}

func (s *developmentStoreStub) BeginDevelopmentEnvironment(context.Context, BeginDevelopmentCommand) (DevelopmentEnvironment, RevisionMaterialization, bool, error) {
	return s.environment, s.materialization, false, nil
}
func (s *developmentStoreStub) GetDevelopmentEnvironment(context.Context, string, ActorRef, string) (DevelopmentEnvironment, RevisionMaterialization, error) {
	return s.environment, s.materialization, nil
}
func (s *developmentStoreStub) CompleteDevelopmentEnvironment(_ context.Context, command CompleteDevelopmentCommand) (DevelopmentEnvironment, error) {
	s.completed++
	if s.completeErr != nil {
		return DevelopmentEnvironment{}, s.completeErr
	}
	command.Environment.State = "ready"
	return command.Environment, nil
}
func (s *developmentStoreStub) FailDevelopmentEnvironment(_ context.Context, environment DevelopmentEnvironment, _ DevelopmentAuthority, code string) (DevelopmentEnvironment, error) {
	s.failed++
	environment.State, environment.ErrorCode = "failed", code
	return environment, nil
}

type developmentGuestStub struct {
	authority                                  DevelopmentAuthority
	template                                   DevelopmentTemplate
	revisionID                                 string
	prepared, committed, finalized, rolledBack int
	written                                    []byte
}

func (s *developmentGuestStub) Health(context.Context, string, string, string) (DevelopmentHealth, DevelopmentAuthority, error) {
	return DevelopmentHealth{Live: true, Mounts: s.template.Mounts, Toolchains: s.template.Toolchains}, s.authority, nil
}
func (s *developmentGuestStub) Prepare(context.Context, DevelopmentEnvironment, DevelopmentTemplate, RevisionMaterialization) (DevelopmentAuthority, error) {
	s.prepared++
	return s.authority, nil
}
func (s *developmentGuestStub) Write(_ context.Context, _ DevelopmentEnvironment, _ string, offset int64, data []byte) (DevelopmentAuthority, error) {
	if int64(len(s.written)) != offset {
		return DevelopmentAuthority{}, ErrControlStale
	}
	s.written = append(s.written, data...)
	return s.authority, nil
}
func (s *developmentGuestStub) Commit(context.Context, DevelopmentEnvironment) (DevelopmentHealth, DevelopmentAuthority, error) {
	s.committed++
	return DevelopmentHealth{Live: true, Ready: true, TemplateRevision: s.template.Revision, WorkspaceRevision: s.revisionID, Mounts: s.template.Mounts, Toolchains: s.template.Toolchains}, s.authority, nil
}
func (s *developmentGuestStub) Finalize(context.Context, DevelopmentEnvironment) error {
	s.finalized++
	return nil
}
func (s *developmentGuestStub) Rollback(context.Context, DevelopmentEnvironment) error {
	s.rolledBack++
	return nil
}

type developmentContentStub struct{ content []byte }

func (s developmentContentStub) Open(context.Context, string, string, string, string, int64) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.content)), nil
}

type developmentIDs struct{ next int }

func (s *developmentIDs) NewID(prefix string) (string, error) {
	s.next++
	return prefix + "-generated", nil
}
