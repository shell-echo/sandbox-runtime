package product

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"
)

const (
	DevelopmentTemplateID = "coding-shell-base-v1"
	developmentChunkBytes = 32 << 10
)

type DevelopmentToolchain struct {
	ID, Version, Digest, Executable string
}

type DevelopmentMount struct {
	Path, Mode string
}

type DevelopmentTemplate struct {
	ID, Revision, RuntimeProfileID, Image string
	Mounts                                []DevelopmentMount
	Toolchains                            []DevelopmentToolchain
}

func (t DevelopmentTemplate) Validate() error {
	if t.ID != DevelopmentTemplateID || !validDigest(t.Revision) || !validIdentifier(t.RuntimeProfileID) ||
		!validDigestAfterAt(t.Image) || len(t.Mounts) != 4 || len(t.Toolchains) < 1 || len(t.Toolchains) > 16 {
		return ErrInvalid
	}
	wantMounts := []DevelopmentMount{{Path: "/inputs", Mode: "ro"}, {Path: "/workspace", Mode: "rw"}, {Path: "/outputs", Mode: "rw"}, {Path: "/tmp", Mode: "rw"}}
	for index := range wantMounts {
		if t.Mounts[index] != wantMounts[index] {
			return ErrInvalid
		}
	}
	previous := ""
	for _, toolchain := range t.Toolchains {
		if !validIdentifier(toolchain.ID) || !validIdentifier(toolchain.Version) || !validDigest(toolchain.Digest) ||
			len(toolchain.Executable) < 2 || toolchain.Executable[0] != '/' || toolchain.ID <= previous {
			return ErrInvalid
		}
		previous = toolchain.ID
	}
	return nil
}

func validDigestAfterAt(value string) bool {
	for index := len(value) - 1; index >= 0; index-- {
		if value[index] == '@' {
			return index > 0 && validDigest(value[index+1:])
		}
	}
	return false
}

type DevelopmentTemplateCatalog interface {
	Get(context.Context, string) (DevelopmentTemplate, error)
}

type DevelopmentHealth struct {
	Live, Ready                         bool
	TemplateRevision, WorkspaceRevision string
	Mounts                              []DevelopmentMount
	Toolchains                          []DevelopmentToolchain
}

type DevelopmentAuthority struct {
	TenantID, WorkspaceID, SlotKey, GuestID string
	SlotGeneration, BindingGeneration       int64
}

type DevelopmentEnvironment struct {
	ID, TenantID, WorkspaceID, SlotKey, GuestID string
	SlotGeneration, BindingGeneration           int64
	TemplateID, TemplateRevision, RevisionID    string
	State, ErrorCode                            string
	Attempt                                     int
	StartedAt, UpdatedAt                        time.Time
}

type RevisionMaterialization struct {
	RevisionID, ManifestDigest string
	Entries                    []RevisionManifestEntry
}

type StartDevelopmentRequest struct {
	TemplateID, RevisionID string
	StartupTimeoutSeconds  int64
}

type BeginDevelopmentCommand struct {
	TenantID, WorkspaceID, StartupID, IdempotencyKey, Path string
	Actor                                                  ActorRef
	EventID, AuditID                                       string
	RequestDigest                                          [32]byte
	Request                                                StartDevelopmentRequest
	Template                                               DevelopmentTemplate
}

type CompleteDevelopmentCommand struct {
	Environment DevelopmentEnvironment
	Authority   DevelopmentAuthority
	Health      DevelopmentHealth
}

type DevelopmentEnvironmentStore interface {
	BeginDevelopmentEnvironment(context.Context, BeginDevelopmentCommand) (DevelopmentEnvironment, RevisionMaterialization, bool, error)
	GetDevelopmentEnvironment(context.Context, string, ActorRef, string) (DevelopmentEnvironment, RevisionMaterialization, error)
	CompleteDevelopmentEnvironment(context.Context, CompleteDevelopmentCommand) (DevelopmentEnvironment, error)
	FailDevelopmentEnvironment(context.Context, DevelopmentEnvironment, DevelopmentAuthority, string) (DevelopmentEnvironment, error)
}

type DevelopmentGuest interface {
	Health(context.Context, string, string, string) (DevelopmentHealth, DevelopmentAuthority, error)
	Prepare(context.Context, DevelopmentEnvironment, DevelopmentTemplate, RevisionMaterialization) (DevelopmentAuthority, error)
	Write(context.Context, DevelopmentEnvironment, string, int64, []byte) (DevelopmentAuthority, error)
	Commit(context.Context, DevelopmentEnvironment) (DevelopmentHealth, DevelopmentAuthority, error)
	Finalize(context.Context, DevelopmentEnvironment) error
	Rollback(context.Context, DevelopmentEnvironment) error
}

type WorkspaceContentSource interface {
	Open(context.Context, string, string, string, string, int64) (io.ReadCloser, error)
}

type DevelopmentService struct {
	store    DevelopmentEnvironmentStore
	catalog  DevelopmentTemplateCatalog
	guest    DevelopmentGuest
	contents WorkspaceContentSource
	ids      IDGenerator
}

func NewDevelopmentService(store DevelopmentEnvironmentStore, catalog DevelopmentTemplateCatalog, guest DevelopmentGuest, contents WorkspaceContentSource, ids IDGenerator) (*DevelopmentService, error) {
	if nilInterface(store) || nilInterface(catalog) || nilInterface(guest) || nilInterface(contents) || nilInterface(ids) {
		return nil, ErrInvalid
	}
	return &DevelopmentService{store: store, catalog: catalog, guest: guest, contents: contents, ids: ids}, nil
}

func (s *DevelopmentService) Start(ctx context.Context, tenantID string, actor ActorRef, workspaceID, key string, request StartDevelopmentRequest) (DevelopmentEnvironment, bool, error) {
	if s == nil || ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(workspaceID) ||
		!validIdempotencyKey(key) || request.TemplateID != DevelopmentTemplateID ||
		(request.RevisionID != "" && !validIdentifier(request.RevisionID)) || request.StartupTimeoutSeconds < 5 || request.StartupTimeoutSeconds > 600 {
		return DevelopmentEnvironment{}, false, ErrInvalid
	}
	template, err := s.catalog.Get(ctx, request.TemplateID)
	if err != nil || template.Validate() != nil {
		return DevelopmentEnvironment{}, false, ErrCapabilityUnsupported
	}
	startupID, err := s.ids.NewID("dev")
	if err != nil {
		return DevelopmentEnvironment{}, false, ErrStoreUnavailable
	}
	eventID, err := s.ids.NewID("evt")
	if err != nil {
		return DevelopmentEnvironment{}, false, ErrStoreUnavailable
	}
	auditID, err := s.ids.NewID("aud")
	if err != nil {
		return DevelopmentEnvironment{}, false, ErrStoreUnavailable
	}
	encoded, _ := json.Marshal(request)
	digest := sha256.Sum256(encoded)
	environment, materialization, replay, err := s.store.BeginDevelopmentEnvironment(ctx, BeginDevelopmentCommand{
		TenantID: tenantID, WorkspaceID: workspaceID, StartupID: startupID, Actor: actor, EventID: eventID, AuditID: auditID,
		IdempotencyKey: key, Path: "/internal/v1/workspaces/" + workspaceID + "/development-environment", RequestDigest: digest,
		Request: request, Template: template,
	})
	if err != nil || environment.State != "materializing" {
		return environment, replay, err
	}
	startupCtx, cancel := boundedDevelopmentContext(ctx, time.Duration(request.StartupTimeoutSeconds)*time.Second)
	defer cancel()
	result, runErr := s.materialize(startupCtx, environment, template, materialization)
	if runErr == nil {
		return result, replay, nil
	}
	failed, failErr := s.fail(context.WithoutCancel(ctx), environment, runErr)
	return failed, replay, failErr
}

func (s *DevelopmentService) Resume(ctx context.Context, tenantID string, actor ActorRef, startupID string, timeout time.Duration) (DevelopmentEnvironment, error) {
	if s == nil || ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(startupID) || timeout < 5*time.Second || timeout > 10*time.Minute {
		return DevelopmentEnvironment{}, ErrInvalid
	}
	environment, materialization, err := s.store.GetDevelopmentEnvironment(ctx, tenantID, actor, startupID)
	if err != nil || environment.State == "ready" || environment.State == "failed" {
		return environment, err
	}
	template, err := s.catalog.Get(ctx, environment.TemplateID)
	if err != nil || template.Revision != environment.TemplateRevision || template.Validate() != nil {
		return DevelopmentEnvironment{}, ErrCapabilityUnsupported
	}
	startupCtx, cancel := boundedDevelopmentContext(ctx, timeout)
	defer cancel()
	result, runErr := s.materialize(startupCtx, environment, template, materialization)
	if runErr == nil {
		return result, nil
	}
	return s.fail(context.WithoutCancel(ctx), environment, runErr)
}

func (s *DevelopmentService) materialize(ctx context.Context, environment DevelopmentEnvironment, template DevelopmentTemplate, materialization RevisionMaterialization) (DevelopmentEnvironment, error) {
	health, authority, err := s.guest.Health(ctx, environment.TenantID, environment.WorkspaceID, environment.SlotKey)
	if err != nil || !health.Live || !sameDevelopmentAuthority(environment, authority) {
		return DevelopmentEnvironment{}, ErrStoreUnavailable
	}
	if exactDevelopmentHealth(health, template, materialization.RevisionID) {
		return s.complete(ctx, environment, authority, health)
	}
	authority, err = s.guest.Prepare(ctx, environment, template, materialization)
	if err != nil || !sameDevelopmentAuthority(environment, authority) {
		return DevelopmentEnvironment{}, ErrControlStale
	}
	for _, entry := range materialization.Entries {
		if entry.Type != "file" {
			continue
		}
		reader, err := s.contents.Open(ctx, environment.TenantID, environment.WorkspaceID, materialization.RevisionID, entry.Digest, entry.SizeBytes)
		if err != nil {
			return DevelopmentEnvironment{}, ErrStoreUnavailable
		}
		writeErr := s.writeFile(ctx, environment, entry, reader)
		closeErr := reader.Close()
		if writeErr != nil || closeErr != nil {
			return DevelopmentEnvironment{}, errors.Join(writeErr, closeErr)
		}
	}
	health, authority, err = s.guest.Commit(ctx, environment)
	if err != nil || !sameDevelopmentAuthority(environment, authority) || !exactDevelopmentHealth(health, template, materialization.RevisionID) {
		return DevelopmentEnvironment{}, ErrControlStale
	}
	return s.complete(ctx, environment, authority, health)
}

func (s *DevelopmentService) complete(ctx context.Context, environment DevelopmentEnvironment, authority DevelopmentAuthority, health DevelopmentHealth) (DevelopmentEnvironment, error) {
	completed, err := s.store.CompleteDevelopmentEnvironment(ctx, CompleteDevelopmentCommand{Environment: environment, Authority: authority, Health: health})
	if err != nil {
		return DevelopmentEnvironment{}, err
	}
	// The durable Product state is now authoritative. Finalization only removes
	// the Guest's rollback journal; Guest health/restart recovery also converges
	// this cleanup if this bounded best-effort call is interrupted.
	_ = s.guest.Finalize(context.WithoutCancel(ctx), environment)
	return completed, nil
}

func (s *DevelopmentService) fail(ctx context.Context, environment DevelopmentEnvironment, runErr error) (DevelopmentEnvironment, error) {
	rollbackErr := s.guest.Rollback(ctx, environment)
	failed, failErr := s.store.FailDevelopmentEnvironment(ctx, environment, authorityOf(environment), developmentFailureCode(runErr))
	if failErr != nil {
		return environment, errors.Join(runErr, rollbackErr, failErr)
	}
	return failed, errors.Join(runErr, rollbackErr)
}

func (s *DevelopmentService) writeFile(ctx context.Context, environment DevelopmentEnvironment, entry RevisionManifestEntry, reader io.Reader) error {
	hash := sha256.New()
	buffer := make([]byte, developmentChunkBytes)
	var offset int64
	for {
		count, readErr := reader.Read(buffer)
		if count > 0 {
			chunk := append([]byte(nil), buffer[:count]...)
			_, _ = hash.Write(chunk)
			authority, err := s.guest.Write(ctx, environment, entry.Path, offset, chunk)
			if err != nil || !sameDevelopmentAuthority(environment, authority) {
				return ErrControlStale
			}
			offset += int64(count)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return ErrStoreUnavailable
		}
	}
	if offset != entry.SizeBytes || "sha256:"+jsonHex(hash.Sum(nil)) != entry.Digest {
		return ErrInvalid
	}
	return nil
}

func jsonHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2], result[index*2+1] = alphabet[item>>4], alphabet[item&15]
	}
	return string(result)
}

func exactDevelopmentHealth(health DevelopmentHealth, template DevelopmentTemplate, revisionID string) bool {
	if !health.Live || !health.Ready || health.TemplateRevision != template.Revision || health.WorkspaceRevision != revisionID ||
		len(health.Mounts) != len(template.Mounts) || len(health.Toolchains) != len(template.Toolchains) {
		return false
	}
	for index := range template.Mounts {
		if health.Mounts[index] != template.Mounts[index] {
			return false
		}
	}
	for index := range template.Toolchains {
		if health.Toolchains[index] != template.Toolchains[index] {
			return false
		}
	}
	return true
}

func sameDevelopmentAuthority(environment DevelopmentEnvironment, authority DevelopmentAuthority) bool {
	return authority == authorityOf(environment)
}

func authorityOf(environment DevelopmentEnvironment) DevelopmentAuthority {
	return DevelopmentAuthority{TenantID: environment.TenantID, WorkspaceID: environment.WorkspaceID, SlotKey: environment.SlotKey, GuestID: environment.GuestID, SlotGeneration: environment.SlotGeneration, BindingGeneration: environment.BindingGeneration}
}

func boundedDevelopmentContext(parent context.Context, maximum time.Duration) (context.Context, context.CancelFunc) {
	if deadline, ok := parent.Deadline(); ok && time.Until(deadline) <= maximum {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, maximum)
}

func developmentFailureCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "startup_timeout"
	case errors.Is(err, context.Canceled):
		return "startup_cancelled"
	case errors.Is(err, ErrControlStale):
		return "guest_authority_lost"
	case errors.Is(err, ErrInvalid):
		return "workspace_integrity_failed"
	default:
		return "startup_failed"
	}
}

func sortedDevelopmentToolchains(values []DevelopmentToolchain) []DevelopmentToolchain {
	result := append([]DevelopmentToolchain(nil), values...)
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
