package productguest

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	guestdevelopment "github.com/shell-echo/sandbox-runtime/guestagent/development"
	"github.com/shell-echo/sandbox-runtime/product"
)

type DevelopmentClient struct {
	hub     *guestagent.Hub
	timeout time.Duration
}

func NewDevelopmentClient(hub *guestagent.Hub, timeout time.Duration) (*DevelopmentClient, error) {
	if hub == nil || timeout < time.Second || timeout > 30*time.Second {
		return nil, product.ErrInvalid
	}
	return &DevelopmentClient{hub: hub, timeout: timeout}, nil
}

func (c *DevelopmentClient) Health(ctx context.Context, tenantID, workspaceID, slotKey string) (product.DevelopmentHealth, product.DevelopmentAuthority, error) {
	document, identity, err := c.call(ctx, tenantID, workspaceID, slotKey, guestdevelopment.CapabilityHealth, struct{}{})
	if err != nil {
		return product.DevelopmentHealth{}, product.DevelopmentAuthority{}, err
	}
	var response guestdevelopment.HealthResponse
	if guestagent.DecodeStrict(document, &response) != nil {
		return product.DevelopmentHealth{}, product.DevelopmentAuthority{}, product.ErrStoreUnavailable
	}
	health, err := projectDevelopmentHealth(response)
	return health, developmentAuthority(identity), err
}

func (c *DevelopmentClient) Prepare(ctx context.Context, environment product.DevelopmentEnvironment, template product.DevelopmentTemplate, materialization product.RevisionMaterialization) (product.DevelopmentAuthority, error) {
	entries := make([]guestdevelopment.Entry, len(materialization.Entries))
	for index, entry := range materialization.Entries {
		entries[index] = guestdevelopment.Entry{Path: entry.Path, Type: entry.Type, Mode: entry.Mode, SizeBytes: entry.SizeBytes, Digest: entry.Digest}
	}
	request := guestdevelopment.PrepareRequest{StartupID: environment.ID, TemplateRevision: template.Revision, WorkspaceRevision: materialization.RevisionID, ManifestDigest: materialization.ManifestDigest, Entries: entries}
	document, identity, err := c.call(ctx, environment.TenantID, environment.WorkspaceID, environment.SlotKey, guestdevelopment.CapabilityPrepare, request)
	if err != nil {
		return product.DevelopmentAuthority{}, err
	}
	var response struct {
		Prepared bool `json:"prepared"`
	}
	if guestagent.DecodeStrict(document, &response) != nil || !response.Prepared {
		return product.DevelopmentAuthority{}, product.ErrStoreUnavailable
	}
	return developmentAuthority(identity), nil
}

func (c *DevelopmentClient) Write(ctx context.Context, environment product.DevelopmentEnvironment, path string, offset int64, data []byte) (product.DevelopmentAuthority, error) {
	document, identity, err := c.call(ctx, environment.TenantID, environment.WorkspaceID, environment.SlotKey, guestdevelopment.CapabilityWrite, guestdevelopment.WriteRequest{StartupID: environment.ID, Path: path, Offset: offset, Data: append([]byte(nil), data...)})
	if err != nil {
		return product.DevelopmentAuthority{}, err
	}
	var response struct {
		Written int `json:"written"`
	}
	if guestagent.DecodeStrict(document, &response) != nil || response.Written != len(data) {
		return product.DevelopmentAuthority{}, product.ErrStoreUnavailable
	}
	return developmentAuthority(identity), nil
}

func (c *DevelopmentClient) Commit(ctx context.Context, environment product.DevelopmentEnvironment) (product.DevelopmentHealth, product.DevelopmentAuthority, error) {
	document, identity, err := c.call(ctx, environment.TenantID, environment.WorkspaceID, environment.SlotKey, guestdevelopment.CapabilityCommit, guestdevelopment.StartupRequest{StartupID: environment.ID})
	if err != nil {
		return product.DevelopmentHealth{}, product.DevelopmentAuthority{}, err
	}
	var response guestdevelopment.HealthResponse
	if guestagent.DecodeStrict(document, &response) != nil {
		return product.DevelopmentHealth{}, product.DevelopmentAuthority{}, product.ErrStoreUnavailable
	}
	health, err := projectDevelopmentHealth(response)
	return health, developmentAuthority(identity), err
}

func (c *DevelopmentClient) Finalize(ctx context.Context, environment product.DevelopmentEnvironment) error {
	document, _, err := c.call(ctx, environment.TenantID, environment.WorkspaceID, environment.SlotKey, guestdevelopment.CapabilityFinalize, guestdevelopment.StartupRequest{StartupID: environment.ID})
	if err != nil {
		return err
	}
	var response struct {
		Finalized bool `json:"finalized"`
	}
	if guestagent.DecodeStrict(document, &response) != nil || !response.Finalized {
		return product.ErrStoreUnavailable
	}
	return nil
}

func (c *DevelopmentClient) Rollback(ctx context.Context, environment product.DevelopmentEnvironment) error {
	document, _, err := c.call(ctx, environment.TenantID, environment.WorkspaceID, environment.SlotKey, guestdevelopment.CapabilityRollback, guestdevelopment.StartupRequest{StartupID: environment.ID})
	if err != nil {
		return err
	}
	var response struct {
		RolledBack bool `json:"rolled_back"`
	}
	if guestagent.DecodeStrict(document, &response) != nil || !response.RolledBack {
		return product.ErrStoreUnavailable
	}
	return nil
}

func (c *DevelopmentClient) call(ctx context.Context, tenantID, workspaceID, slotKey, capability string, request any) ([]byte, guestagent.Identity, error) {
	callCtx, cancel := bounded(ctx, c.timeout)
	defer cancel()
	document, identity, err := c.hub.CallWithIdentity(callCtx, tenantID, workspaceID, slotKey, capability, request)
	if err != nil {
		return nil, guestagent.Identity{}, developmentCallError(err)
	}
	return document, identity, nil
}

func projectDevelopmentHealth(response guestdevelopment.HealthResponse) (product.DevelopmentHealth, error) {
	health := product.DevelopmentHealth{Live: response.Live, Ready: response.Ready, TemplateRevision: response.TemplateRevision, WorkspaceRevision: response.WorkspaceRevision}
	health.Mounts = make([]product.DevelopmentMount, len(response.Mounts))
	for index, mount := range response.Mounts {
		health.Mounts[index] = product.DevelopmentMount{Path: mount.Path, Mode: mount.Mode}
	}
	health.Toolchains = make([]product.DevelopmentToolchain, len(response.Toolchains))
	for index, toolchain := range response.Toolchains {
		health.Toolchains[index] = product.DevelopmentToolchain{ID: toolchain.ID, Version: toolchain.Version, Digest: toolchain.Digest, Executable: toolchain.Executable}
	}
	if !health.Live || len(health.Mounts) != 4 || len(health.Toolchains) < 1 || len(health.Toolchains) > 16 {
		return product.DevelopmentHealth{}, product.ErrStoreUnavailable
	}
	return health, nil
}

func developmentAuthority(identity guestagent.Identity) product.DevelopmentAuthority {
	return product.DevelopmentAuthority{TenantID: identity.TenantID, WorkspaceID: identity.WorkspaceID, SlotKey: identity.SlotKey, GuestID: identity.GuestID, SlotGeneration: identity.SlotGeneration, BindingGeneration: identity.BindingGeneration}
}

func developmentCallError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, guestagent.ErrCapabilityMissing) {
		return product.ErrCapabilityUnsupported
	}
	if errors.Is(err, guestagent.ErrRemote) {
		return product.ErrControlStale
	}
	return product.ErrStoreUnavailable
}

var _ product.DevelopmentGuest = (*DevelopmentClient)(nil)
