package productpostgres

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/product"
	productgateway "github.com/shell-echo/sandbox-runtime/product/adapter/gateway"
)

const maxBrowserHandoffBindingsPerSession = 64

var browserBindingKeyName = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
var browserBindingKeyVersion = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var browserBindingSessionID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)

// BrowserHandoffBindingSelection is a pre-derived, non-secret Product
// projection. The caller resolves the exact dedicated key outside SQL locks;
// this store never reads Vault or holds key bytes.
type BrowserHandoffBindingSelection struct {
	ProductSessionID    string
	Input               productgateway.BrowserTenantBindingInput
	KeyBindingID        string
	KeyVersion          string
	KeyBinding          secretref.Binding
	KeyBindingDigest    string
	TenantBindingDigest string
	HandoffExpiresAt    time.Time
}

// BrowserHandoffBindingPreparer resolves the exact caller secret outside the
// Provider-observation transaction and returns only bounded non-secret data.
type BrowserHandoffBindingPreparer interface {
	PrepareBrowserHandoffBinding(context.Context, product.ProviderObservationWork, product.ProviderOperationEvidence) (BrowserHandoffBindingSelection, error)
}

func NewWithBrowserHandoffBinding(pool *pgxpool.Pool, operationTimeout time.Duration, preparer BrowserHandoffBindingPreparer) (*Store, error) {
	if preparer == nil {
		return nil, product.ErrInvalid
	}
	store, err := New(pool, operationTimeout)
	if err != nil {
		return nil, err
	}
	store.browserBindingPreparer = preparer
	return store, nil
}

func (s BrowserHandoffBindingSelection) Validate() error {
	if !browserBindingSessionID.MatchString(s.ProductSessionID) || s.Input.Validate() != nil ||
		!browserBindingKeyName.MatchString(s.KeyBindingID) ||
		!browserBindingKeyVersion.MatchString(s.KeyVersion) ||
		s.KeyBinding.Validate() != nil || s.KeyBinding.Kind != secretref.KindSecret ||
		s.KeyBinding.Purpose != secretref.PurposeBrowserTenantBindingKey ||
		s.KeyBinding.TenantID != secretref.SystemTenant ||
		(s.KeyBinding.Role != secretref.RoleProduct && s.KeyBinding.Role != secretref.RoleGateway) ||
		s.KeyBinding.Version != s.KeyVersion || s.KeyBinding.Digest() != s.KeyBindingDigest ||
		browserbinding.ValidateDigest(s.TenantBindingDigest) != nil || s.HandoffExpiresAt.IsZero() {
		return product.ErrInvalid
	}
	return nil
}

// CurrentBrowserHandoffBinding requires both the immutable v2 row and the
// sole current Product/Provider pointers. A missing row is never repaired or
// silently derived from a newer active key here.
func (s *Store) CurrentBrowserHandoffBinding(ctx context.Context, tenantID, productSessionID, providerAudience string) (BrowserHandoffBindingSelection, error) {
	if s == nil || s.pool == nil || ctx == nil || !browserBindingSessionID.MatchString(tenantID) ||
		!browserBindingSessionID.MatchString(productSessionID) || !browserBindingSessionID.MatchString(providerAudience) {
		return BrowserHandoffBindingSelection{}, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	var selected BrowserHandoffBindingSelection
	selected.ProductSessionID = productSessionID
	selected.Input.TenantID = tenantID
	selected.Input.ProviderInstanceAudience = providerAudience
	selected.KeyBinding.Schema = secretref.BindingSchema
	selected.KeyBinding.Kind = secretref.KindSecret
	selected.KeyBinding.TenantID = secretref.SystemTenant
	var keyReference, keyPurpose, keyRole string
	err := s.pool.QueryRow(opCtx, `SELECT m.handoff_reference,m.caller_authority_scope,m.key_binding_id,m.key_version,
m.key_reference,m.key_purpose,m.key_role,m.key_binding_digest,
m.provider_revision_id,m.sandbox_id,m.browser_session_id,m.capability_profile_id,
m.connection_generation,m.tenant_binding_digest,m.handoff_expires_at
FROM sandbox_runtime_product.runtime_sessions s
JOIN sandbox_runtime_product.provider_bindings b ON b.tenant_id=s.tenant_id
 AND b.workspace_id=s.workspace_id AND b.slot_key=s.slot_key
 AND b.slot_generation=s.slot_generation AND b.current
JOIN sandbox_runtime_product.browser_handoff_binding_metadata m
 ON m.tenant_id=s.tenant_id AND m.product_session_id=s.session_id
 AND m.provider_instance_audience=$3 AND m.handoff_reference=s.provider_handoff_reference
 AND m.connection_generation=s.provider_connection_generation
 AND m.handoff_expires_at=s.provider_handoff_expires_at
 AND m.provider_revision_id=b.provider_revision_id AND m.sandbox_id=b.sandbox_id
 AND m.browser_session_id=s.provider_runtime_session_id
WHERE s.tenant_id=$1 AND s.session_id=$2 AND s.kind IN('browser_automation','browser_live')
 AND s.provider_runtime_session_id=s.session_id
 AND s.state IN('ready','active') AND s.provider_handoff_expires_at>clock_timestamp()`,
		tenantID, productSessionID, providerAudience).Scan(&selected.Input.HandoffReference,
		&selected.Input.CallerAuthorityScope, &selected.KeyBindingID, &selected.KeyVersion,
		&keyReference, &keyPurpose, &keyRole,
		&selected.KeyBindingDigest,
		&selected.Input.ProviderRevisionID, &selected.Input.SandboxID, &selected.Input.BrowserSessionID,
		&selected.Input.CapabilityProfileID, &selected.Input.ConnectionGeneration,
		&selected.TenantBindingDigest, &selected.HandoffExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return BrowserHandoffBindingSelection{}, product.ErrControlStale
	}
	if err != nil {
		return BrowserHandoffBindingSelection{}, storeError(ctx, opCtx, err, false)
	}
	selected.KeyBinding.Reference = secretref.Reference(keyReference)
	selected.KeyBinding.Version = selected.KeyVersion
	selected.KeyBinding.Purpose = secretref.Purpose(keyPurpose)
	selected.KeyBinding.Role = secretref.Role(keyRole)
	if selected.Validate() != nil {
		return BrowserHandoffBindingSelection{}, product.ErrControlStale
	}
	return selected, nil
}

// The caller holds the matching Product session row lock. This helper never
// resolves material and never changes an existing immutable selection.
func insertBrowserHandoffMetadata(ctx context.Context, tx pgx.Tx, selection BrowserHandoffBindingSelection, now time.Time) error {
	var count int
	var alreadyBound bool
	if err := tx.QueryRow(ctx, `SELECT count(*),COALESCE(bool_or(provider_instance_audience=$3 AND handoff_reference=$4),false)
FROM sandbox_runtime_product.browser_handoff_binding_metadata
WHERE tenant_id=$1 AND product_session_id=$2`, selection.Input.TenantID, selection.ProductSessionID,
		selection.Input.ProviderInstanceAudience, selection.Input.HandoffReference).Scan(&count, &alreadyBound); err != nil {
		return err
	}
	if !alreadyBound && count >= maxBrowserHandoffBindingsPerSession {
		return product.ErrQuotaExceeded
	}
	_, err := tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.browser_handoff_binding_metadata
(tenant_id,product_session_id,provider_instance_audience,handoff_reference,caller_authority_scope,
 key_binding_id,key_version,key_reference,key_purpose,key_role,key_binding_digest,
 provider_revision_id,sandbox_id,browser_session_id,capability_profile_id,
 connection_generation,tenant_binding_digest,handoff_expires_at,created_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
ON CONFLICT(tenant_id,product_session_id,provider_instance_audience,handoff_reference) DO NOTHING`,
		selection.Input.TenantID, selection.ProductSessionID, selection.Input.ProviderInstanceAudience,
		selection.Input.HandoffReference, selection.Input.CallerAuthorityScope, selection.KeyBindingID,
		selection.KeyVersion, string(selection.KeyBinding.Reference), string(selection.KeyBinding.Purpose),
		string(selection.KeyBinding.Role), selection.KeyBindingDigest,
		selection.Input.ProviderRevisionID, selection.Input.SandboxID,
		selection.Input.BrowserSessionID, selection.Input.CapabilityProfileID,
		selection.Input.ConnectionGeneration, selection.TenantBindingDigest, selection.HandoffExpiresAt, now)
	if err != nil {
		return err
	}
	var committed BrowserHandoffBindingSelection
	committed.Input = selection.Input
	var keyReference, keyPurpose, keyRole string
	err = tx.QueryRow(ctx, `SELECT caller_authority_scope,key_binding_id,key_version,
key_reference,key_purpose,key_role,key_binding_digest,provider_revision_id,
sandbox_id,browser_session_id,capability_profile_id,connection_generation,tenant_binding_digest,handoff_expires_at
FROM sandbox_runtime_product.browser_handoff_binding_metadata
WHERE tenant_id=$1 AND product_session_id=$2 AND provider_instance_audience=$3 AND handoff_reference=$4`,
		selection.Input.TenantID, selection.ProductSessionID, selection.Input.ProviderInstanceAudience,
		selection.Input.HandoffReference).Scan(&committed.Input.CallerAuthorityScope, &committed.KeyBindingID,
		&committed.KeyVersion, &keyReference, &keyPurpose,
		&keyRole, &committed.KeyBindingDigest,
		&committed.Input.ProviderRevisionID, &committed.Input.SandboxID,
		&committed.Input.BrowserSessionID, &committed.Input.CapabilityProfileID,
		&committed.Input.ConnectionGeneration, &committed.TenantBindingDigest, &committed.HandoffExpiresAt)
	if err != nil {
		return err
	}
	committed.KeyBinding.Reference = secretref.Reference(keyReference)
	committed.KeyBinding.Purpose = secretref.Purpose(keyPurpose)
	committed.KeyBinding.Role = secretref.Role(keyRole)
	if committed.Input.CallerAuthorityScope != selection.Input.CallerAuthorityScope ||
		committed.KeyBindingID != selection.KeyBindingID || committed.KeyVersion != selection.KeyVersion ||
		committed.KeyBinding.Reference != selection.KeyBinding.Reference ||
		committed.KeyBinding.Purpose != selection.KeyBinding.Purpose ||
		committed.KeyBinding.Role != selection.KeyBinding.Role ||
		committed.KeyBindingDigest != selection.KeyBindingDigest ||
		committed.Input.ProviderRevisionID != selection.Input.ProviderRevisionID ||
		committed.Input.SandboxID != selection.Input.SandboxID ||
		committed.Input.BrowserSessionID != selection.Input.BrowserSessionID ||
		committed.Input.CapabilityProfileID != selection.Input.CapabilityProfileID ||
		committed.Input.ConnectionGeneration != selection.Input.ConnectionGeneration ||
		committed.TenantBindingDigest != selection.TenantBindingDigest ||
		!committed.HandoffExpiresAt.Equal(selection.HandoffExpiresAt) {
		return product.ErrControlConflict
	}
	return nil
}
