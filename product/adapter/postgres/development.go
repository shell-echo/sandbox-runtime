package productpostgres

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shell-echo/sandbox-runtime/product"
)

const emptyWorkspaceManifestDigest = "sha256:d801aa1fb7ddcc330a5e3173372ea6af4a3d08ec58074478e85aa5603e926658"

var developmentCapabilities = []string{
	"development.health", "workspace.materialize.commit", "workspace.materialize.finalize", "workspace.materialize.prepare", "workspace.materialize.rollback", "workspace.materialize.write",
}

func (s *Store) BeginDevelopmentEnvironment(ctx context.Context, command product.BeginDevelopmentCommand) (product.DevelopmentEnvironment, product.RevisionMaterialization, bool, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, false, product.ErrStoreUnavailable
	}
	defer rollbackBounded(tx, s.operationTimeout)
	var now time.Time
	if err := tx.QueryRow(opCtx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, false, product.ErrStoreUnavailable
	}
	tag, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.mutation_idempotency(tenant_id,actor_type,actor_id,method,normalized_path,idempotency_key,request_digest,result_type,result_id,created_at,expires_at)VALUES($1,$2,$3,'POST',$4,$5,$6,'development_environment',$7,$8,$9)ON CONFLICT DO NOTHING`, command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey, command.RequestDigest[:], command.StartupID, now, now.Add(idempotencyRetention))
	if err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, false, product.ErrStoreUnavailable
	}
	if tag.RowsAffected() == 0 {
		environment, materialization, err := loadRetainedDevelopment(opCtx, tx, command)
		return environment, materialization, true, err
	}
	var slotGeneration, bindingGeneration int64
	var guestID string
	var capabilities []byte
	err = tx.QueryRow(opCtx, `SELECT s.generation,g.guest_id,g.binding_generation,g.capabilities
FROM sandbox_runtime_product.workspaces w
JOIN sandbox_runtime_product.workspace_slots s ON s.tenant_id=w.tenant_id AND s.workspace_id=w.workspace_id AND s.slot_key='primary-code'
JOIN sandbox_runtime_product.guest_bindings g ON g.tenant_id=s.tenant_id AND g.workspace_id=s.workspace_id AND g.slot_key=s.slot_key AND g.slot_generation=s.generation
WHERE w.tenant_id=$1 AND w.workspace_id=$2 AND w.owner_actor_type=$3 AND w.owner_actor_id=$4
  AND w.desired_state='active' AND s.kind='code' AND s.desired_state='ready' AND s.observed_state='ready'
  AND g.state='connected' AND g.expires_at>clock_timestamp()
FOR UPDATE OF w,s,g`, command.TenantID, command.WorkspaceID, string(command.Actor.Type), command.Actor.ID).Scan(&slotGeneration, &guestID, &bindingGeneration, &capabilities)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, false, product.ErrNotFound
	}
	if err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, false, product.ErrStoreUnavailable
	}
	if !containsDevelopmentCapabilities(capabilities) {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, false, product.ErrCapabilityUnsupported
	}
	materialization, err := loadDevelopmentMaterialization(opCtx, tx, command.TenantID, command.WorkspaceID, command.Request.RevisionID)
	if err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, false, err
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.development_environments SET current=false,updated_at=$1 WHERE tenant_id=$2 AND workspace_id=$3 AND slot_key='primary-code' AND current`, now, command.TenantID, command.WorkspaceID); err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, false, product.ErrStoreUnavailable
	}
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.development_environments
    (tenant_id,startup_id,workspace_id,slot_key,slot_generation,guest_id,binding_generation,template_id,template_revision,base_revision_id,manifest_digest,state,attempt,current,started_at,updated_at)
VALUES($1,$2,$3,'primary-code',$4,$5,$6,$7,$8,$9,$10,'materializing',1,true,$11,$11)`, command.TenantID, command.StartupID, command.WorkspaceID, slotGeneration, guestID, bindingGeneration, command.Template.ID, command.Template.Revision, materialization.RevisionID, materialization.ManifestDigest, now); err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, false, product.ErrStoreUnavailable
	}
	sequence, err := lockWorkspaceAndAdvance(opCtx, tx, command.TenantID, command.WorkspaceID, "", now)
	if err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, false, product.ErrStoreUnavailable
	}
	attributes, _ := json.Marshal(map[string]any{"slot_key": product.PrimarySlotKey, "template_id": command.Template.ID, "template_revision": command.Template.Revision, "base_revision_id": materialization.RevisionID})
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspace_events(tenant_id,workspace_id,sequence,event_id,event_type,subject_type,subject_id,actor_type,actor_id,occurred_at,attributes)VALUES($1,$2,$3,$4,'development.startup','slot','primary-code',$5,$6,$7,$8)`, command.TenantID, command.WorkspaceID, sequence, command.EventID, string(command.Actor.Type), command.Actor.ID, now, attributes); err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, false, product.ErrStoreUnavailable
	}
	if err := insertAudit(opCtx, tx, command.AuditID, command.TenantID, command.Actor, "development.start", "slot", product.PrimarySlotKey, "allowed", "authorized", now); err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, false, product.ErrStoreUnavailable
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, false, product.ErrStoreOutcomeUnknown
	}
	return product.DevelopmentEnvironment{ID: command.StartupID, TenantID: command.TenantID, WorkspaceID: command.WorkspaceID, SlotKey: product.PrimarySlotKey, GuestID: guestID, SlotGeneration: slotGeneration, BindingGeneration: bindingGeneration, TemplateID: command.Template.ID, TemplateRevision: command.Template.Revision, RevisionID: materialization.RevisionID, State: "materializing", Attempt: 1, StartedAt: now, UpdatedAt: now}, materialization, false, nil
}

func (s *Store) GetDevelopmentEnvironment(ctx context.Context, tenantID string, actor product.ActorRef, startupID string) (product.DevelopmentEnvironment, product.RevisionMaterialization, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, product.ErrStoreUnavailable
	}
	defer rollbackBounded(tx, s.operationTimeout)
	environment, err := scanDevelopment(tx.QueryRow(opCtx, `SELECT d.startup_id,d.tenant_id,d.workspace_id,d.slot_key,d.guest_id,d.slot_generation,d.binding_generation,d.template_id,d.template_revision,d.base_revision_id,d.state,COALESCE(d.error_code,''),d.attempt,d.started_at,d.updated_at FROM sandbox_runtime_product.development_environments d JOIN sandbox_runtime_product.workspaces w ON w.tenant_id=d.tenant_id AND w.workspace_id=d.workspace_id WHERE d.tenant_id=$1 AND d.startup_id=$2 AND w.owner_actor_type=$3 AND w.owner_actor_id=$4`, tenantID, startupID, string(actor.Type), actor.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, product.ErrNotFound
	}
	if err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, product.ErrStoreUnavailable
	}
	materialization, err := loadDevelopmentMaterialization(opCtx, tx, tenantID, environment.WorkspaceID, environment.RevisionID)
	if err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, err
	}
	return environment, materialization, nil
}

func (s *Store) CompleteDevelopmentEnvironment(ctx context.Context, command product.CompleteDevelopmentCommand) (product.DevelopmentEnvironment, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.DevelopmentEnvironment{}, product.ErrStoreUnavailable
	}
	defer rollbackBounded(tx, s.operationTimeout)
	if !exactDevelopmentAuthority(command.Environment, command.Authority) || !command.Health.Live || !command.Health.Ready || command.Health.TemplateRevision != command.Environment.TemplateRevision || command.Health.WorkspaceRevision != command.Environment.RevisionID {
		return product.DevelopmentEnvironment{}, product.ErrControlStale
	}
	var now time.Time
	if err := tx.QueryRow(opCtx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return product.DevelopmentEnvironment{}, product.ErrStoreUnavailable
	}
	var valid bool
	if err := tx.QueryRow(opCtx, `SELECT EXISTS(SELECT 1 FROM sandbox_runtime_product.development_environments d JOIN sandbox_runtime_product.workspace_slots s ON s.tenant_id=d.tenant_id AND s.workspace_id=d.workspace_id AND s.slot_key=d.slot_key JOIN sandbox_runtime_product.guest_bindings g ON g.tenant_id=d.tenant_id AND g.workspace_id=d.workspace_id AND g.slot_key=d.slot_key AND g.binding_generation=d.binding_generation WHERE d.tenant_id=$1 AND d.startup_id=$2 AND d.current AND d.state='materializing' AND s.generation=d.slot_generation AND s.observed_state='ready' AND g.guest_id=d.guest_id AND g.slot_generation=d.slot_generation AND g.state='connected' AND g.expires_at>clock_timestamp())`, command.Environment.TenantID, command.Environment.ID).Scan(&valid); err != nil {
		return product.DevelopmentEnvironment{}, product.ErrStoreUnavailable
	}
	if !valid {
		return product.DevelopmentEnvironment{}, product.ErrControlStale
	}
	updated, err := scanDevelopment(tx.QueryRow(opCtx, `UPDATE sandbox_runtime_product.development_environments SET state='ready',ready_at=$1,updated_at=$1 WHERE tenant_id=$2 AND startup_id=$3 AND current AND state='materializing' RETURNING startup_id,tenant_id,workspace_id,slot_key,guest_id,slot_generation,binding_generation,template_id,template_revision,base_revision_id,state,COALESCE(error_code,''),attempt,started_at,updated_at`, now, command.Environment.TenantID, command.Environment.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return product.DevelopmentEnvironment{}, product.ErrControlStale
	}
	if err != nil {
		return product.DevelopmentEnvironment{}, product.ErrStoreUnavailable
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.DevelopmentEnvironment{}, product.ErrStoreOutcomeUnknown
	}
	return updated, nil
}

func (s *Store) FailDevelopmentEnvironment(ctx context.Context, environment product.DevelopmentEnvironment, authority product.DevelopmentAuthority, code string) (product.DevelopmentEnvironment, error) {
	if !exactDevelopmentAuthority(environment, authority) || code == "" {
		return product.DevelopmentEnvironment{}, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	updated, err := scanDevelopment(s.pool.QueryRow(opCtx, `UPDATE sandbox_runtime_product.development_environments SET state='failed',error_code=$1,current=false,updated_at=clock_timestamp() WHERE tenant_id=$2 AND startup_id=$3 AND state='materializing' RETURNING startup_id,tenant_id,workspace_id,slot_key,guest_id,slot_generation,binding_generation,template_id,template_revision,base_revision_id,state,COALESCE(error_code,''),attempt,started_at,updated_at`, code, environment.TenantID, environment.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return product.DevelopmentEnvironment{}, product.ErrControlStale
	}
	if err != nil {
		return product.DevelopmentEnvironment{}, product.ErrStoreUnavailable
	}
	return updated, nil
}

func loadRetainedDevelopment(ctx context.Context, tx pgx.Tx, command product.BeginDevelopmentCommand) (product.DevelopmentEnvironment, product.RevisionMaterialization, error) {
	var digest []byte
	var startupID string
	if err := tx.QueryRow(ctx, `SELECT request_digest,result_id FROM sandbox_runtime_product.mutation_idempotency WHERE tenant_id=$1 AND actor_type=$2 AND actor_id=$3 AND method='POST' AND normalized_path=$4 AND idempotency_key=$5`, command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey).Scan(&digest, &startupID); err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, product.ErrStoreUnavailable
	}
	if len(digest) != 32 || subtle.ConstantTimeCompare(digest, command.RequestDigest[:]) != 1 {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, product.ErrIdempotencyConflict
	}
	environment, err := scanDevelopment(tx.QueryRow(ctx, `SELECT startup_id,tenant_id,workspace_id,slot_key,guest_id,slot_generation,binding_generation,template_id,template_revision,base_revision_id,state,COALESCE(error_code,''),attempt,started_at,updated_at FROM sandbox_runtime_product.development_environments WHERE tenant_id=$1 AND startup_id=$2`, command.TenantID, startupID))
	if err != nil {
		return product.DevelopmentEnvironment{}, product.RevisionMaterialization{}, product.ErrStoreUnavailable
	}
	materialization, err := loadDevelopmentMaterialization(ctx, tx, command.TenantID, command.WorkspaceID, environment.RevisionID)
	return environment, materialization, err
}

func loadDevelopmentMaterialization(ctx context.Context, tx pgx.Tx, tenantID, workspaceID, requestedRevision string) (product.RevisionMaterialization, error) {
	if requestedRevision == "" || requestedRevision == "initial-empty" {
		return product.RevisionMaterialization{RevisionID: "initial-empty", ManifestDigest: emptyWorkspaceManifestDigest, Entries: []product.RevisionManifestEntry{}}, nil
	}
	var digest string
	var document []byte
	err := tx.QueryRow(ctx, `SELECT r.manifest_digest,m.manifest FROM sandbox_runtime_product.workspace_revisions r JOIN sandbox_runtime_product.workspace_revision_manifests m ON m.tenant_id=r.tenant_id AND m.revision_id=r.revision_id AND m.workspace_id=r.workspace_id WHERE r.tenant_id=$1 AND r.workspace_id=$2 AND r.revision_id=$3`, tenantID, workspaceID, requestedRevision).Scan(&digest, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.RevisionMaterialization{}, product.ErrNotFound
	}
	if err != nil {
		return product.RevisionMaterialization{}, product.ErrStoreUnavailable
	}
	var manifest product.RevisionManifest
	if len(document) == 0 || len(document) > int(product.MaxManifestBytes) || json.Unmarshal(document, &manifest) != nil || len(manifest.Entries) > 100000 {
		return product.RevisionMaterialization{}, product.ErrStoreUnavailable
	}
	return product.RevisionMaterialization{RevisionID: requestedRevision, ManifestDigest: digest, Entries: manifest.Entries}, nil
}

func containsDevelopmentCapabilities(document []byte) bool {
	var values []string
	if json.Unmarshal(document, &values) != nil {
		return false
	}
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	for _, required := range developmentCapabilities {
		if !set[required] {
			return false
		}
	}
	return true
}

func exactDevelopmentAuthority(environment product.DevelopmentEnvironment, authority product.DevelopmentAuthority) bool {
	return environment.TenantID == authority.TenantID && environment.WorkspaceID == authority.WorkspaceID && environment.SlotKey == authority.SlotKey && environment.GuestID == authority.GuestID && environment.SlotGeneration == authority.SlotGeneration && environment.BindingGeneration == authority.BindingGeneration
}

type developmentScanner interface{ Scan(...any) error }

func scanDevelopment(row developmentScanner) (product.DevelopmentEnvironment, error) {
	var value product.DevelopmentEnvironment
	err := row.Scan(&value.ID, &value.TenantID, &value.WorkspaceID, &value.SlotKey, &value.GuestID, &value.SlotGeneration, &value.BindingGeneration, &value.TemplateID, &value.TemplateRevision, &value.RevisionID, &value.State, &value.ErrorCode, &value.Attempt, &value.StartedAt, &value.UpdatedAt)
	return value, err
}

var _ product.DevelopmentEnvironmentStore = (*Store)(nil)
