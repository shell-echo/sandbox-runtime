ALTER TABLE sandbox_runtime_product.outbox
    ADD COLUMN lease_owner text,
    ADD COLUMN lease_expires_at timestamp with time zone,
    ADD COLUMN last_error_code text,
    ADD CONSTRAINT outbox_lease_shape CHECK (
        (state = 'leased' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (state <> 'leased' AND lease_owner IS NULL AND lease_expires_at IS NULL)
    ),
    ADD CONSTRAINT outbox_lease_owner CHECK (lease_owner IS NULL OR lease_owner ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
    ADD CONSTRAINT outbox_error_code CHECK (last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_.-]{0,127}$');

CREATE TABLE sandbox_runtime_product.product_operation_attempts (
    tenant_id text NOT NULL,
    operation_id text NOT NULL,
    attempt_id text NOT NULL,
    workspace_id text NOT NULL,
    slot_key text NOT NULL,
    slot_generation bigint NOT NULL,
    fencing_token bigint NOT NULL,
    idempotency_key text NOT NULL,
    request_digest text,
    provider_revision_id text,
    provider_operation_id text,
    state text NOT NULL,
    outcome text NOT NULL,
    error_code text,
    deadline_at timestamp with time zone NOT NULL,
    dispatched_at timestamp with time zone,
    observed_at timestamp with time zone,
    reconcile_lease_owner text,
    reconcile_lease_expires_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT product_operation_attempts_primary_key PRIMARY KEY (tenant_id, operation_id, attempt_id),
    CONSTRAINT product_operation_attempts_operation FOREIGN KEY (tenant_id, operation_id)
        REFERENCES sandbox_runtime_product.product_operations (tenant_id, operation_id) ON DELETE RESTRICT,
    CONSTRAINT product_operation_attempts_workspace FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES sandbox_runtime_product.workspaces (tenant_id, workspace_id) ON DELETE RESTRICT,
    CONSTRAINT product_operation_attempts_generation CHECK (slot_generation >= 1 AND fencing_token >= 1),
    CONSTRAINT product_operation_attempts_state CHECK (state IN ('prepared', 'dispatched', 'accepted', 'running', 'succeeded', 'failed', 'cancelled', 'outcome_unknown')),
    CONSTRAINT product_operation_attempts_outcome CHECK (outcome IN ('pending', 'known', 'unknown')),
    CONSTRAINT product_operation_attempts_digest CHECK (request_digest IS NULL OR request_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT product_operation_attempts_lease CHECK ((reconcile_lease_owner IS NULL) = (reconcile_lease_expires_at IS NULL)),
    CONSTRAINT product_operation_attempts_timestamp_order CHECK (updated_at >= created_at AND deadline_at > created_at)
);

CREATE TABLE sandbox_runtime_product.provider_bindings (
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    slot_key text NOT NULL,
    slot_generation bigint NOT NULL,
    binding_generation bigint NOT NULL,
    provider_revision_id text NOT NULL,
    runtime_profile_id text NOT NULL,
    sandbox_id text NOT NULL,
    create_operation_id text NOT NULL,
    create_attempt_id text NOT NULL,
    provider_operation_id text,
    observed_state text NOT NULL,
    current boolean NOT NULL,
    last_observed_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT provider_bindings_primary_key PRIMARY KEY (tenant_id, workspace_id, slot_key, binding_generation),
    CONSTRAINT provider_bindings_slot FOREIGN KEY (tenant_id, workspace_id, slot_key)
        REFERENCES sandbox_runtime_product.workspace_slots (tenant_id, workspace_id, slot_key) ON DELETE RESTRICT,
    CONSTRAINT provider_bindings_attempt FOREIGN KEY (tenant_id, create_operation_id, create_attempt_id)
        REFERENCES sandbox_runtime_product.product_operation_attempts (tenant_id, operation_id, attempt_id) ON DELETE RESTRICT,
    CONSTRAINT provider_bindings_generation CHECK (slot_generation >= 1 AND binding_generation >= 1),
    CONSTRAINT provider_bindings_state CHECK (observed_state IN ('requested', 'provisioning', 'ready', 'suspending', 'suspended', 'resuming', 'terminating', 'terminated', 'expired', 'failed')),
    CONSTRAINT provider_bindings_timestamp_order CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX provider_bindings_one_current
    ON sandbox_runtime_product.provider_bindings (tenant_id, workspace_id, slot_key, slot_generation)
    WHERE current;

CREATE TABLE sandbox_runtime_product.reconciliation_checkpoints (
    authority text NOT NULL,
    partition_key text NOT NULL,
    cursor_value text NOT NULL,
    lease_owner text,
    lease_expires_at timestamp with time zone,
    version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT reconciliation_checkpoints_primary_key PRIMARY KEY (authority, partition_key),
    CONSTRAINT reconciliation_checkpoints_authority CHECK (authority ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    CONSTRAINT reconciliation_checkpoints_version CHECK (version >= 1),
    CONSTRAINT reconciliation_checkpoints_lease CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL))
);

CREATE TABLE sandbox_runtime_product.control_lease_fences (
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    scope_type text NOT NULL,
    scope_id text NOT NULL,
    last_fence bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT control_lease_fences_primary_key PRIMARY KEY (tenant_id, workspace_id, scope_type, scope_id),
    CONSTRAINT control_lease_fences_workspace FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES sandbox_runtime_product.workspaces (tenant_id, workspace_id) ON DELETE RESTRICT,
    CONSTRAINT control_lease_fences_scope CHECK (scope_type IN ('workspace', 'session')),
    CONSTRAINT control_lease_fences_value CHECK (last_fence >= 0)
);

CREATE TABLE sandbox_runtime_product.control_leases (
    tenant_id text NOT NULL,
    lease_id text NOT NULL,
    workspace_id text NOT NULL,
    scope_type text NOT NULL,
    scope_id text NOT NULL,
    controller_actor_type text NOT NULL,
    controller_actor_id text NOT NULL,
    fence bigint NOT NULL,
    state text NOT NULL,
    issued_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT control_leases_primary_key PRIMARY KEY (tenant_id, lease_id),
    CONSTRAINT control_leases_public_id UNIQUE (lease_id),
    CONSTRAINT control_leases_workspace FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES sandbox_runtime_product.workspaces (tenant_id, workspace_id) ON DELETE RESTRICT,
    CONSTRAINT control_leases_scope CHECK (scope_type IN ('workspace', 'session')),
    CONSTRAINT control_leases_actor CHECK (controller_actor_type IN ('human', 'agent', 'service')),
    CONSTRAINT control_leases_fence CHECK (fence >= 1),
    CONSTRAINT control_leases_state CHECK (state IN ('active', 'released', 'expired', 'revoked')),
    CONSTRAINT control_leases_expiry CHECK (expires_at > issued_at AND updated_at >= issued_at)
);

CREATE UNIQUE INDEX control_leases_one_active
    ON sandbox_runtime_product.control_leases (tenant_id, workspace_id, scope_type, scope_id)
    WHERE state = 'active';

CREATE TABLE sandbox_runtime_product.runtime_sessions (
    tenant_id text NOT NULL,
    session_id text NOT NULL,
    workspace_id text NOT NULL,
    slot_key text NOT NULL,
    slot_generation bigint NOT NULL,
    owner_actor_type text NOT NULL,
    owner_actor_id text NOT NULL,
    kind text NOT NULL,
    protocol_profile text NOT NULL,
    state text NOT NULL,
    requires_control_lease boolean NOT NULL,
    recording_policy text NOT NULL,
    version bigint NOT NULL,
    provider_runtime_session_id text,
    provider_connection_generation bigint,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT runtime_sessions_primary_key PRIMARY KEY (tenant_id, session_id),
    CONSTRAINT runtime_sessions_public_id UNIQUE (session_id),
    CONSTRAINT runtime_sessions_slot FOREIGN KEY (tenant_id, workspace_id, slot_key)
        REFERENCES sandbox_runtime_product.workspace_slots (tenant_id, workspace_id, slot_key) ON DELETE RESTRICT,
    CONSTRAINT runtime_sessions_actor CHECK (owner_actor_type IN ('human', 'agent', 'service')),
    CONSTRAINT runtime_sessions_kind CHECK (kind IN ('terminal', 'browser_automation', 'browser_live', 'desktop', 'editor', 'notebook', 'preview', 'files', 'mcp')),
    CONSTRAINT runtime_sessions_state CHECK (state IN ('requested', 'provisioning', 'ready', 'active', 'draining', 'closed', 'expired', 'failed')),
    CONSTRAINT runtime_sessions_recording CHECK (recording_policy IN ('disabled', 'metadata_only', 'required')),
    CONSTRAINT runtime_sessions_version CHECK (version >= 1 AND slot_generation >= 1),
    CONSTRAINT runtime_sessions_expiry CHECK (expires_at > created_at AND updated_at >= created_at)
);

CREATE TABLE sandbox_runtime_product.connection_grants (
    tenant_id text NOT NULL,
    connection_id text NOT NULL,
    session_id text NOT NULL,
    workspace_id text NOT NULL,
    slot_key text NOT NULL,
    slot_generation bigint NOT NULL,
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    protocol_profile text NOT NULL,
    ticket_digest bytea NOT NULL,
    control_lease_id text,
    control_fence bigint,
    state text NOT NULL,
    issued_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    CONSTRAINT connection_grants_primary_key PRIMARY KEY (tenant_id, connection_id),
    CONSTRAINT connection_grants_public_id UNIQUE (connection_id),
    CONSTRAINT connection_grants_session FOREIGN KEY (tenant_id, session_id)
        REFERENCES sandbox_runtime_product.runtime_sessions (tenant_id, session_id) ON DELETE RESTRICT,
    CONSTRAINT connection_grants_actor CHECK (actor_type IN ('human', 'agent', 'service')),
    CONSTRAINT connection_grants_ticket UNIQUE (ticket_digest),
    CONSTRAINT connection_grants_ticket_digest CHECK (octet_length(ticket_digest) = 32),
    CONSTRAINT connection_grants_control CHECK ((control_lease_id IS NULL) = (control_fence IS NULL)),
    CONSTRAINT connection_grants_state CHECK (state IN ('issued', 'consumed', 'expired', 'revoked')),
    CONSTRAINT connection_grants_expiry CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '60 seconds')
);

CREATE TABLE sandbox_runtime_product.guest_bindings (
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    slot_key text NOT NULL,
    binding_generation bigint NOT NULL,
    guest_id text NOT NULL,
    credential_digest bytea NOT NULL,
    protocol_version text NOT NULL,
    capabilities jsonb NOT NULL,
    state text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT guest_bindings_primary_key PRIMARY KEY (tenant_id, workspace_id, slot_key, binding_generation),
    CONSTRAINT guest_bindings_slot FOREIGN KEY (tenant_id, workspace_id, slot_key)
        REFERENCES sandbox_runtime_product.workspace_slots (tenant_id, workspace_id, slot_key) ON DELETE RESTRICT,
    CONSTRAINT guest_bindings_digest CHECK (octet_length(credential_digest) = 32),
    CONSTRAINT guest_bindings_capabilities CHECK (jsonb_typeof(capabilities) = 'array' AND jsonb_array_length(capabilities) <= 32),
    CONSTRAINT guest_bindings_state CHECK (state IN ('issued', 'connected', 'disconnected', 'revoked', 'expired')),
    CONSTRAINT guest_bindings_expiry CHECK (expires_at > created_at AND updated_at >= created_at)
);

CREATE TABLE sandbox_runtime_product.workspace_revisions (
    tenant_id text NOT NULL,
    revision_id text NOT NULL,
    workspace_id text NOT NULL,
    parent_revision_id text,
    manifest_digest text NOT NULL,
    object_reference text NOT NULL,
    file_count integer NOT NULL,
    size_bytes bigint NOT NULL,
    created_actor_type text NOT NULL,
    created_actor_id text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT workspace_revisions_primary_key PRIMARY KEY (tenant_id, revision_id),
    CONSTRAINT workspace_revisions_public_id UNIQUE (revision_id),
    CONSTRAINT workspace_revisions_workspace FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES sandbox_runtime_product.workspaces (tenant_id, workspace_id) ON DELETE RESTRICT,
    CONSTRAINT workspace_revisions_digest CHECK (manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT workspace_revisions_bounds CHECK (file_count >= 0 AND file_count <= 100000 AND size_bytes >= 0),
    CONSTRAINT workspace_revisions_actor CHECK (created_actor_type IN ('human', 'agent', 'service'))
);

CREATE TABLE sandbox_runtime_product.workspace_heads (
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    branch_id text NOT NULL,
    revision_id text NOT NULL,
    version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT workspace_heads_primary_key PRIMARY KEY (tenant_id, workspace_id, branch_id),
    CONSTRAINT workspace_heads_revision FOREIGN KEY (tenant_id, revision_id)
        REFERENCES sandbox_runtime_product.workspace_revisions (tenant_id, revision_id) ON DELETE RESTRICT,
    CONSTRAINT workspace_heads_branch CHECK (branch_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
    CONSTRAINT workspace_heads_version CHECK (version >= 1)
);

CREATE TABLE sandbox_runtime_product.file_changes (
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    slot_key text NOT NULL,
    sequence bigint NOT NULL,
    path text NOT NULL,
    change_type text NOT NULL,
    revision text NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    CONSTRAINT file_changes_primary_key PRIMARY KEY (tenant_id, workspace_id, slot_key, sequence),
    CONSTRAINT file_changes_slot FOREIGN KEY (tenant_id, workspace_id, slot_key)
        REFERENCES sandbox_runtime_product.workspace_slots (tenant_id, workspace_id, slot_key) ON DELETE RESTRICT,
    CONSTRAINT file_changes_sequence CHECK (sequence >= 1),
    CONSTRAINT file_changes_path CHECK (char_length(path) BETWEEN 1 AND 4096 AND path !~ '(^|/)\.\.(/|$)'),
    CONSTRAINT file_changes_type CHECK (change_type IN ('create', 'modify', 'remove', 'rename'))
);

CREATE TABLE sandbox_runtime_product.blob_transfers (
    tenant_id text NOT NULL,
    transfer_id text NOT NULL,
    workspace_id text NOT NULL,
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    direction text NOT NULL,
    digest text NOT NULL,
    size_bytes bigint NOT NULL,
    committed_bytes bigint NOT NULL,
    state text NOT NULL,
    object_reference text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT blob_transfers_primary_key PRIMARY KEY (tenant_id, transfer_id),
    CONSTRAINT blob_transfers_public_id UNIQUE (transfer_id),
    CONSTRAINT blob_transfers_workspace FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES sandbox_runtime_product.workspaces (tenant_id, workspace_id) ON DELETE RESTRICT,
    CONSTRAINT blob_transfers_actor CHECK (actor_type IN ('human', 'agent', 'service')),
    CONSTRAINT blob_transfers_direction CHECK (direction IN ('upload', 'download')),
    CONSTRAINT blob_transfers_digest CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT blob_transfers_bounds CHECK (size_bytes >= 0 AND committed_bytes >= 0 AND committed_bytes <= size_bytes),
    CONSTRAINT blob_transfers_state CHECK (state IN ('pending', 'transferring', 'complete', 'cancelled', 'expired', 'failed')),
    CONSTRAINT blob_transfers_expiry CHECK (expires_at > created_at AND updated_at >= created_at)
);

CREATE TABLE sandbox_runtime_product.artifacts (
    tenant_id text NOT NULL,
    artifact_id text NOT NULL,
    workspace_id text NOT NULL,
    slot_key text,
    name text NOT NULL,
    media_type text NOT NULL,
    size_bytes bigint NOT NULL,
    digest text NOT NULL,
    state text NOT NULL,
    object_reference text NOT NULL,
    created_actor_type text NOT NULL,
    created_actor_id text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT artifacts_primary_key PRIMARY KEY (tenant_id, artifact_id),
    CONSTRAINT artifacts_public_id UNIQUE (artifact_id),
    CONSTRAINT artifacts_workspace FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES sandbox_runtime_product.workspaces (tenant_id, workspace_id) ON DELETE RESTRICT,
    CONSTRAINT artifacts_digest CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT artifacts_state CHECK (state IN ('available', 'quarantined', 'expired', 'deleted')),
    CONSTRAINT artifacts_size CHECK (size_bytes >= 0),
    CONSTRAINT artifacts_actor CHECK (created_actor_type IN ('human', 'agent', 'service'))
);

CREATE TABLE sandbox_runtime_product.recordings (
    tenant_id text NOT NULL,
    recording_id text NOT NULL,
    workspace_id text NOT NULL,
    session_id text,
    agent_run_id text,
    recording_type text NOT NULL,
    state text NOT NULL,
    digest text,
    size_bytes bigint,
    integrity_manifest_reference text,
    encryption_key_reference text NOT NULL,
    consent_reference text NOT NULL,
    started_at timestamp with time zone NOT NULL,
    completed_at timestamp with time zone,
    retention_expires_at timestamp with time zone NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT recordings_primary_key PRIMARY KEY (tenant_id, recording_id),
    CONSTRAINT recordings_public_id UNIQUE (recording_id),
    CONSTRAINT recordings_workspace FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES sandbox_runtime_product.workspaces (tenant_id, workspace_id) ON DELETE RESTRICT,
    CONSTRAINT recordings_type CHECK (recording_type IN ('audit', 'terminal', 'media', 'agent_trace')),
    CONSTRAINT recordings_state CHECK (state IN ('recording', 'finalizing', 'available', 'failed', 'expired', 'deleted')),
    CONSTRAINT recordings_digest CHECK (digest IS NULL OR digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT recordings_size CHECK (size_bytes IS NULL OR size_bytes >= 0),
    CONSTRAINT recordings_retention CHECK (retention_expires_at > started_at)
);

CREATE TABLE sandbox_runtime_product.recording_segments (
    tenant_id text NOT NULL,
    recording_id text NOT NULL,
    sequence bigint NOT NULL,
    object_reference text NOT NULL,
    digest text NOT NULL,
    previous_digest text,
    size_bytes bigint NOT NULL,
    started_at timestamp with time zone NOT NULL,
    completed_at timestamp with time zone NOT NULL,
    CONSTRAINT recording_segments_primary_key PRIMARY KEY (tenant_id, recording_id, sequence),
    CONSTRAINT recording_segments_recording FOREIGN KEY (tenant_id, recording_id)
        REFERENCES sandbox_runtime_product.recordings (tenant_id, recording_id) ON DELETE RESTRICT,
    CONSTRAINT recording_segments_sequence CHECK (sequence >= 1),
    CONSTRAINT recording_segments_digest CHECK (digest ~ '^sha256:[0-9a-f]{64}$' AND (previous_digest IS NULL OR previous_digest ~ '^sha256:[0-9a-f]{64}$')),
    CONSTRAINT recording_segments_size CHECK (size_bytes >= 0 AND completed_at >= started_at)
);

CREATE TABLE sandbox_runtime_product.security_audit (
    event_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    outcome text NOT NULL,
    reason_code text NOT NULL,
    request_id text NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    CONSTRAINT security_audit_actor CHECK (actor_type IN ('human', 'agent', 'service')),
    CONSTRAINT security_audit_action CHECK (action ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    CONSTRAINT security_audit_outcome CHECK (outcome IN ('allowed', 'denied', 'failed')),
    CONSTRAINT security_audit_reason CHECK (reason_code ~ '^[a-z][a-z0-9_.-]{0,127}$')
);

CREATE TABLE sandbox_runtime_product.mutation_idempotency (
    tenant_id text NOT NULL,
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    method text NOT NULL,
    normalized_path text NOT NULL,
    idempotency_key text NOT NULL,
    request_digest bytea NOT NULL,
    result_type text NOT NULL,
    result_id text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT mutation_idempotency_primary_key PRIMARY KEY (tenant_id,actor_type,actor_id,method,normalized_path,idempotency_key),
    CONSTRAINT mutation_idempotency_actor CHECK (actor_type IN ('human','agent','service')),
    CONSTRAINT mutation_idempotency_method CHECK (method IN ('POST','PUT','PATCH','DELETE')),
    CONSTRAINT mutation_idempotency_key CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128 AND idempotency_key ~ '^[!-~]+$'),
    CONSTRAINT mutation_idempotency_digest CHECK (octet_length(request_digest)=32),
    CONSTRAINT mutation_idempotency_result CHECK (result_type ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    CONSTRAINT mutation_idempotency_expiry CHECK (expires_at >= created_at + interval '24 hours')
);

CREATE TABLE sandbox_runtime_product.tenant_quotas (
    tenant_id text PRIMARY KEY,
    max_workspaces integer NOT NULL,
    max_sessions integer NOT NULL,
    max_active_transfers integer NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT tenant_quotas_bounds CHECK (max_workspaces BETWEEN 1 AND 10000 AND max_sessions BETWEEN 1 AND 100000 AND max_active_transfers BETWEEN 1 AND 10000)
);

CREATE INDEX product_operation_attempts_reconcile_index
    ON sandbox_runtime_product.product_operation_attempts (state, updated_at)
    WHERE state IN ('dispatched', 'accepted', 'running', 'outcome_unknown');
CREATE INDEX runtime_sessions_workspace_index
    ON sandbox_runtime_product.runtime_sessions (tenant_id, workspace_id, created_at, session_id);
CREATE INDEX file_changes_watch_index
    ON sandbox_runtime_product.file_changes (tenant_id, workspace_id, slot_key, sequence);
CREATE INDEX artifact_catalog_index
    ON sandbox_runtime_product.artifacts (tenant_id, workspace_id, created_at, artifact_id);
CREATE INDEX recording_catalog_index
    ON sandbox_runtime_product.recordings (tenant_id, workspace_id, started_at, recording_id);

REVOKE ALL ON ALL TABLES IN SCHEMA sandbox_runtime_product FROM PUBLIC;
