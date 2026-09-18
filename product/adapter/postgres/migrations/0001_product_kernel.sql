CREATE TABLE sandbox_runtime_product.workspaces (
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    owner_actor_type text NOT NULL,
    owner_actor_id text NOT NULL,
    display_name text NOT NULL,
    primary_slot_key text NOT NULL,
    desired_state text NOT NULL,
    observed_state text NOT NULL,
    version bigint NOT NULL,
    lease_expires_at timestamp with time zone NOT NULL,
    next_event_sequence bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT workspaces_primary_key PRIMARY KEY (tenant_id, workspace_id),
    CONSTRAINT workspaces_public_id UNIQUE (workspace_id),
    CONSTRAINT workspaces_tenant_id CHECK (tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
    CONSTRAINT workspaces_workspace_id CHECK (workspace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
    CONSTRAINT workspaces_owner_actor_type CHECK (owner_actor_type IN ('human', 'agent', 'service')),
    CONSTRAINT workspaces_owner_actor_id CHECK (owner_actor_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
    CONSTRAINT workspaces_display_name CHECK (char_length(display_name) BETWEEN 1 AND 128),
    CONSTRAINT workspaces_primary_slot CHECK (primary_slot_key = 'primary-code'),
    CONSTRAINT workspaces_desired_state CHECK (desired_state IN ('active', 'suspended', 'terminated')),
    CONSTRAINT workspaces_observed_state CHECK (observed_state IN ('requested', 'provisioning', 'active', 'degraded', 'suspending', 'suspended', 'terminating', 'terminated', 'failed')),
    CONSTRAINT workspaces_version CHECK (version >= 1),
    CONSTRAINT workspaces_event_sequence CHECK (next_event_sequence >= 2),
    CONSTRAINT workspaces_lease_order CHECK (lease_expires_at > created_at),
    CONSTRAINT workspaces_timestamp_order CHECK (updated_at >= created_at)
);

CREATE TABLE sandbox_runtime_product.workspace_slots (
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    slot_key text NOT NULL,
    kind text NOT NULL,
    profile_id text NOT NULL,
    required_capabilities jsonb NOT NULL,
    desired_state text NOT NULL,
    observed_state text NOT NULL,
    generation bigint NOT NULL,
    observed_generation bigint NOT NULL,
    version bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT workspace_slots_primary_key PRIMARY KEY (tenant_id, workspace_id, slot_key),
    CONSTRAINT workspace_slots_workspace FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES sandbox_runtime_product.workspaces (tenant_id, workspace_id) ON DELETE CASCADE,
    CONSTRAINT workspace_slots_key CHECK (slot_key ~ '^[a-z0-9][a-z0-9-]{0,127}$'),
    CONSTRAINT workspace_slots_kind CHECK (kind IN ('code', 'browser', 'desktop', 'subagent', 'isolated')),
    CONSTRAINT workspace_slots_profile CHECK (profile_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
    CONSTRAINT workspace_slots_capabilities CHECK (jsonb_typeof(required_capabilities) = 'array' AND jsonb_array_length(required_capabilities) BETWEEN 1 AND 32),
    CONSTRAINT workspace_slots_desired_state CHECK (desired_state IN ('ready', 'suspended', 'terminated')),
    CONSTRAINT workspace_slots_observed_state CHECK (observed_state IN ('requested', 'provisioning', 'ready', 'degraded', 'suspending', 'suspended', 'terminating', 'terminated', 'failed')),
    CONSTRAINT workspace_slots_generation CHECK (generation >= 1 AND observed_generation >= 0 AND observed_generation <= generation),
    CONSTRAINT workspace_slots_version CHECK (version >= 1),
    CONSTRAINT workspace_slots_timestamp_order CHECK (updated_at >= created_at),
    CONSTRAINT workspace_slots_primary_shape CHECK (slot_key <> 'primary-code' OR (kind = 'code' AND desired_state = 'ready'))
);

CREATE TABLE sandbox_runtime_product.product_operations (
    tenant_id text NOT NULL,
    operation_id text NOT NULL,
    operation_type text NOT NULL,
    workspace_id text NOT NULL,
    submitted_actor_type text NOT NULL,
    submitted_actor_id text NOT NULL,
    state text NOT NULL,
    reconciliation_status text NOT NULL,
    version bigint NOT NULL,
    accepted_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT product_operations_primary_key PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT product_operations_public_id UNIQUE (operation_id),
    CONSTRAINT product_operations_workspace FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES sandbox_runtime_product.workspaces (tenant_id, workspace_id) ON DELETE RESTRICT,
    CONSTRAINT product_operations_type CHECK (operation_type IN ('create_workspace', 'set_workspace_desired_state', 'put_slot', 'create_session', 'close_session', 'resize_session', 'start_agent_run', 'cancel_agent_run')),
    CONSTRAINT product_operations_actor_type CHECK (submitted_actor_type IN ('human', 'agent', 'service')),
    CONSTRAINT product_operations_state CHECK (state IN ('accepted', 'running', 'succeeded', 'failed', 'cancelled', 'outcome_unknown')),
    CONSTRAINT product_operations_reconciliation CHECK (reconciliation_status IN ('pending', 'reconciling', 'complete', 'manual_review')),
    CONSTRAINT product_operations_version CHECK (version >= 1),
    CONSTRAINT product_operations_timestamp_order CHECK (updated_at >= accepted_at)
);

CREATE TABLE sandbox_runtime_product.workspace_events (
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    sequence bigint NOT NULL,
    event_id text NOT NULL,
    event_type text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    operation_id text,
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    attributes jsonb NOT NULL,
    CONSTRAINT workspace_events_primary_key PRIMARY KEY (tenant_id, workspace_id, sequence),
    CONSTRAINT workspace_events_public_id UNIQUE (event_id),
    CONSTRAINT workspace_events_workspace FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES sandbox_runtime_product.workspaces (tenant_id, workspace_id) ON DELETE RESTRICT,
    CONSTRAINT workspace_events_operation FOREIGN KEY (tenant_id, operation_id)
        REFERENCES sandbox_runtime_product.product_operations (tenant_id, operation_id) ON DELETE RESTRICT,
    CONSTRAINT workspace_events_sequence CHECK (sequence >= 1),
    CONSTRAINT workspace_events_type CHECK (event_type ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    CONSTRAINT workspace_events_subject_type CHECK (subject_type IN ('workspace', 'slot', 'operation', 'control_lease', 'session', 'artifact', 'recording', 'agent_run')),
    CONSTRAINT workspace_events_actor_type CHECK (actor_type IN ('human', 'agent', 'service')),
    CONSTRAINT workspace_events_attributes CHECK (jsonb_typeof(attributes) = 'object' AND octet_length(attributes::text) <= 65536)
);

CREATE TABLE sandbox_runtime_product.outbox (
    tenant_id text NOT NULL,
    outbox_id text NOT NULL,
    workspace_id text NOT NULL,
    operation_id text NOT NULL,
    message_type text NOT NULL,
    payload jsonb NOT NULL,
    state text NOT NULL,
    attempt_count integer NOT NULL,
    available_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT outbox_primary_key PRIMARY KEY (tenant_id, outbox_id),
    CONSTRAINT outbox_public_id UNIQUE (outbox_id),
    CONSTRAINT outbox_workspace FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES sandbox_runtime_product.workspaces (tenant_id, workspace_id) ON DELETE RESTRICT,
    CONSTRAINT outbox_operation FOREIGN KEY (tenant_id, operation_id)
        REFERENCES sandbox_runtime_product.product_operations (tenant_id, operation_id) ON DELETE RESTRICT,
    CONSTRAINT outbox_type CHECK (message_type ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    CONSTRAINT outbox_payload CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 131072),
    CONSTRAINT outbox_state CHECK (state IN ('pending', 'leased', 'delivered', 'dead_letter')),
    CONSTRAINT outbox_attempt_count CHECK (attempt_count >= 0),
    CONSTRAINT outbox_timestamp_order CHECK (updated_at >= created_at)
);

CREATE INDEX outbox_dispatch_index
    ON sandbox_runtime_product.outbox (state, available_at, created_at)
    WHERE state IN ('pending', 'leased');

CREATE TABLE sandbox_runtime_product.idempotency_records (
    tenant_id text NOT NULL,
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    method text NOT NULL,
    normalized_path text NOT NULL,
    idempotency_key text NOT NULL,
    request_digest bytea NOT NULL,
    result_workspace_id text NOT NULL,
    result_operation_id text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT idempotency_records_primary_key PRIMARY KEY (tenant_id, actor_type, actor_id, method, normalized_path, idempotency_key),
    CONSTRAINT idempotency_records_operation FOREIGN KEY (tenant_id, result_operation_id)
        REFERENCES sandbox_runtime_product.product_operations (tenant_id, operation_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT idempotency_records_actor_type CHECK (actor_type IN ('human', 'agent', 'service')),
    CONSTRAINT idempotency_records_method CHECK (method IN ('POST', 'PUT', 'PATCH', 'DELETE')),
    CONSTRAINT idempotency_records_path CHECK (char_length(normalized_path) BETWEEN 1 AND 512),
    CONSTRAINT idempotency_records_key CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128 AND idempotency_key ~ '^[!-~]+$'),
    CONSTRAINT idempotency_records_digest CHECK (octet_length(request_digest) = 32),
    CONSTRAINT idempotency_records_expiry CHECK (expires_at >= created_at + interval '24 hours')
);

REVOKE ALL ON ALL TABLES IN SCHEMA sandbox_runtime_product FROM PUBLIC;
