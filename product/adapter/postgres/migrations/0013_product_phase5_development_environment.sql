CREATE TABLE sandbox_runtime_product.workspace_revision_manifests (
    tenant_id text NOT NULL,
    revision_id text NOT NULL,
    workspace_id text NOT NULL,
    manifest jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT workspace_revision_manifests_primary_key PRIMARY KEY (tenant_id, revision_id),
    CONSTRAINT workspace_revision_manifests_revision FOREIGN KEY (tenant_id,workspace_id,revision_id)
        REFERENCES sandbox_runtime_product.workspace_revisions (tenant_id,workspace_id,revision_id) ON DELETE RESTRICT,
    CONSTRAINT workspace_revision_manifests_shape CHECK (jsonb_typeof(manifest) = 'object' AND octet_length(manifest::text) <= 16777216)
);

CREATE TABLE sandbox_runtime_product.development_environments (
    tenant_id text NOT NULL,
    startup_id text NOT NULL,
    workspace_id text NOT NULL,
    slot_key text NOT NULL,
    slot_generation bigint NOT NULL,
    guest_id text NOT NULL,
    binding_generation bigint NOT NULL,
    template_id text NOT NULL,
    template_revision text NOT NULL,
    base_revision_id text NOT NULL,
    manifest_digest text NOT NULL,
    state text NOT NULL,
    error_code text,
    attempt integer NOT NULL,
    current boolean NOT NULL,
    started_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    ready_at timestamp with time zone,
    CONSTRAINT development_environments_primary_key PRIMARY KEY (tenant_id,startup_id),
    CONSTRAINT development_environments_public_id UNIQUE (startup_id),
    CONSTRAINT development_environments_slot FOREIGN KEY (tenant_id,workspace_id,slot_key)
        REFERENCES sandbox_runtime_product.workspace_slots (tenant_id,workspace_id,slot_key) ON DELETE RESTRICT,
    CONSTRAINT development_environments_guest FOREIGN KEY (tenant_id,workspace_id,slot_key,binding_generation)
        REFERENCES sandbox_runtime_product.guest_bindings (tenant_id,workspace_id,slot_key,binding_generation) ON DELETE RESTRICT,
    CONSTRAINT development_environments_generation CHECK (slot_generation >= 1 AND binding_generation >= 1),
    CONSTRAINT development_environments_template CHECK (template_id = 'coding-shell-base-v1' AND template_revision ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT development_environments_manifest CHECK (manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT development_environments_state CHECK (state IN ('materializing','ready','failed')),
    CONSTRAINT development_environments_error CHECK ((state = 'failed') = (error_code IS NOT NULL)),
    CONSTRAINT development_environments_attempt CHECK (attempt >= 1),
    CONSTRAINT development_environments_ready CHECK ((state = 'ready') = (ready_at IS NOT NULL)),
    CONSTRAINT development_environments_time CHECK (updated_at >= started_at AND (ready_at IS NULL OR ready_at >= started_at))
);

CREATE UNIQUE INDEX development_environments_one_current
    ON sandbox_runtime_product.development_environments (tenant_id,workspace_id,slot_key,slot_generation)
    WHERE current;

CREATE INDEX development_environments_recovery
    ON sandbox_runtime_product.development_environments (state,updated_at)
    WHERE current AND state = 'materializing';

REVOKE ALL ON TABLE sandbox_runtime_product.workspace_revision_manifests FROM PUBLIC;
REVOKE ALL ON TABLE sandbox_runtime_product.development_environments FROM PUBLIC;
