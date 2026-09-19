CREATE TABLE sandbox_runtime_product.desktop_policy_revisions (
    tenant_id text NOT NULL,
    workspace_id text NOT NULL,
    revision bigint NOT NULL,
    policy jsonb NOT NULL,
    updated_by_actor_type text NOT NULL,
    updated_by_actor_id text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT desktop_policy_revisions_primary_key PRIMARY KEY (tenant_id, workspace_id, revision),
    CONSTRAINT desktop_policy_revisions_workspace FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES sandbox_runtime_product.workspaces (tenant_id, workspace_id) ON DELETE CASCADE,
    CONSTRAINT desktop_policy_revisions_revision CHECK (revision >= 1),
    CONSTRAINT desktop_policy_revisions_policy_object CHECK (
        jsonb_typeof(policy) = 'object'
        AND policy ? 'revision'
        AND (policy->>'revision')::bigint = revision
    ),
    CONSTRAINT desktop_policy_revisions_actor CHECK (updated_by_actor_type IN ('human','agent','service'))
);

CREATE INDEX desktop_policy_revisions_current
    ON sandbox_runtime_product.desktop_policy_revisions (tenant_id, workspace_id, revision DESC);

REVOKE ALL ON TABLE sandbox_runtime_product.desktop_policy_revisions FROM PUBLIC;
