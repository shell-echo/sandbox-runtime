ALTER TABLE sandbox_runtime_product.tenant_quotas
    ADD COLUMN max_browser_slots integer NOT NULL DEFAULT 4,
    ADD CONSTRAINT tenant_quotas_browser_slots_bounds CHECK (max_browser_slots BETWEEN 1 AND 64);

CREATE INDEX workspace_slots_browser_quota_index
    ON sandbox_runtime_product.workspace_slots (tenant_id, desired_state)
    WHERE kind = 'browser' AND desired_state <> 'terminated';
