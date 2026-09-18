ALTER TABLE sandbox_runtime_product.product_operation_attempts
    ADD COLUMN provider_action text,
    ADD CONSTRAINT product_operation_attempts_provider_action CHECK (
        provider_action IS NULL OR provider_action IN (
            'create', 'suspend', 'resume', 'terminate',
            'open_runtime_session', 'close_runtime_session',
            'open_browser_session', 'terminate_browser_session'
        )
    );

ALTER TABLE sandbox_runtime_product.provider_bindings
    ADD COLUMN provider_generation bigint NOT NULL DEFAULT 1,
    ADD CONSTRAINT provider_bindings_provider_generation CHECK (provider_generation >= 1);

DROP INDEX sandbox_runtime_product.provider_bindings_one_current;
CREATE UNIQUE INDEX provider_bindings_one_current
    ON sandbox_runtime_product.provider_bindings (tenant_id, workspace_id, slot_key)
    WHERE current;

CREATE UNIQUE INDEX runtime_sessions_one_live_browser_slot
    ON sandbox_runtime_product.runtime_sessions (tenant_id, workspace_id, slot_key)
    WHERE kind IN ('browser_automation', 'browser_live')
      AND state IN ('requested', 'provisioning', 'ready', 'active', 'draining');
