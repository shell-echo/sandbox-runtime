ALTER TABLE sandbox_runtime_product.runtime_sessions
    DROP CONSTRAINT runtime_sessions_implemented_profile_shape,
    ADD CONSTRAINT runtime_sessions_implemented_profile_shape CHECK (
        (kind = 'terminal' AND protocol_profile = 'product-terminal.v1')
        OR (kind = 'browser_automation' AND protocol_profile = 'product-browser-automation.v1')
        OR (kind = 'browser_live' AND protocol_profile = 'product-browser-live.v1')
        OR (kind = 'desktop' AND protocol_profile = 'product-desktop.v1')
        OR kind NOT IN ('terminal', 'browser_automation', 'browser_live', 'desktop')
    );

ALTER TABLE sandbox_runtime_product.workspace_slots
    ADD CONSTRAINT workspace_slots_desktop_profile_shape CHECK (
        kind <> 'desktop'
        OR (
            profile_id = 'sandbox-runtime-desktop-v1'
            AND required_capabilities =
                '[{"capability_id":"sandbox.desktop","version":"1.0.0","profile_id":"desktop-v1"}]'::jsonb
        )
    );

ALTER TABLE sandbox_runtime_product.tenant_quotas
    ADD COLUMN max_desktop_slots integer NOT NULL DEFAULT 4,
    ADD COLUMN max_desktop_sessions integer NOT NULL DEFAULT 16,
    ADD CONSTRAINT tenant_quotas_desktop_bounds CHECK (
        max_desktop_slots BETWEEN 1 AND 64
        AND max_desktop_sessions BETWEEN 1 AND 256
    );

CREATE INDEX workspace_slots_desktop_quota_index
    ON sandbox_runtime_product.workspace_slots (tenant_id, desired_state)
    WHERE kind = 'desktop' AND desired_state <> 'terminated';

CREATE INDEX runtime_sessions_desktop_reconciliation
    ON sandbox_runtime_product.runtime_sessions (tenant_id, state, expires_at, session_id)
    WHERE kind = 'desktop'
      AND state IN ('requested', 'provisioning', 'ready', 'active', 'draining');

CREATE UNIQUE INDEX runtime_sessions_one_live_desktop_slot
    ON sandbox_runtime_product.runtime_sessions (tenant_id, workspace_id, slot_key)
    WHERE kind = 'desktop'
      AND state IN ('requested', 'provisioning', 'ready', 'active', 'draining');
