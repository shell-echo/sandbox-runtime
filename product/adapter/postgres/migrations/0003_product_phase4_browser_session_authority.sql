ALTER TABLE sandbox_runtime_product.runtime_sessions
    ADD CONSTRAINT runtime_sessions_implemented_profile_shape CHECK (
        (kind = 'terminal' AND protocol_profile = 'product-terminal.v1')
        OR (kind = 'browser_automation' AND protocol_profile = 'product-browser-automation.v1')
        OR (kind = 'browser_live' AND protocol_profile = 'product-browser-live.v1')
        OR kind NOT IN ('terminal', 'browser_automation', 'browser_live')
    );

CREATE INDEX runtime_sessions_browser_reconciliation
    ON sandbox_runtime_product.runtime_sessions (tenant_id, state, expires_at, session_id)
    WHERE kind IN ('browser_automation', 'browser_live')
      AND state IN ('requested', 'provisioning', 'ready', 'active', 'draining');
