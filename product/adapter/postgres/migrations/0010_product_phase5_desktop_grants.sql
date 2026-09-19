ALTER TABLE sandbox_runtime_product.tenant_quotas
    ADD COLUMN max_desktop_viewers integer NOT NULL DEFAULT 16,
    ADD COLUMN max_desktop_controllers integer NOT NULL DEFAULT 16,
    ADD CONSTRAINT tenant_quotas_desktop_connections_bounds CHECK (
        max_desktop_viewers BETWEEN 1 AND 1000
        AND max_desktop_controllers BETWEEN 1 AND 64
    );

ALTER INDEX sandbox_runtime_product.connection_grants_one_browser_controller
    RENAME TO connection_grants_one_session_controller;

CREATE INDEX connection_grants_live_quota_admission
    ON sandbox_runtime_product.connection_grants (tenant_id, access_mode, expires_at)
    WHERE state IN ('issued', 'consumed');
