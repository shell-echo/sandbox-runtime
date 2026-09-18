ALTER TABLE sandbox_runtime_product.connection_grants
    ADD COLUMN access_mode text NOT NULL DEFAULT 'control',
    ADD CONSTRAINT connection_grants_access_mode CHECK (access_mode IN ('view','control'));

ALTER TABLE sandbox_runtime_product.tenant_quotas
    ADD COLUMN max_browser_viewers integer NOT NULL DEFAULT 16,
    ADD COLUMN max_browser_controllers integer NOT NULL DEFAULT 16,
    ADD CONSTRAINT tenant_quotas_browser_connections_bounds CHECK (
        max_browser_viewers BETWEEN 1 AND 1000
        AND max_browser_controllers BETWEEN 1 AND 64
    );

CREATE UNIQUE INDEX connection_grants_one_browser_controller
    ON sandbox_runtime_product.connection_grants (tenant_id, session_id)
    WHERE access_mode = 'control' AND state IN ('issued','consumed');
