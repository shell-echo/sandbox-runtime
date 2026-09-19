ALTER TABLE sandbox_runtime_product.connection_grants
    ADD COLUMN gateway_lease_expires_at timestamp with time zone;

CREATE INDEX connection_grants_gateway_recovery
    ON sandbox_runtime_product.connection_grants (tenant_id, gateway_lease_expires_at)
    WHERE state = 'consumed' AND gateway_lease_expires_at IS NOT NULL;
