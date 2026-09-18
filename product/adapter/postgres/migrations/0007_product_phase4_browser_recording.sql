ALTER TABLE sandbox_runtime_product.tenant_quotas
    ADD COLUMN max_active_recordings integer NOT NULL DEFAULT 16,
    ADD COLUMN max_recording_bytes bigint NOT NULL DEFAULT 1073741824,
    ADD CONSTRAINT tenant_quotas_recording_bounds CHECK (
        max_active_recordings BETWEEN 1 AND 1000
        AND max_recording_bytes BETWEEN 1048576 AND 1099511627776
    );

CREATE INDEX recordings_tenant_quota_index
    ON sandbox_runtime_product.recordings (tenant_id, state, recording_id)
    INCLUDE (size_bytes);
