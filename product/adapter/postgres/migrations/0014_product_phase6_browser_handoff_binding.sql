-- Browser v2 caller metadata is immutable per exact Provider handoff. The
-- runtime_sessions row remains the sole current-handoff selector.
CREATE TABLE sandbox_runtime_product.browser_handoff_binding_metadata (
    tenant_id text NOT NULL,
    product_session_id text NOT NULL,
    provider_instance_audience text NOT NULL,
    handoff_reference text NOT NULL,
    caller_authority_scope text NOT NULL,
    key_binding_id text NOT NULL,
    key_version text NOT NULL,
    key_reference text NOT NULL,
    key_purpose text NOT NULL,
    key_role text NOT NULL,
    key_binding_digest text NOT NULL,
    provider_revision_id text NOT NULL,
    sandbox_id text NOT NULL,
    browser_session_id text NOT NULL,
    capability_profile_id text NOT NULL,
    connection_generation bigint NOT NULL,
    tenant_binding_digest text NOT NULL,
    handoff_expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT browser_handoff_binding_metadata_pk PRIMARY KEY
        (tenant_id, product_session_id, provider_instance_audience, handoff_reference),
    CONSTRAINT browser_handoff_binding_metadata_session FOREIGN KEY (tenant_id, product_session_id)
        REFERENCES sandbox_runtime_product.runtime_sessions (tenant_id, session_id) ON DELETE RESTRICT,
    CONSTRAINT browser_handoff_binding_metadata_reference CHECK
        (handoff_reference ~ '^ref:browser-session:[0-9a-f]{32}$'),
    CONSTRAINT browser_handoff_binding_metadata_identity CHECK
        (provider_instance_audience ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'
         AND caller_authority_scope ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'
         AND provider_revision_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'
         AND sandbox_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'
         AND browser_session_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'
         AND capability_profile_id = 'browser-v1'),
    CONSTRAINT browser_handoff_binding_metadata_key CHECK
        (key_binding_id ~ '^[a-z][a-z0-9._-]{0,63}$'
         AND key_version ~ '^[a-z0-9][a-z0-9._-]{0,63}$'
         AND key_reference LIKE 'secret://%'
         AND octet_length(key_reference) BETWEEN 10 AND 512
         AND key_purpose = 'browser_tenant_binding_key'
         AND key_role IN ('product','gateway')
         AND key_binding_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT browser_handoff_binding_metadata_digest CHECK
        (tenant_binding_digest ~ '^hmac-sha256:v2:[0-9a-f]{64}$'),
    CONSTRAINT browser_handoff_binding_metadata_generation CHECK
        (connection_generation BETWEEN 1 AND 9007199254740991),
    CONSTRAINT browser_handoff_binding_metadata_expiry CHECK (handoff_expires_at > created_at)
);

CREATE INDEX browser_handoff_binding_metadata_retention
    ON sandbox_runtime_product.browser_handoff_binding_metadata (handoff_expires_at, tenant_id, product_session_id);

CREATE FUNCTION sandbox_runtime_product.reject_browser_handoff_binding_update()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'browser handoff binding metadata is immutable' USING ERRCODE = 'check_violation';
END;
$$;

CREATE TRIGGER browser_handoff_binding_metadata_immutable
    BEFORE UPDATE ON sandbox_runtime_product.browser_handoff_binding_metadata
    FOR EACH ROW EXECUTE FUNCTION sandbox_runtime_product.reject_browser_handoff_binding_update();

-- Null preserves historical v1 grants for compatibility reads. A v3 grant
-- constructor must require both fields and the immutable metadata FK.
ALTER TABLE sandbox_runtime_product.connection_grants
    ADD COLUMN browser_binding_audience text,
    ADD COLUMN browser_binding_reference text,
    ADD CONSTRAINT connection_grants_browser_binding_pair CHECK
        ((browser_binding_audience IS NULL) = (browser_binding_reference IS NULL)),
    ADD CONSTRAINT connection_grants_browser_binding_metadata FOREIGN KEY
        (tenant_id, session_id, browser_binding_audience, browser_binding_reference)
        REFERENCES sandbox_runtime_product.browser_handoff_binding_metadata
        (tenant_id, product_session_id, provider_instance_audience, handoff_reference) ON DELETE RESTRICT;
