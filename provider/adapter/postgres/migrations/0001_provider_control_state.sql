CREATE TABLE sandbox_runtime_provider.control_state (
    singleton boolean PRIMARY KEY DEFAULT true,
    revision bigint NOT NULL DEFAULT 0,
    documents jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamp with time zone NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT control_state_singleton CHECK (singleton),
    CONSTRAINT control_state_revision CHECK (revision >= 0),
    CONSTRAINT control_state_documents_object CHECK (jsonb_typeof(documents) = 'object')
);

REVOKE ALL ON TABLE sandbox_runtime_provider.control_state FROM PUBLIC;

INSERT INTO sandbox_runtime_provider.control_state (singleton)
VALUES (true)
ON CONFLICT (singleton) DO NOTHING;
