BEGIN;

CREATE SCHEMA IF NOT EXISTS sandbox_runtime;
REVOKE ALL ON SCHEMA sandbox_runtime FROM PUBLIC;

CREATE TABLE sandbox_runtime.action_history_witnesses (
    namespace_fingerprint bytea NOT NULL,
    policy_fingerprint bytea NOT NULL,
    format_version smallint NOT NULL,
    sequence bigint NOT NULL,
    token bytea NOT NULL,
    updated_at timestamp with time zone NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT action_history_witnesses_primary_key
        PRIMARY KEY (namespace_fingerprint, policy_fingerprint),
    CONSTRAINT action_history_witnesses_namespace_length
        CHECK (octet_length(namespace_fingerprint) = 32),
    CONSTRAINT action_history_witnesses_policy_length
        CHECK (octet_length(policy_fingerprint) = 32),
    CONSTRAINT action_history_witnesses_format_version
        CHECK (format_version = 1),
    CONSTRAINT action_history_witnesses_sequence_range
        CHECK (sequence >= 0 AND sequence <= 999999999999999),
    CONSTRAINT action_history_witnesses_token_length
        CHECK (octet_length(token) = 32)
);

REVOKE ALL ON TABLE sandbox_runtime.action_history_witnesses FROM PUBLIC;

COMMIT;
