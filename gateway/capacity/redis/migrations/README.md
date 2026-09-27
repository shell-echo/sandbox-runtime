# PostgreSQL Action-History Witness

Apply `0001_action_history_witness.sql` with a migration owner before starting
the witnessed-v2 runtime. Runtime startup never creates or alters this schema.

Use three distinct identities: a migration owner for schema DDL, a one-shot
provisioning identity for the initial witness row, and the ingress runtime
identity for `Load`, `Verify`, `AuthorizeAction` and conditional
`CompareAndSwap`. The runtime must never call `Provision` or receive `INSERT`:

```sql
-- Run only on a dedicated witness database after reviewing existing users.
REVOKE CREATE, TEMPORARY ON DATABASE your_database FROM PUBLIC;
GRANT CONNECT ON DATABASE your_database TO sandbox_runtime_witness;
GRANT USAGE ON SCHEMA sandbox_runtime TO sandbox_runtime_witness;
GRANT SELECT ON TABLE sandbox_runtime.action_history_witnesses
    TO sandbox_runtime_witness;
GRANT UPDATE (sequence, token, updated_at)
    ON TABLE sandbox_runtime.action_history_witnesses TO sandbox_runtime_witness;

GRANT CONNECT ON DATABASE your_database TO sandbox_witness_provisioner;
GRANT USAGE ON SCHEMA sandbox_runtime TO sandbox_witness_provisioner;
GRANT SELECT ON TABLE sandbox_runtime.action_history_witnesses
    TO sandbox_witness_provisioner;
GRANT INSERT (namespace_fingerprint, policy_fingerprint, format_version, sequence, token)
    ON TABLE sandbox_runtime.action_history_witnesses TO sandbox_witness_provisioner;
```

When upgrading an earlier grant set, explicitly revoke both table-level and
column-level `INSERT` from the runtime role before admitting traffic:

```sql
REVOKE CREATE, TEMPORARY ON DATABASE your_database
    FROM sandbox_runtime_witness;
REVOKE INSERT ON TABLE sandbox_runtime.action_history_witnesses
    FROM sandbox_runtime_witness;
REVOKE INSERT (namespace_fingerprint, policy_fingerprint, format_version, sequence, token)
    ON TABLE sandbox_runtime.action_history_witnesses FROM sandbox_runtime_witness;
```

Inspect role memberships and every applicable direct/inherited table grant;
revoke any membership or grant that would still let the runtime `INSERT` or
`SET ROLE` into a provisioning/migration identity. Verify denial with a valid
row insert and SQLSTATE `42501` before startup. Do not run this upgrade SQL
automatically against an unreviewed database. The runtime role must not own
the database, schema, or table and must not have `CREATE`, `DELETE`,
`TRUNCATE`, `REFERENCES`, `TRIGGER`, role-management, or privilege-escalation
authority. It must not receive database `TEMPORARY` from `PUBLIC` or another
role membership. Production action-ingress startup checks the effective
current/session role, database, required read/CAS grants, forbidden table and
column grants, ownership, role memberships and escalation attributes; it
refuses an overly privileged account even if its configured username matches.
Keep provisioning and migration credentials out of both Gateway
and action ingress; the provisioning identity is a one-shot operator path,
not another long-running service. The column-scoped `UPDATE` grant and the
adapter's CAS predicate are separate controls: a compromised runtime holding
the SQL credential can still modify the granted columns, so this is not a
general hostile-runtime integrity claim.

Deploy this database in a failure, backup, snapshot, restore, and access-control
domain independent from the Redis-compatible capacity authority. A correlated
rollback of both stores is not detectable. Do not run a restore check until the
unique private ingress is quarantined, and do not resume it unless
`VerifyRestoredState` succeeds against the retained witness.
