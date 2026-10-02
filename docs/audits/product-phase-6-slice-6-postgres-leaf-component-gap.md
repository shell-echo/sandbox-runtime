# Phase 6 Slice 6 PostgreSQL leaf component gap (non-release)

On 2026-10-02, temporary run `889e1fbba5416e2e8fce7b390cecc5c2`
signed an external PostgreSQL server leaf in a real file-backed Vault under
general issuer `58417845-2a81-8937-8555-e96615a2dd62` (issuer DER
`sha256:de2d2c437c6e2dc3cde7c7268a20efadf78f1e869d7f0e646300111a7e18da43`).
The leaf DER was `sha256:dca04ab50d9890fb41368dc3533c92960f09133e05b6b28b2360fbe884b3fbf1`,
serial `1c:a1:8c:eb:2e:7a:f7:fd:22:d8:e7:a1:5a:f9:70:8c:90:5e:d8:e1`.
The test observed its exact issuer, URI, DNS, P-256 key match, ServerAuth-only
EKU, non-CA constraints and lifetime, rejected foreign URI/DNS CSRs, and
confirmed controller/management tokens could not sign through this role.
No PostgreSQL process was launched.

This run started before the explicit terminal-cleanup v2 decision. Its
source-bound v1 one-shot operator confirmed only the two controller
certificates and two token accessors. **Revocation of the PostgreSQL leaf and
its presence in a complete CRL were not confirmed.** The v1 receipt and
physical deletion do not cure that evidence gap. The run-owned Vault was
destroyed after root-token revocation; the unconfirmed leaf cannot be used as
release evidence or retroactively counted as revoked. A new run must enforce
v2 before signing and independently confirm all three certificate targets.

After the test, exact run-label queries found zero containers, networks and
volumes. The exact temporary directory, including the private PostgreSQL key,
was absent. No secret or private key is retained in this audit.
