# Sandbox Runtime Product Contract

This directory contains the independent Product control-plane Contract. It is
not part of the Sandbox Provider Contract under `contract/`.

Current identity:

- namespace: `urn:shell-echo:sandbox-runtime:product-v1alpha1`
- design version: `0.1.0`
- maturity: Phase 1 design-definition authority; Phase 3 implementation
  evidence is recorded separately
- manifest: `sha256:7f7c5264693f4f01c47fcda6e27f0add609b4bec9549bc2a10338517dcef7cba`
- resource tree: `sha256:9bf1b35f343fb2a19574c064ad6a7ad29f29216ee22305665ad98f89a414fd7f`

Normative resources are listed by
`compatibility/contract-manifest.json` and content-addressed by
`compatibility/contract.lock.json`. A route or schema in this design does not
by itself claim implementation, availability, compatibility, or readiness.
Product Phase 3 is complete at 13/13 for its separately recorded bounded
standalone scope: Product, Gateway, Guest, and a locked-wire Provider fixture
ran as separate OS processes against fresh pinned PostgreSQL, and the exact
nine-scenario matrix plus strict evidence validation passed. Capability
advertisement in that gate is tenant-aware and dependency-derived; incomplete
dependency graphs remain unavailable rather than being promoted by schema or
configuration alone.

That result does not change this Contract's v1alpha1 version or Phase 1
design-definition maturity. The locked fixtures and three-case conformance
seed remain definition and initial transport evidence, not a complete Product
compatibility suite. The Phase 3 gate supplies no deployable listener
configuration, independently implemented caller, HA, hostile-multitenant,
deployment, or production-readiness claim.

The Provider compatibility lock and Provider Conformance Suite remain wholly
separate.
