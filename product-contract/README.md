# Sandbox Runtime Product Contract

This directory contains the independent Product control-plane Contract. It is
not part of the Sandbox Provider Contract under `contract/`.

Current identity:

- namespace: `urn:shell-echo:sandbox-runtime:product-v1alpha1`
- design version: `0.1.0`
- maturity: Phase 1 design authority; implementation incomplete
- manifest: `sha256:7f7c5264693f4f01c47fcda6e27f0add609b4bec9549bc2a10338517dcef7cba`
- resource tree: `sha256:a5c9cfa4fdfcdb481336732b4b33de39b57ef6e30dc668b95a0cf524b143b4d1`

Normative resources are listed by
`compatibility/contract-manifest.json` and content-addressed by
`compatibility/contract.lock.json`. A route or schema in this design does not
claim that the Product, Gateway, Guest Agent, or a backing Provider currently
implements it. Product Phase 3 Slice 2 implements only the authenticated
capability, Workspace-create/read, and operation-read handler subset; it has no
deployable listener and advertises no Product capability. Runtime advertisement
must remain empty for incomplete capabilities. The locked fixture and three-case conformance seed
cover only the first Product transport slice and are not a complete Phase 3
or compatibility claim.

The Provider compatibility lock and Provider Conformance Suite remain wholly
separate.
