# Sandbox Runtime Product Contract

This directory contains the independent Product control-plane Contract. It is
not part of the Sandbox Provider Contract under `contract/`.

Current identity:

- namespace: `urn:shell-echo:sandbox-runtime:product-v1alpha1`
- design version: `0.1.0`
- maturity: Phase 1 design authority; implementation incomplete
- manifest: `sha256:fa933c55b9025ba5d0d6661eb023d76de075676089342cab83bab9bacfbda007`
- resource tree: `sha256:3cbd422e7753768be6ed6510d62b0b78f63abd4c383179c91bd3a5ab73375562`

Normative resources are listed by
`compatibility/contract-manifest.json` and content-addressed by
`compatibility/contract.lock.json`. A route or schema in this design does not
claim that the Product, Gateway, Guest Agent, or a backing Provider currently
implements it. Product Phase 3 Slice 1 adds only a PostgreSQL command kernel;
it implements no Product route. Runtime advertisement must remain empty for
incomplete capabilities.

The Provider compatibility lock and Provider Conformance Suite remain wholly
separate.
