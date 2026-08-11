# Contributing

Changes to trust resolution, receipt verification, path containment, archive extraction,
or fail-closed behavior require regression tests. Never weaken a block merely to make a
fixture pass.

Before opening a pull request:

1. Run pnpm test.
2. Confirm no secrets, receipts, quarantine payloads, or real provider identifiers are
   staged.
3. Explain the threat-model assumption changed by the patch.
4. Treat automatic promotion of trust as out of scope; demotion may be automatic,
   promotion requires an accountable maintainer decision.
