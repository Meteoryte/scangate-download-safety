# Deferred resolution

DEFERRED is an open commitment state, not a permanent dead end. Work it through without
editing the original receipt or letting artifact content enter a general model context.

## Evidence sequence

1. Keep the original `_source/` and payload unchanged.
2. Run `scan:formats` against the payload directory. A blocker stops resolution.
3. Optionally run `scan:defender` against `_source/` on Windows. It disables remediation
   and records only engine metadata and the source-tree digest.
4. Review warning rule IDs and counts. The tooling never prints extracted text, URLs,
   secrets, JavaScript bodies, or binary strings.
5. Reconcile every governance candidate by exact path and SHA-256.
6. Run `scan:resolve` with an accountable identity and additive landing directory.
7. Run `scan:weekly`; both the landed bytes and original provenance must verify.

`NO_FINDINGS` still does not mean safe. A `REVIEW` result records expected or unresolved
capabilities for an accountable decision. `scan:resolve` cannot waive a blocker.

## Governance decision schema

When `formatReview.governanceCandidates` is non-empty, provide a JSON file whose candidate
set exactly matches the report:

```json
{
  "schemaVersion": 1,
  "decidedAt": "2026-01-01T00:00:00.000Z",
  "decidedBy": "accountable identity",
  "disposition": "VERIFIED-NO-FOLD",
  "basis": "Exact-installed or canonical authority is newer.",
  "candidates": [
    {
      "path": "protocols/EXAMPLE_PROTOCOL.md",
      "sha256": "<64 lowercase hexadecimal characters>"
    }
  ]
}
```

Closed dispositions are `ADOPTED`, `MIRROR`, `VERIFIED-NO-FOLD`, or `REJECTED`.
`PULLED` and `DEFERRED` do not close governance. A genuine new protocol must go through
the caller's normalization, ownership, routing, and activation process before its
candidate can be marked adopted.

## Receipt lineage

The resolver creates a new receipt with:

- `supersedes_receipt_id`: the immutable DEFERRED receipt;
- `quarantine_entry_id`: the original source/payload evidence location;
- exact hashes for the landed bytes and evidence reports;
- accepted warning rule IDs;
- governance candidate count and final disposition;
- the accountable ALLOW decision.

The original receipt remains valid evidence of the earlier decision. The resolution
receipt records why a later decision was justified. Neither is silently rewritten.
