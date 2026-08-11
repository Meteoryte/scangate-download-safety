# Provider batch runbook

This sequence works for Drive, object storage, release assets, or any provider that can
list stable file IDs and stream content.

## 1. List without content ingestion

Collect provider ID, relative name, modified time, declared size, and parent container.
Also inspect the provider's handoff or request control area if one exists. Listing metadata
does not authorize a transfer.

## 2. Diff the manifest

Use stable provider ID as the primary key. New means the ID is absent. Updated means the
provider modified time is later than the recorded value. Do not use a filename as the
identity.

## 3. Approve the exact scope

Present new and updated files separately with the total byte count. Obtain approval for
that exact list. Approval to check a drop folder is not approval to transfer an unknown
batch.

## 4. Stream directly to quarantine

For each approved file, run scan:intake against a provider download URL and supply the
provider name and exact byte count. Do not download to a temporary workspace folder first.
On mismatch or transfer failure, retain no successful manifest state.

Create a pull-time commitment row immediately. PULLED means the bytes arrived; it does not
mean adopted.

## 5. Scan and demote precisely

Run static scanning for every file. Run detonation where executable content warrants it.
If an approved first-party container is T1, bind each file to its stable provider ID.
Critical or high evidence demotes that exact artifact to T2 before disposition. Never
demote the whole wildcard container merely because one sibling has findings.

## 6. Dispose and land

Only exact T1 artifacts with NO_FINDINGS may use a narrowly preauthorized automatic ALLOW
policy. Everything else needs an accountable decision. Land ALLOWed files additively.
Name collisions receive a deterministic suffix such as provider modified date. Keep
DEFERRED files in quarantine.

Write a signed receipt over the actual landed path.

## 7. Reconcile rather than overwrite

Compare approved files to canonical and retained copies by hash before reading content.
Exact matches can close as verified-no-fold or mirror. Guidance, policies, and protocols
must be diffed against their recorded source state and folded into canonical authority;
do not replace a diverged canonical file with a provider copy.

Update commitment state to the final result: adopted, mirror, verified-no-fold, deferred,
or rejected.

## 8. Commit manifest state

Record provider ID, modified time, declared size, download time, disposition, receipt ID,
and landed or quarantine path only after each file reaches the stated result. Report
per-file failures honestly.

## 9. Close the provider loop

Generate an adoption report containing counts, deferred risks, canonical divergences, and
requests. Upload it to the provider control area. Then re-list and re-read the provider
copy. Only call it delivered when exact title, parent, readability, and content have been
verified.

## Reference batch

The sanitized production exercise in docs/REFERENCE-RUN-2026-08-11.md demonstrates why
exact artifact demotion and additive landing matter at batch scale.
