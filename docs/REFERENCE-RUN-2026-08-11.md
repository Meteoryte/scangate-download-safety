# Sanitized reference run — 2026-08-11

A provider inventory contained 551 files in 85 folders. Manifest comparison found 167
previously untracked provider IDs totaling 652,845,176 bytes. The exact list was approved.

All 167 files streamed directly to quarantine. Provider sizes matched and no transfer was
recorded as successful before its bytes arrived.

Static analysis returned NO_FINDINGS for 145 files totaling 11,356,686 bytes. Those files
received signed ALLOW receipts and additive landing. Twenty-two files totaling 641,488,490
bytes contained opaque package formats or unresolved high-severity or coverage evidence.
They received exact-artifact T2 demotions and signed DEFERRED receipts and remained in
quarantine.

A later authorized deferred pass inspected all 22 model-blind with format-native parsers.
It validated archive structure; DOCX active-content surfaces; PDF actions, JavaScript,
links, and decoded streams; APK structure, DEX capability strings, and signatures; and
Unicode/codepoint metadata. A non-remediating malware-engine pass returned NO_FINDINGS
for all exact source trees. Four artifacts had no format warnings; 18 retained explicit
review warnings, but none had a format blocker.

Nineteen embedded governance candidates were reconciled before landing. Twelve were
exact-installed, six were older than installed project authority, and one installed
requirements matrix was a strict superset. No new governance needed activation. All 22
artifacts then landed as historical mirrors under additive signed supersession receipts;
the original DEFERRED receipts remained unchanged. Final commitment state was 76
verified-no-fold, 91 mirror, and zero pulled/deferred.

Hash-first reconciliation showed that 139 of the 145 allowed files were byte-identical to
installed or retained copies. The remaining six were preserved as historical mirrors.
No incoming policy or protocol was newer than canonical authority, so no governance body
was overwritten.

The run exposed and fixed four reusable gaps:

1. Remote bytes must stream into quarantine and verify provider size.
2. A trusted batch container needs exact per-artifact identities and exact demotions.
3. Receipts must attest the real landed file or directory.
4. Weekly drift must support single-file adopted targets.

The regression suite after deferred-resolution hardening passed 173 tests. The post-intake weekly sweep
reported zero drift. The result was described as NO_FINDINGS for approved files, never as
proof that they were safe.
