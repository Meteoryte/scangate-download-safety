# Threat model

## Protected assets

- Agent context and instruction hierarchy
- Workspace files and source code
- Credentials reachable by an agent
- Provider connections and external mutation authority
- Integrity of adopted artifacts and their provenance

## Adversaries and failures

SCANGATE addresses malicious or malformed external content, prompt injection inside
documents, path traversal, deceptive filenames, archive bombs, hidden payloads,
self-extracting code, dangerous model-weight serialization, incomplete inspection,
provider truncation, accidental overwrite, receipt drift, and trust inherited through an
overbroad source rule.

It also treats scanner outages and malformed scanner output as security failures. Unknown
does not become clean.

## Out of scope

- A host already compromised with arbitrary local read and write
- Kernel or hypervisor escape
- A malicious accountable administrator who controls both evidence and the receipt key
- Compromise of every independent upstream and local control at once
- Proof that novel malware is absent

## Security invariants

1. Foreign bytes do not pass through an ordinary workspace path before quarantine.
2. No general-purpose model reads quarantine without a valid ALLOW receipt.
3. Source identity is exact and unknown identity defaults to T3.
4. Archive extraction cannot write outside its assigned payload root.
5. Tool failure, parse failure, and incomplete coverage block.
6. Network is disabled during static scanning and detonation.
7. The receipt signs the real adopted bytes and the decision.
8. A content change or invalid signature closes the evidence chain.
9. A clean scan is described as NO_FINDINGS, never as SAFE.

## Deployment notes

Keep .secrets/scangate-receipt.key private and backed up through the host's normal secret
management. Do not commit receipts from real investigations. Restrict direct access to
_quarantine, install the hook on every agent that can read it, and run the weekly sweep
from an account that can read adopted targets but cannot silently rewrite audit history.
