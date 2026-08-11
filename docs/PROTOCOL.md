# SCANGATE protocol

Version 1.1.0

## Trigger

Apply this gate before downloading, importing, installing, cloning, unpacking, adopting,
or allowing a model to read any external artifact. This includes documents, archives,
repositories, skills, plugins, hooks, prompt packs, protocol packs, executables, and model
assets.

Reading is part of the threat surface. A malicious instruction file can compromise an
agent as soon as its content enters context, even if the file is never installed or run.

## Required stages

### Stage 0: quarantine

1. Obtain provider metadata without reading artifact content.
2. For a batch, diff stable provider IDs and modified times against a manifest.
3. Obtain approval for the exact transfer list and total size.
4. Stream bytes directly into _quarantine through scan:intake.
5. Validate provider-declared size when supplied.
6. Preserve the source bytes under _source and never overwrite an existing entry.
7. Validate every archive member before extraction.
8. Record pull-time commitment state in the caller's durable system of record.

No model may read the artifact.

### Stage 1: deterministic static scanning

Run scan:run. SkillSpector executes offline in a read-only container with no model. Local
checks add path, Unicode, entropy, inspection-coverage, and model-weight analysis.

Any scanner failure, malformed output, incomplete coverage, or unparseable artifact fails
closed. Output is structured metadata; artifact content is not printed.

### Stage 2: isolated detonation

Run scan:detonate for content that is executable or has lifecycle hooks. The container has
no network, no added capabilities, no new privileges, bounded memory and process count,
and no Docker socket. Filesystem changes become evidence.

Docker is not a kernel boundary. Detonation reduces risk; it does not prove safety.

### Stage 3: semantic review

Semantic review is an integration boundary. If a sealed reviewer is available, it must
have read-only access only to the one quarantined artifact and return a strict structured
verdict. It receives no credentials, network, shell, provider tools, or mutation
authority. Malformed output is BLOCKED.

Do not send raw quarantined content to a general-purpose agent.

### Stage 4: accountable decision

The allowed decisions are ALLOW, BLOCKED, REJECTED, and DEFERRED. A person decides for T2
or T3 findings. A deployment may preauthorize exact T1 artifacts to auto-ALLOW only when
all deterministic stages return NO_FINDINGS and the approval record binds the container
and exact artifact identity.

Automatic demotion is allowed. Automatic promotion is not.

### Stage 5: additive landing and signed receipt

ALLOWed bytes land additively. Existing files are not silently overwritten. The receipt
must attest the actual adopted file or directory, not only its quarantine copy. Non-ALLOW
decisions cannot carry an adopted path.

The receipt records provenance, tier, decision, decider, timestamps, content hashes, and
evidence. Any later byte mutation is drift.

## Trust

Identity matching is exact, ASCII-only, and case-insensitive. Host, organization or
container, and repository or artifact identity are distinct fields.

| Tier | Meaning | Maximum score |
|---|---|---:|
| T0 | Scanner trust anchor, pinned by commit SHA | Not score-derived |
| T1 | Verified first-party source | 50 |
| T2 | Known but unaudited or exactly demoted artifact | 50 |
| T3 | Unknown, the default | 20 |
| T4 | Denylisted | Never admitted |

Critical findings score 50, high 25, medium 10, and low 5. Scores accumulate.

A trusted wildcard container does not erase artifact identity. An exact artifact demotion
is evaluated before the wildcard source, so one bad file cannot either inherit T1 or
revoke every clean sibling.

## Verdict language

Only BLOCKED, NO_FINDINGS, and FINDINGS_ACCEPTED are scan verdicts. SAFE is deliberately
absent.

## Drift and provenance

Run scan:weekly on a schedule:

- ALLOWed artifacts are checked at adopted_path, including single-file targets.
- A purged blocked payload that reappears is tampering.
- Preserved _source bytes are compared with the decision-time provenance digest.
- A receipt that predates provenance hashing is unverifiable, not tampering.
- Stale receipts report loudly but do not silently revoke all access.

## Scanner upgrades

The scanner is privileged and therefore pinned by full commit SHA. Before changing the
pin, have scanner version N-1 inspect candidate N, review the source diff and dependency
changes, and confirm that detection capability was not silently removed. The current
anchor command produces evidence; a human still decides whether to promote the candidate.

Scanner source contains attack fixtures and rules, so an absolute risk score is not a
useful pass/fail threshold for the scanner itself. Compare candidate findings
differentially against the incumbent baseline.

## Honest limits

- NO_FINDINGS is not SAFE.
- HMAC receipts defend against ordinary agent writes and accidental drift, not an attacker
  with arbitrary host filesystem access.
- Docker raises the cost of execution but does not contain a kernel-level escape.
- Static and semantic review can both miss packed or novel behavior.
- The model-read hook must be installed on each agent surface; this repository cannot
  enforce operating-system policy by itself.
