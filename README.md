# SCANGATE Download Safety

SCANGATE is a fail-closed intake pipeline for files, archives, repositories, prompt packs,
plugins, skills, model assets, and other content that should not enter an agent's context
before it has been checked.

The core rule is simple: foreign bytes stream directly into quarantine. Deterministic
checks and optional detonation run without sending file content to a model. An accountable
decision is bound to the exact adopted bytes by a signed receipt. Later drift invalidates
the evidence.

NO_FINDINGS means no known-bad behavior was found. It never means safe.

## What is included

- Remote downloads stream directly into quarantine and can be checked against a
  provider-declared byte count.
- Archive names are validated before extraction, including traversal, device names,
  Unicode deception, zip bombs, duplicate paths, encryption, and symlinks.
- NVIDIA SkillSpector runs in a pinned, offline, read-only Docker container.
- Local checks cover Unicode deception, entropy, hidden paths, inspection gaps, pickle
  execution opcodes, safetensors bounds, and GGUF headers.
- Executable content can be detonated in a disposable no-network container.
- Format-native, model-blind review covers JSON, SVG, HTML, PDF, DOCX, APK, tar.gz,
  and mixed source trees without printing extracted content.
- An optional non-remediating Microsoft Defender pass can corroborate the exact source
  tree on Windows.
- Trust uses exact ASCII identities. Unknown sources default to T3. Exact artifact
  demotions override trusted wildcard containers without affecting siblings.
- HMAC-signed receipts attest the real adopted file or directory.
- A DEFERRED decision can be resolved additively: the original signed receipt remains
  immutable and a new signed receipt supersedes it against the same quarantine evidence.
- A weekly sweep checks adopted-byte drift, blocked-payload reappearance, provenance
  mutation, stale receipts, and landing-zone coverage.
- A PreToolUse hook can deny model access to quarantine unless a valid ALLOW receipt
  exists.

## Requirements

- Node.js 22 or newer
- pnpm 11.12.0
- Git and curl
- Docker Engine or Docker Desktop for stages 1 and 2

## Quick start

Install and build the pinned scanner images:

    corepack enable
    pnpm install
    pnpm run scan:build

Intake a remote file. Pass the provider's exact size whenever it is available:

    pnpm run scan:intake -- "https://files.example.test/artifact.zip" --name "artifact.zip" --size 123456

The command returns a quarantine ID, directory, and tier. Run static scanning against the
payload directory:

    pnpm run scan:run -- "_quarantine/<id>/payload" T3

For an explicit low-token intake choice, answer with full `yes` or `no` tokens:

    pnpm run scan:user-choice -- <url-or-path> --defer-scans yes --by human/chuck
    pnpm run scan:user-choice -- <url-or-path> --defer-scans no --trusted-source yes --by human/chuck

`defer-scans yes` writes a signed DEFERRED receipt and keeps the artifact unreadable.
`trusted-source yes` binds the attestation to the exact payload tree, still runs mandatory
deterministic Stage 1, retains all findings, and can ALLOW that exact payload for review
only when it remains below the T1 threshold. It is not an adoption, install, release,
deletion, or side-effect authorization. Use `trusted-source no` for the full tier-resolved
pipeline.

If the payload contains executable content, detonate it:

    pnpm run scan:detonate -- "_quarantine/<id>/payload"

An operator then reviews only the structured evidence. For an ALLOW decision, land the
byte-preserved artifact additively, then bind the receipt to that real destination:

    pnpm run scan:dispose -- <id> --decision ALLOW --by <accountable-identity> --adopted-path "landing/artifact.zip"

For unresolved or rejected content:

    pnpm run scan:dispose -- <id> --decision DEFERRED --by <accountable-identity>
    pnpm run scan:dispose -- <id> --decision REJECTED --by <accountable-identity> --purge

To work through a DEFERRED artifact, run the format-native review against its payload:

    pnpm run scan:formats -- "_quarantine/<id>/payload" --output format-review.json

On Windows, an optional Defender corroboration can bind a second engine to the original
source tree without allowing remediation:

    pnpm run scan:defender -- "_quarantine/<id>/_source" --output defender-review.json

If the format report lists governance candidates, reconcile every exact path/hash first
using the decision schema in docs/DEFERRED-RESOLUTION.md. Then create an additive
supersession receipt and land the byte-preserved source:

    pnpm run scan:resolve -- <id> --by <accountable-identity> --landing-dir landing --format-report format-review.json --defender-report defender-review.json --governance-decision governance-decision.json --commitment-state MIRROR

The Defender and governance flags are optional when not applicable. Format blockers are
never waivable by this command. `REVIEW` warnings require the accountable `--by` decision
and remain recorded in the signed receipt.

Run the drift sweep on a schedule:

    pnpm run scan:weekly

Set SCANGATE_LANDING_ZONES to the platform-delimited list of directories you want included
in coverage reporting. The default is landing.

## Batch and Drive intake

The repository intentionally does not embed a provider credential or a Drive folder ID.
For an approval-gated batch, use the provider-neutral sequence in
docs/PROVIDER-BATCH-RUNBOOK.md: list, diff, approve the exact file list, stream each file
directly to quarantine, record pull-time commitment state, scan, dispose, update the
manifest, reconcile, and verify any outbound report at the provider.

## Security boundaries

Read docs/THREAT-MODEL.md before deploying. The quarantine hook is an integration point,
not a universal operating-system policy. Install it in every agent surface that can read
workspace files, and keep the receipt key outside version control.

The scanner pin is a trust anchor. Verify it with pnpm run scan:anchor and apply the
N-1-scans-N review described in docs/PROTOCOL.md before changing it.

## Tests

    pnpm test

The suite is dependency-free and exercises path containment, archive handling, intake,
trust, scan parsing, detonation, format-native review, immutable receipt resolution,
hooks, and weekly drift behavior.

## License

MIT. SkillSpector is a separate NVIDIA project licensed under Apache-2.0 and is fetched at
the exact commit recorded in docker/skillspector.pin.json.
