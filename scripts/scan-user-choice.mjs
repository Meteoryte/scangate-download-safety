#!/usr/bin/env node
// ---------------------------------------------------------------------------
// scan-user-choice.mjs — explicit, low-token SCANGATE intake choice.
//
// This is not a scan bypass. Stage 0 always contains the artifact. A trusted-source
// choice runs the mandatory deterministic Stage 1 and may open the exact hash-bound
// payload for review; a deferred choice leaves the payload unreadable in quarantine.
// Optional format, Defender, semantic, and detonation depth is skipped only when the
// accountable user selects the trusted-source fast track.
// ---------------------------------------------------------------------------

import fs from 'node:fs';
import path from 'node:path';
import { intake } from './scan-intake.mjs';
import { runStage1 } from './scan-run.mjs';
import { dispose } from './scan-dispose.mjs';
import { QUARANTINE_ROOT, treeDigest } from './scan-core.mjs';

export function parseYesNo(value, label) {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'yes') return true;
  if (normalized === 'no') return false;
  throw new Error(`${label} must be exactly yes or no`);
}

export function choiceMode({ deferScans, trustedSource }) {
  if (deferScans) return 'QUARANTINE_DEFERRED';
  return trustedSource ? 'TRUSTED_FAST_TRACK' : 'FULL_SCAN_REQUIRED';
}

function loadEntry(root, id) {
  const dir = path.join(root, id);
  const metaPath = path.join(dir, 'intake.json');
  if (!fs.existsSync(metaPath)) throw new Error(`no completed quarantine intake: ${id}`);
  const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
  return { id, dir, metaPath, meta, tier: meta.tier || 'T3' };
}

export function applyUserChoice({
  source = null,
  existingId = null,
  deferScans,
  trustedSource = false,
  by,
  root = QUARANTINE_ROOT,
  sourceUrl = null,
  sourceName = null,
  expectedSize = null,
  intakeFn = intake,
  scanFn = runStage1,
  disposeFn = dispose,
}) {
  if (!by || typeof by !== 'string') throw new Error('an accountable identity is required (--by)');
  if (existingId && source) throw new Error('provide a source or --existing-id, not both');
  if (!existingId && !source) throw new Error('a source or --existing-id is required');

  const entry = existingId
    ? loadEntry(root, path.basename(existingId.replace(/[/\\]+$/, '')))
    : intakeFn({ source, root, sourceUrl, sourceName, expectedSize });
  const loaded = loadEntry(root, entry.id);
  const payloadDir = path.join(loaded.dir, 'payload');
  const mode = choiceMode({ deferScans, trustedSource });

  if (mode === 'QUARANTINE_DEFERRED') {
    const evidence = {
      mode: 'USER_DEFERRED',
      scans_run: [],
      authorization_scope: 'QUARANTINE_ONLY',
      limitation: 'No model or consuming tool may read, adopt, install, or execute this payload until a later signed resolution.',
    };
    const disposition = disposeFn({
      id: loaded.id, decision: 'DEFERRED', by, root, evidence,
    });
    return { outcome: 'QUARANTINED_DEFERRED', id: loaded.id, tier: loaded.tier, disposition };
  }

  if (mode === 'FULL_SCAN_REQUIRED') {
    return {
      outcome: 'FULL_SCAN_REQUIRED',
      id: loaded.id,
      tier: loaded.tier,
      next: `pnpm run scan:run -- \"${payloadDir}\" ${loaded.tier}`,
    };
  }

  const digest = treeDigest(payloadDir);
  const attestedAt = new Date().toISOString();
  const trustedMeta = {
    ...loaded.meta,
    source_identity: {
      host: 'local-user',
      org: by,
      repo: `tree-sha256:${digest}`,
    },
    trusted_source_attestation: {
      attested_by: by,
      attested_at: attestedAt,
      decision: 'trusted-source-yes',
      scope: `tree-sha256:${digest}`,
      limitations: 'Mandatory deterministic scanning remains active. This choice does not authorize adoption, installation, release, deletion, or unrelated external mutation.',
    },
    tier: 'T1',
  };
  fs.writeFileSync(loaded.metaPath, JSON.stringify(trustedMeta, null, 2), 'utf8');

  const core = scanFn(payloadDir, 'T1');
  const evidence = {
    mode: 'TRUSTED_SOURCE_FAST_TRACK',
    source_attestation: trustedMeta.trusted_source_attestation,
    mandatory_core_scan: core,
    authorization_scope: core.verdict === 'BLOCKED' ? 'NONE' : 'READ_REVIEW_ONLY',
    optional_stages_skipped: core.verdict === 'BLOCKED'
      ? []
      : ['format-native-depth', 'defender-corroboration', 'model-assisted-semantic-review', 'detonation-unless-required'],
    limitations: [
      'Findings remain visible and are not reclassified.',
      'The receipt does not authorize adoption, installation, release, deletion, or unrelated external mutation.',
    ],
  };

  if (core.verdict === 'BLOCKED') {
    const disposition = disposeFn({
      id: loaded.id, decision: 'BLOCKED', by, root, evidence,
    });
    return { outcome: 'BLOCKED', id: loaded.id, tier: 'T1', core, disposition };
  }

  const disposition = disposeFn({
    id: loaded.id, decision: 'ALLOW', by, root, evidence,
  });
  return {
    outcome: 'TRUSTED_FAST_TRACK_ALLOW_FOR_REVIEW',
    id: loaded.id,
    tier: 'T1',
    core,
    disposition,
  };
}

if (process.argv[1] && process.argv[1].endsWith('scan-user-choice.mjs')) {
  const args = process.argv.slice(2);
  const flag = (name) => {
    const index = args.indexOf(`--${name}`);
    return index >= 0 ? args[index + 1] : null;
  };
  const positional = args.find((arg, index) => index === 0 && !arg.startsWith('--')) || null;

  try {
    const deferScans = parseYesNo(flag('defer-scans'), '--defer-scans');
    const trustedSource = deferScans
      ? false
      : parseYesNo(flag('trusted-source'), '--trusted-source');
    const sizeValue = flag('size');
    const expectedSize = sizeValue == null ? null : Number(sizeValue);
    if (sizeValue != null && (!Number.isSafeInteger(expectedSize) || expectedSize < 0)) {
      throw new Error('--size must be a non-negative integer');
    }
    const result = applyUserChoice({
      source: positional,
      existingId: flag('existing-id'),
      deferScans,
      trustedSource,
      by: flag('by'),
      sourceUrl: flag('url'),
      sourceName: flag('name'),
      expectedSize,
    });
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.outcome === 'BLOCKED' ? 1 : 0);
  } catch (error) {
    console.error(`user choice refused: ${error.message}`);
    console.error('usage: pnpm run scan:user-choice -- <url-or-path> --defer-scans yes|no [--trusted-source yes|no] --by <accountable-identity>');
    console.error('   or: pnpm run scan:user-choice -- --existing-id <id> --defer-scans yes|no [--trusted-source yes|no] --by <accountable-identity>');
    process.exit(2);
  }
}
