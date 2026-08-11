#!/usr/bin/env node
// ---------------------------------------------------------------------------
// scan-dispose.mjs — SCANGATE stages 4 and 5 (human decision, then adoption).
//
// This closes the workflow. Without it a quarantined artifact can never leave quarantine:
// the PreToolUse hook denies every agent path into the tree, and `pnpm run lint` fails
// while any artifact lacks a receipt. Discovered by using the gate, not by designing it —
// the first real intake became permanently undisposable.
//
// The receipt written here IS the enforcement record. It binds a human decision to the
// exact bytes reviewed, so any later modification invalidates it and the gate re-closes.
//
// ALLOW is a human decision. The tool records who made it; it does not make it.
// ---------------------------------------------------------------------------

import fs from 'node:fs';
import path from 'node:path';
import { QUARANTINE_ROOT, hashTree, sha256File, treeDigest, writeReceipt, readReceipt } from './scan-core.mjs';

const DECISIONS = new Set(['ALLOW', 'BLOCKED', 'REJECTED', 'DEFERRED']);

/**
 * @param {{ id: string, decision: string, by: string, purge?: boolean, root?: string, evidence?: object, adoptedPath?: string|null }} options
 */
export function dispose({ id, decision, by, purge = false, root = QUARANTINE_ROOT, evidence = null, adoptedPath = null }) {
  if (!DECISIONS.has(decision)) {
    throw new Error(`decision must be one of ${[...DECISIONS].join(', ')} — got ${decision}`);
  }
  if (!by || typeof by !== 'string') {
    throw new Error('a decision requires an accountable decider (--by)');
  }

  const dir = path.join(root, id);
  if (!fs.existsSync(dir)) throw new Error(`no such quarantine entry: ${id}`);
  if (readReceipt(id)) throw new Error(`${id} already has a receipt — receipts are not overwritten`);

  const payloadDir = path.join(dir, 'payload');
  if (decision !== 'ALLOW' && adoptedPath) {
    throw new Error('an adopted path is valid only for an ALLOW decision');
  }

  // Stage 5 may land the byte-preserved artifact outside quarantine before the signed
  // receipt is written. Hash that real destination, not merely the quarantine payload,
  // so the weekly sweep protects the bytes consumers actually use.
  const attestedPath = decision === 'ALLOW' && adoptedPath
    ? path.resolve(adoptedPath)
    : payloadDir;
  if (decision === 'ALLOW' && !fs.existsSync(attestedPath)) {
    throw new Error(`ALLOW destination does not exist: ${attestedPath}`);
  }
  const files = fs.existsSync(attestedPath)
    ? (fs.statSync(attestedPath).isDirectory()
      ? hashTree(attestedPath)
      : [{ path: path.basename(attestedPath), sha256: sha256File(attestedPath) }])
    : [];

  let intakeMeta = {};
  try { intakeMeta = JSON.parse(fs.readFileSync(path.join(dir, 'intake.json'), 'utf8')); } catch { /* optional */ }

  const receipt = {
    receipt_id: id,
    artifact: {
      source: intakeMeta.source ?? null,
      source_url: intakeMeta.source_url ?? null,
      tier: intakeMeta.tier ?? 'T3',
      intake_at: intakeMeta.at ?? null,
    },
    adopted_path: decision === 'ALLOW' ? attestedPath : null,
    files,
    // Provenance baseline. When the payload is purged, `_source/` becomes the only surviving
    // evidence of what arrived, so the weekly sweep needs a hash taken at decision time to
    // detect a later swap. Recorded for every decision, not just purged ones.
    source_sha256: treeDigest(path.join(dir, '_source')),
    purged: false,
    evidence,
    stage4: { decision, decided_by: by, at: new Date().toISOString() },
    last_verified: new Date().toISOString(),
  };

  // Purge only removes the payload. `_source/` is preserved as provenance — it is the
  // only proof of what actually arrived, and the receipt would otherwise reference
  // nothing reviewable.
  //
  // This runs BEFORE the receipt is written: `purged` is a signed field, and the weekly
  // sweep treats a purged payload that reappears as tampering. Recording the intent to
  // purge rather than the fact of it would make that check assert against a lie.
  if (purge) {
    if (decision === 'ALLOW') throw new Error('refusing to purge an ALLOWed artifact — that would delete what was just approved');
    fs.rmSync(payloadDir, { recursive: true, force: true });
    receipt.purged = true;
  }

  const receiptPath = writeReceipt(receipt);

  if (receipt.purged) {
    fs.writeFileSync(path.join(dir, 'PURGED.md'),
      `# Payload purged\n\nDecision: ${decision} by ${by} at ${receipt.stage4.at}\n\n`
      + `The original is preserved in _source/ as provenance. Receipt: ${path.basename(receiptPath)}\n`);
  }

  return { id, decision, receiptPath, fileCount: files.length, purged: receipt.purged };
}

const invokedDirectly = process.argv[1] && process.argv[1].endsWith('scan-dispose.mjs');

if (invokedDirectly) {
  const args = process.argv.slice(2);
  const flag = (name) => {
    const index = args.indexOf(`--${name}`);
    return index >= 0 ? args[index + 1] : null;
  };

  const target = args[0];
  if (!target || target.startsWith('--')) {
    console.error('usage: node scripts/scan-dispose.mjs <quarantine-id> --decision ALLOW|BLOCKED|REJECTED|DEFERRED --by <who> [--adopted-path <path>] [--purge]');
    process.exit(2);
  }

  try {
    const result = dispose({
      id: path.basename(target.replace(/[/\\]+$/, '')),
      decision: (flag('decision') || '').toUpperCase(),
      by: flag('by'),
      purge: args.includes('--purge'),
      adoptedPath: flag('adopted-path'),
    });
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(`dispose refused: ${error.message}`);
    process.exit(1);
  }
}
