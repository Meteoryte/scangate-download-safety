#!/usr/bin/env node
// scripts/scan-weekly.mjs — SCANGATE section 6.4 sweep.
// Intake scanning answers "was this safe on arrival". This answers "is it still safe".

import fs from 'node:fs';
import path from 'node:path';
import { QUARANTINE_ROOT, RECEIPTS_DIR, WORKSPACE_ROOT, hashTree, sha256File, treeDigest, verifyReceipt } from './scan-core.mjs';

const STALE_DAYS = 9;

// Which directory holds the bytes this receipt attests to?
//
// An ADOPTED receipt points at its adopted_path. A BLOCKED receipt has adopted_path: null
// by design -- it was never adopted, and `--purge` deletes the payload outright -- so its
// `files` hashes describe bytes that no longer exist anywhere. Drift-checking those is
// guaranteed to fail forever, which is how this sweep spent its first week screaming
// TAMPERING at a receipt that was behaving exactly as designed.
//
// A blocked artifact is therefore held to two different questions, below: did the purge
// hold, and is the preserved provenance still the provenance we reviewed.
export function driftTargetFor(receipt) {
  if (receipt?.adopted_path) return receipt.adopted_path;
  return null;
}

// Did the purge hold? A blocked payload back on disk is somebody undoing a human BLOCK
// decision, which is exactly the thing worth an alarm.
export function checkPurgeHeld(receipt, entryDir) {
  if (receipt?.stage4?.decision === 'ALLOW') return { ok: true, reason: null };
  if (!receipt?.purged) return { ok: true, reason: null };   // never purged; payload may legitimately remain
  if (!fs.existsSync(path.join(entryDir, 'payload'))) return { ok: true, reason: null };
  return { ok: false, reason: 'blocked payload reappeared on disk after purge' };
}

// Is the preserved `_source/` still what was reviewed? Purging the payload makes `_source/`
// the only surviving evidence, so swapping it would rewrite history unchallenged.
//
// A receipt with no recorded baseline is reported `unverifiable` rather than as tampering:
// absence of a baseline is not evidence of change, and calling it tampering would train the
// reader to ignore the loudest line in this report.
export function checkProvenance(receipt, entryDir) {
  if (!receipt?.source_sha256) {
    return { ok: false, unverifiable: true, reason: 'no provenance hash recorded (receipt predates source_sha256)' };
  }
  const source = path.join(entryDir, '_source');
  const current = treeDigest(source);
  if (current === null) return { ok: false, unverifiable: false, reason: '_source provenance directory is missing' };
  if (current !== receipt.source_sha256) return { ok: false, unverifiable: false, reason: '_source provenance changed since review' };
  return { ok: true, unverifiable: false, reason: null };
}

export function checkDrift(receipt) {
  const dir = driftTargetFor(receipt);
  if (!dir || !fs.existsSync(dir)) return { ok: false, changed: ['<adopted path missing>'] };
  const stat = fs.statSync(dir);
  const currentFiles = stat.isDirectory()
    ? hashTree(dir)
    : stat.isFile()
      ? [{ path: path.basename(dir), sha256: sha256File(dir) }]
      : [{ path: path.basename(dir), sha256: 'NONREGULAR' }];
  const current = new Map(currentFiles.map((f) => [f.path, f.sha256]));
  const changed = [];
  for (const file of receipt.files || []) {
    if (current.get(file.path) !== file.sha256) changed.push(file.path);
  }
  for (const key of current.keys()) {
    if (!(receipt.files || []).some((f) => f.path === key)) changed.push(key);
  }
  return { ok: changed.length === 0, changed: [...new Set(changed)].sort() };
}

export function isStale(receipt, now = Date.now()) {
  const last = Date.parse(receipt?.last_verified || '');
  if (!last) return true;
  return (now - last) / 86_400_000 > STALE_DAYS;
}

export function sweep({ quarantineRoot = QUARANTINE_ROOT } = {}) {
  const drift = [];
  const unverifiable = [];
  const stale = [];
  const uncovered = [];

  if (fs.existsSync(RECEIPTS_DIR)) {
    for (const file of fs.readdirSync(RECEIPTS_DIR).filter((f) => f.endsWith('.json'))) {
      let receipt;
      try { receipt = JSON.parse(fs.readFileSync(path.join(RECEIPTS_DIR, file), 'utf8')); }
      catch { drift.push({ id: file, reason: 'unparseable receipt' }); continue; }

      if (!verifyReceipt(receipt).valid) { drift.push({ id: file, reason: 'signature invalid' }); continue; }

      const entryDir = path.join(quarantineRoot, receipt.receipt_id || path.basename(file, '.json'));

      // Adopted artifacts are drift-checked against what they became.
      if (driftTargetFor(receipt)) {
        const d = checkDrift(receipt);
        if (!d.ok) drift.push({ id: file, reason: 'content changed after approval', changed: d.changed });
      }

      // Blocked artifacts are held to the purge and to their provenance instead.
      const purge = checkPurgeHeld(receipt, entryDir);
      if (!purge.ok) drift.push({ id: file, reason: purge.reason });

      const prov = checkProvenance(receipt, entryDir);
      if (!prov.ok) {
        if (prov.unverifiable) unverifiable.push({ id: file, reason: prov.reason });
        else drift.push({ id: file, reason: prov.reason });
      }

      if (isStale(receipt)) stale.push({ id: file, last_verified: receipt.last_verified || null });
    }
  }

  const zones = String(process.env.SCANGATE_LANDING_ZONES || 'landing')
    .split(path.delimiter).map((zone) => zone.trim()).filter(Boolean);
  for (const zone of zones) {
    const abs = path.join(WORKSPACE_ROOT, zone);
    if (!fs.existsSync(abs)) continue;
    // Coverage reporting only — the grandfather inventory suppresses pre-existing files.
    uncovered.push({ zone, files: hashTree(abs).length });
  }

  return { drift, unverifiable, stale, uncovered };
}

if (process.argv[1] && process.argv[1].endsWith('scan-weekly.mjs')) {
  const result = sweep();
  console.log('SCANGATE weekly sweep —', new Date().toISOString().slice(0, 10));
  console.log('='.repeat(60));
  console.log(`drift:     ${result.drift.length}  ${result.drift.length ? '*** TAMPERING OR CORRUPTION ***' : 'none'}`);
  for (const d of result.drift) console.log(`  [BLOCKED] ${d.id}: ${d.reason}${d.changed ? ` (${d.changed.join(', ')})` : ''}`);
  console.log(`unverifiable: ${result.unverifiable.length} (no provenance baseline — NOT tampering)`);
  for (const u of result.unverifiable) console.log(`  [UNVERIF] ${u.id}: ${u.reason}`);
  console.log(`stale:     ${result.stale.length} (reported, NOT revoked)`);
  for (const s of result.stale) console.log(`  [STALE]   ${s.id}: last verified ${s.last_verified || 'never'}`);
  console.log(`coverage:  ${result.uncovered.map((u) => `${u.zone}=${u.files}`).join(' ')}`);
  process.exit(result.drift.length ? 1 : 0);
}
