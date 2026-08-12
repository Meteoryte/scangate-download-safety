import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { checkDrift, isStale, checkPurgeHeld, checkProvenance, quarantineEntryIdFor } from '../scan-weekly.mjs';
import { hashTree, sha256File, treeDigest } from '../scan-core.mjs';

// Build a quarantine entry the way scan-intake/scan-dispose lay one out.
function buildEntry({ purged = false, sourceFiles = { 'a.zip': 'original' } } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sgq-'));
  const source = path.join(dir, '_source');
  fs.mkdirSync(source);
  for (const [name, data] of Object.entries(sourceFiles)) fs.writeFileSync(path.join(source, name), data);
  if (!purged) {
    fs.mkdirSync(path.join(dir, 'payload'));
    fs.writeFileSync(path.join(dir, 'payload', 'SKILL.md'), 'x');
  }
  return dir;
}

test('drift check passes when files are unchanged and fails when one byte changes', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sgw-'));
  const file = path.join(dir, 'a.md');
  fs.writeFileSync(file, 'original');

  const receipt = { adopted_path: dir, files: hashTree(dir) };
  assert.equal(checkDrift(receipt).ok, true);

  fs.writeFileSync(file, 'tampered');
  const after = checkDrift(receipt);
  assert.equal(after.ok, false);
  assert.deepEqual(after.changed, ['a.md']);
});

test('drift check supports a single adopted file as well as a directory', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sgw-file-'));
  const file = path.join(dir, 'artifact.bin');
  fs.writeFileSync(file, 'original');
  const hash = sha256File(file);
  const receipt = { adopted_path: file, files: [{ path: 'artifact.bin', sha256: hash }] };
  assert.equal(checkDrift(receipt).ok, true);
  fs.writeFileSync(file, 'changed');
  assert.deepEqual(checkDrift(receipt).changed, ['artifact.bin']);
});

test('a receipt older than 9 days is stale; 8 days is not', () => {
  const now = Date.parse('2026-08-05T00:00:00Z');
  assert.equal(isStale({ last_verified: '2026-07-25T00:00:00Z' }, now), true);  // 11 days
  assert.equal(isStale({ last_verified: '2026-07-28T00:00:00Z' }, now), false); // 8 days
  assert.equal(isStale({}, now), true);                                          // never verified
});

test('a purged payload that reappears on disk is tampering', () => {
  const dir = buildEntry({ purged: true });
  const receipt = { purged: true, stage4: { decision: 'BLOCKED' } };
  assert.equal(checkPurgeHeld(receipt, dir).ok, true);

  // Someone puts the blocked payload back.
  fs.mkdirSync(path.join(dir, 'payload'));
  fs.writeFileSync(path.join(dir, 'payload', 'SKILL.md'), 'resurrected');
  const after = checkPurgeHeld(receipt, dir);
  assert.equal(after.ok, false);
  assert.match(after.reason, /reappeared/i);
});

test('an unpurged or ALLOWed receipt is not subject to the purge check', () => {
  const dir = buildEntry({ purged: false });
  assert.equal(checkPurgeHeld({ purged: false, stage4: { decision: 'BLOCKED' } }, dir).ok, true);
  assert.equal(checkPurgeHeld({ stage4: { decision: 'ALLOW' } }, dir).ok, true);
});

test('_source provenance verifies, and any change to it fails', () => {
  const dir = buildEntry({ purged: true });
  const receipt = { source_sha256: treeDigest(path.join(dir, '_source')) };
  assert.equal(checkProvenance(receipt, dir).ok, true);

  fs.writeFileSync(path.join(dir, '_source', 'a.zip'), 'swapped');
  const after = checkProvenance(receipt, dir);
  assert.equal(after.ok, false);
  assert.match(after.reason, /provenance/i);
});

test('a receipt with no recorded provenance hash is unverifiable, not proof of tampering', () => {
  const dir = buildEntry({ purged: true });
  const out = checkProvenance({}, dir);
  assert.equal(out.ok, false);
  assert.equal(out.unverifiable, true);
  assert.match(out.reason, /no provenance hash/i);
});

test('treeDigest is stable and order-independent', () => {
  const a = buildEntry({ purged: true, sourceFiles: { 'x.txt': '1', 'y.txt': '2' } });
  const b = buildEntry({ purged: true, sourceFiles: { 'y.txt': '2', 'x.txt': '1' } });
  assert.equal(treeDigest(path.join(a, '_source')), treeDigest(path.join(b, '_source')));
});

test('a resolution receipt keeps provenance anchored to its original quarantine entry', () => {
  assert.equal(quarantineEntryIdFor({
    receipt_id: 'new-resolution',
    quarantine_entry_id: 'original-deferred',
    supersedes_receipt_id: 'original-deferred',
  }), 'original-deferred');
});
