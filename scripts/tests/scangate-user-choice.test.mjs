import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { applyUserChoice, choiceMode, parseYesNo } from '../scan-user-choice.mjs';

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-choice-'));
  const id = `fixture-${crypto.randomUUID()}`;
  const entry = path.join(root, id);
  fs.mkdirSync(path.join(entry, 'payload'), { recursive: true });
  fs.mkdirSync(path.join(entry, '_source'), { recursive: true });
  fs.writeFileSync(path.join(entry, 'payload', 'artifact.txt'), 'trusted bytes');
  fs.writeFileSync(path.join(entry, '_source', 'artifact.txt'), 'trusted bytes');
  fs.writeFileSync(path.join(entry, 'intake.json'), JSON.stringify({ id, source: 'fixture', tier: 'T3' }));
  return { root, id, entry };
}

test('yes/no parsing is explicit and mode selection gives deferral precedence', () => {
  assert.equal(parseYesNo('YES', 'choice'), true);
  assert.equal(parseYesNo('no', 'choice'), false);
  assert.throws(() => parseYesNo('y', 'choice'), /exactly yes or no/);
  assert.equal(choiceMode({ deferScans: true, trustedSource: true }), 'QUARANTINE_DEFERRED');
  assert.equal(choiceMode({ deferScans: false, trustedSource: true }), 'TRUSTED_FAST_TRACK');
  assert.equal(choiceMode({ deferScans: false, trustedSource: false }), 'FULL_SCAN_REQUIRED');
});

test('defer creates a quarantine-only DEFERRED decision without running a scan', () => {
  const { root, id } = fixture();
  let disposed;
  try {
    const result = applyUserChoice({
      existingId: id, deferScans: true, by: 'human/test', root,
      scanFn: () => { throw new Error('scan must not run'); },
      disposeFn: (options) => { disposed = options; return { ok: true }; },
    });
    assert.equal(result.outcome, 'QUARANTINED_DEFERRED');
    assert.equal(disposed.decision, 'DEFERRED');
    assert.equal(disposed.evidence.authorization_scope, 'QUARANTINE_ONLY');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('trusted fast track binds trust to exact bytes, runs core T1, and allows review only', () => {
  const { root, id, entry } = fixture();
  let scanTier;
  let disposed;
  try {
    const result = applyUserChoice({
      existingId: id, deferScans: false, trustedSource: true, by: 'human/test', root,
      scanFn: (_payload, tier) => {
        scanTier = tier;
        return { verdict: 'FINDINGS_ACCEPTED', score: 10, tier, findings: [{ severity: 'MEDIUM' }] };
      },
      disposeFn: (options) => { disposed = options; return { ok: true }; },
    });
    const meta = JSON.parse(fs.readFileSync(path.join(entry, 'intake.json'), 'utf8'));
    assert.equal(result.outcome, 'TRUSTED_FAST_TRACK_ALLOW_FOR_REVIEW');
    assert.equal(scanTier, 'T1');
    assert.match(meta.source_identity.repo, /^tree-sha256:[0-9a-f]{64}$/);
    assert.equal(disposed.decision, 'ALLOW');
    assert.equal(disposed.evidence.authorization_scope, 'READ_REVIEW_ONLY');
    assert.equal(disposed.evidence.mandatory_core_scan.score, 10);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('trusted fast track remains fail-closed when the core scan blocks', () => {
  const { root, id } = fixture();
  let disposed;
  try {
    const result = applyUserChoice({
      existingId: id, deferScans: false, trustedSource: true, by: 'human/test', root,
      scanFn: () => ({ verdict: 'BLOCKED', score: 100, tier: 'T1', findings: [] }),
      disposeFn: (options) => { disposed = options; return { ok: true }; },
    });
    assert.equal(result.outcome, 'BLOCKED');
    assert.equal(disposed.decision, 'BLOCKED');
    assert.equal(disposed.evidence.authorization_scope, 'NONE');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
