import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { treeDigest } from '../scan-core.mjs';
import { validateResolutionEvidence } from '../scan-resolve.mjs';

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-resolution-'));
  const payloadDir = path.join(root, 'payload');
  const sourceDir = path.join(root, '_source');
  fs.mkdirSync(payloadDir);
  fs.mkdirSync(sourceDir);
  fs.writeFileSync(path.join(payloadDir, 'protocol.md'), 'reviewed');
  fs.writeFileSync(path.join(sourceDir, 'artifact.zip'), 'source');
  const candidate = { path: 'protocol.md', sha256: 'a'.repeat(64) };
  const original = { source_sha256: treeDigest(sourceDir) };
  return {
    original,
    payloadDir,
    sourceDir,
    formatReport: {
      modelBlind: true,
      contentPrinted: false,
      targetTreeDigest: treeDigest(payloadDir),
      formatReview: { verdict: 'REVIEW', blockers: [], warnings: [{ rule: 'expected-capability' }], governanceCandidates: [candidate] },
    },
    defenderReport: {
      modelBlind: true,
      contentPrinted: false,
      remediationDisabled: true,
      sourceTreeDigest: original.source_sha256,
      verdict: 'NO_FINDINGS',
      exitCode: 0,
      noThreatsMarker: true,
      timedOut: false,
    },
    governanceDecision: { disposition: 'VERIFIED-NO-FOLD', candidates: [candidate] },
  };
}

test('resolution requires exact, closed governance coverage and clean model-blind evidence', () => {
  const result = validateResolutionEvidence(fixture());
  assert.deepEqual(result.warningRules, ['expected-capability']);
  assert.equal(result.governanceDisposition, 'VERIFIED-NO-FOLD');
});

test('resolution fails closed on any format blocker', () => {
  const input = fixture();
  input.formatReport.formatReview.blockers.push({ rule: 'active-content' });
  assert.throws(() => validateResolutionEvidence(input), /blockers remain/i);
});

test('resolution fails closed when Defender did not corroborate the exact source', () => {
  const input = fixture();
  input.defenderReport.sourceTreeDigest = 'b'.repeat(64);
  assert.throws(() => validateResolutionEvidence(input), /does not bind/i);
});

test('resolution fails closed when one embedded governance candidate is missing', () => {
  const input = fixture();
  input.governanceDecision.candidates = [];
  assert.throws(() => validateResolutionEvidence(input), /exact candidate set/i);
});
