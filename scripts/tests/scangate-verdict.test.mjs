import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateVerdict } from '../scan-verdict.mjs';

test('accepts a well-formed verdict', () => {
  const out = validateVerdict({ verdict: 'NO_FINDINGS', confidence: 'strongly-supported', findings: [], rationale: 'clean' });
  assert.equal(out.verdict, 'NO_FINDINGS');
});

test('a malformed response becomes BLOCKED, never allowed through', () => {
  for (const bad of ['not json at all', {}, { verdict: 'SAFE' }, { verdict: 'NO_FINDINGS' }, null]) {
    assert.equal(validateVerdict(bad).verdict, 'BLOCKED', `should block: ${JSON.stringify(bad)}`);
  }
});

test('SAFE is not a valid verdict token', () => {
  assert.equal(validateVerdict({ verdict: 'SAFE', confidence: 'confirmed', findings: [], rationale: 'x' }).verdict, 'BLOCKED');
});

test('rationale is truncated so it cannot carry a large injected payload', () => {
  const out = validateVerdict({ verdict: 'NO_FINDINGS', confidence: 'confirmed', findings: [], rationale: 'A'.repeat(20_000) });
  assert.ok(out.rationale.length <= 2000);
});
