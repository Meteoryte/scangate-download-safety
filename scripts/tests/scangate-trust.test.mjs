// SCANGATE trust tiers.
//
// Trust modulates scan DEPTH, never scan EXISTENCE. These tests exist mostly to make one
// regression impossible: a future maintainer "improving" identity matching with Unicode
// normalization or fuzzy comparison, at which point every homoglyph typosquat inherits
// the trust of the org it imitates.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveTier, resolveTierFromRegistry, thresholdForTier } from '../scan-core.mjs';

test('exact identity match earns T1; lookalikes do not', () => {
  assert.equal(resolveTier({ host: 'github.com', org: 'NVIDIA', repo: 'SkillSpector' }), 'T1');
  // Latin lowercase-L substituted for uppercase-I: renders near-identically in most fonts.
  assert.equal(resolveTier({ host: 'github.com', org: 'NVlDlA', repo: 'SkillSpector' }), 'T3');
  // Cyrillic А (U+0410) substituted for Latin A.
  assert.equal(resolveTier({ host: 'github.com', org: 'NVIDIА', repo: 'SkillSpector' }), 'T3');
});

test('host matching is exact — no suffix, subdomain, or trailing-dot confusion', () => {
  assert.equal(resolveTier({ host: 'github.com.evil.io', org: 'NVIDIA', repo: 'SkillSpector' }), 'T3');
  assert.equal(resolveTier({ host: 'evil-github.com', org: 'NVIDIA', repo: 'SkillSpector' }), 'T3');
  assert.equal(resolveTier({ host: 'notgithub.com', org: 'NVIDIA', repo: 'SkillSpector' }), 'T3');
  // "github.com." is a valid FQDN that resolves identically but must not match.
  assert.equal(resolveTier({ host: 'github.com.', org: 'NVIDIA', repo: 'SkillSpector' }), 'T3');
});

test('host and org matching is case-insensitive for real ASCII identities', () => {
  assert.equal(resolveTier({ host: 'GitHub.com', org: 'nvidia', repo: 'skillspector' }), 'T1');
});

test('unknown sources default to T3, never to a permissive tier', () => {
  assert.equal(resolveTier({ host: 'pastebin.com' }), 'T3');
  assert.equal(resolveTier({ host: 'github.com', org: 'some-random-user', repo: 'thing' }), 'T3');
  assert.equal(resolveTier({}), 'T3');
  assert.equal(resolveTier(null), 'T3');
  assert.equal(resolveTier(undefined), 'T3');
  assert.equal(resolveTier('a string'), 'T3');
  assert.equal(resolveTier(42), 'T3');
});

test('T3 is held to the SAFE band; T1/T2 keep the default cut', () => {
  assert.equal(thresholdForTier('T3'), 20);
  assert.equal(thresholdForTier('T2'), 50);
  assert.equal(thresholdForTier('T1'), 50);
});

test('an unknown or missing tier gets the strictest bar, never the loosest', () => {
  for (const tier of ['nonsense', '', null, undefined, 'T0', 'T4', 'T9']) {
    assert.equal(thresholdForTier(tier), 20, `unknown tier should be strict: ${tier}`);
  }
});

test('a source with a port or credentials in the host does not match', () => {
  assert.equal(resolveTier({ host: 'github.com:443', org: 'NVIDIA', repo: 'SkillSpector' }), 'T3');
  assert.equal(resolveTier({ host: 'user@github.com', org: 'NVIDIA', repo: 'SkillSpector' }), 'T3');
});

test('an exact artifact demotion overrides a trusted wildcard without affecting siblings', () => {
  const registry = {
    sources: [{ tier: 'T1', host: 'files.example.test', org: 'approved-drop', repo: '*' }],
    demotions: [{ tier: 'T2', host: 'files.example.test', org: 'approved-drop', repo: 'artifact-123' }],
    denylist: [],
    default_policy: { unknown_tier: 'T3' },
  };

  assert.equal(resolveTierFromRegistry(
    { host: 'files.example.test', org: 'approved-drop', repo: 'artifact-123' },
    registry,
  ), 'T2');
  assert.equal(resolveTierFromRegistry(
    { host: 'files.example.test', org: 'approved-drop', repo: 'artifact-456' },
    registry,
  ), 'T1');
});
