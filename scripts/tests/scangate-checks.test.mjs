// SCANGATE content pre-checks.
//
// These target what the static scanner structurally cannot see: payloads hidden in
// ignored folders, packed into high-entropy blobs, or disguised with Unicode. The
// unpack-gap check is the one that matters most — it fires whenever a file exists that
// the scanner never opened, which is the shape of the >90%-bypass packing evasion.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { checkUnicode, checkEntropy, findHiddenPaths, findUnpackGap, runPreChecks } from '../scan-checks.mjs';

test('detects bidi override, zero-width, and homoglyph characters', () => {
  assert.ok(checkUnicode('run this ‮txt.exe').some((f) => /bidi/i.test(f.rule)));
  assert.ok(checkUnicode('safe​hidden').some((f) => /zero-width/i.test(f.rule)));
  assert.ok(checkUnicode('Аdmin access').some((f) => /homoglyph/i.test(f.rule)));
  assert.equal(checkUnicode('ordinary ascii text').length, 0);
});

test('checkUnicode tolerates non-string input without throwing', () => {
  for (const value of [null, undefined, 42, {}]) {
    assert.deepEqual(checkUnicode(value), []);
  }
});

test('flags a large high-entropy blob but not ordinary prose', () => {
  const blob = Buffer.from(crypto.randomBytes(4096).toString('base64'));
  assert.ok(checkEntropy(blob).length > 0);

  const prose = Buffer.from('# Heading\n\nA normal markdown document about ordinary things.\n'.repeat(40));
  assert.equal(checkEntropy(prose).length, 0);
});

test('checkEntropy ignores small buffers where entropy is meaningless', () => {
  assert.deepEqual(checkEntropy(Buffer.from('short')), []);
  assert.deepEqual(checkEntropy(Buffer.alloc(0)), []);
});

// Calibration, measured 2026-08-09 against the real workspace: whole-file Shannon entropy
// flagged 76 of 109 stage-1 retro-scan findings, including the sealed reviewer's own agent
// file at 4.82 bits/byte. Dense markdown is not a packed payload.
test('dense technical markdown is not flagged as a packed payload', () => {
  const dense = Buffer.from([
    '# SCANGATE — trigger card',
    '',
    '| Stage | Decision point | Command |',
    '|---|---|---|',
    '| 0 | Is this foreign content? | `pnpm run scan:intake` |',
    '',
    'Run `docker run --rm --network none --read-only --cap-drop ALL` before any',
    'model reads it; verdicts are BLOCKED / NO_FINDINGS / FINDINGS_ACCEPTED (never SAFE).',
    '',
    '```js',
    'export function resolveTier(source) { return registry.default_policy?.unknown_tier ?? "T3"; }',
    '```',
  ].join('\n').repeat(12));
  assert.ok(dense.length > 1024, 'fixture must exceed the minimum size');
  assert.deepEqual(checkEntropy(dense), [], 'dense prose+code+tables must not read as a blob');
});

test('a base64 payload embedded in an otherwise ordinary text file is still flagged', () => {
  const payload = crypto.randomBytes(1024).toString('base64');
  const hidden = Buffer.from(
    `# Ordinary Skill\n\nThis skill does ordinary things.\n\nconst data = "${payload}";\n\nMore prose follows.\n`
  );
  const findings = checkEntropy(hidden);
  assert.ok(findings.length > 0, 'an embedded encoded blob is the actual threat shape');
  assert.match(findings[0].detail, /encoded/i);
});

test('ordinary binary content is not flagged — compressed bytes are expected to look random', () => {
  // A PNG header followed by compressed-looking data. Real images, zips, and model shards
  // all sit near 8 bits/byte; flagging them buries the finding that matters.
  const binary = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    crypto.randomBytes(8192),
  ]);
  assert.deepEqual(checkEntropy(binary), []);
});

test('unpack gap reports files the scanner never analyzed', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sgc-'));
  fs.writeFileSync(path.join(dir, 'seen.md'), 'x');
  fs.mkdirSync(path.join(dir, '.hidden'));
  fs.writeFileSync(path.join(dir, '.hidden', 'payload.bin'), 'y');

  const gap = findUnpackGap(dir, ['seen.md']);
  assert.deepEqual(gap, ['.hidden/payload.bin']);
});

test('unpack gap is empty when the scanner covered everything', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sgc2-'));
  fs.writeFileSync(path.join(dir, 'a.md'), 'x');
  fs.writeFileSync(path.join(dir, 'b.md'), 'y');
  assert.deepEqual(findUnpackGap(dir, ['a.md', 'b.md']), []);
});

test('hidden paths are enumerated explicitly rather than walked past', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sgh-'));
  fs.mkdirSync(path.join(dir, '.git'));
  fs.writeFileSync(path.join(dir, '.git', 'config'), 'x');
  fs.writeFileSync(path.join(dir, '.env'), 'SECRET=1');
  fs.writeFileSync(path.join(dir, 'visible.md'), 'y');

  const hidden = findHiddenPaths(dir);
  assert.deepEqual(hidden.sort(), ['.env', '.git/config']);
});

test('runPreChecks marks unpack-gap findings HIGH severity', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sgp-'));
  fs.writeFileSync(path.join(dir, 'unscanned.md'), 'content');
  const findings = runPreChecks(dir, []);
  const gap = findings.find((f) => f.rule === 'unpack-gap');
  assert.ok(gap, 'expected an unpack-gap finding');
  assert.equal(gap.severity, 'HIGH');
});

test('runPreChecks does not flag genuinely compressed media as an entropy blob', () => {
  // Every PNG and every gzip is high-entropy by construction. Flagging them all would
  // bury the one blob that matters. Signal beats coverage here.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sgm-'));
  fs.writeFileSync(path.join(dir, 'image.png'), crypto.randomBytes(4096));
  const findings = runPreChecks(dir, ['image.png']);
  assert.equal(findings.filter((f) => f.rule === 'high-entropy-blob').length, 0);
});

test('runPreChecks survives an unreadable or exotic file without crashing', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sgu-'));
  fs.writeFileSync(path.join(dir, 'ok.md'), 'fine');
  assert.doesNotThrow(() => runPreChecks(dir, ['ok.md']));
});

test('runPreChecks throws on a missing directory rather than reporting all-clear', () => {
  assert.throws(() => runPreChecks(path.join(os.tmpdir(), 'sg-missing-98765'), []));
});
