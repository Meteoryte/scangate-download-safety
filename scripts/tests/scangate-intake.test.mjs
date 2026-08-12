// SCANGATE stage-0 ingress.
//
// This is the ONLY sanctioned path for foreign content to reach disk. The PreToolUse hook
// denies agent writes into the quarantine tree, so anything that lands there arrives
// through this tool — which means this tool is where every containment check has to live.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { slugFor, quarantineIdFor, intake } from '../scan-intake.mjs';

const tmpRoot = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sgq-'));

// Minimal single-member zip builder (mirrors scangate-zip.test.mjs).
function buildZip(name, data) {
  const raw = Buffer.from(data);
  const deflated = zlib.deflateRawSync(raw);
  const nameBuf = Buffer.from(name, 'utf8');

  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(8, 8);
  local.writeUInt32LE(deflated.length, 18); local.writeUInt32LE(raw.length, 22);
  local.writeUInt16LE(nameBuf.length, 26);

  const cdStart = 30 + nameBuf.length + deflated.length;
  const cd = Buffer.alloc(46);
  cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 6); cd.writeUInt16LE(8, 10);
  cd.writeUInt32LE(deflated.length, 20); cd.writeUInt32LE(raw.length, 24);
  cd.writeUInt16LE(nameBuf.length, 28); cd.writeUInt32LE(0, 42);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8); eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(46 + nameBuf.length, 12); eocd.writeUInt32LE(cdStart, 16);

  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sgqz-')), 'pack.zip');
  fs.writeFileSync(file, Buffer.concat([local, nameBuf, deflated, cd, nameBuf, eocd]));
  return file;
}

// --- naming ---------------------------------------------------------------------

test('slug is filesystem-safe and lowercase', () => {
  assert.equal(slugFor('https://github.com/NVIDIA/SkillSpector.git'), 'github-com-nvidia-skillspector');
  assert.equal(slugFor('My Weird Pack (v2).zip'), 'my-weird-pack-v2-zip');
  assert.match(slugFor('!!!'), /^[a-z0-9-]*$/);
});

test('quarantine id is date-prefixed and stable for the same input', () => {
  const id = quarantineIdFor('https://example.com/a.zip', '2026-08-05');
  assert.match(id, /^2026-08-05-example-com-a-zip-[0-9a-f]{6}$/);
  assert.equal(id, quarantineIdFor('https://example.com/a.zip', '2026-08-05'));
});

test('different sources get different ids even with the same slug', () => {
  const a = quarantineIdFor('https://a.example.com/pack.zip', '2026-08-05');
  const b = quarantineIdFor('https://b.example.com/pack.zip', '2026-08-05');
  assert.notEqual(a, b);
});

// --- ingress --------------------------------------------------------------------

test('a local directory is quarantined with metadata and a sentinel', () => {
  const src = fs.mkdtempSync(path.join(os.tmpdir(), 'sgsrc-'));
  fs.writeFileSync(path.join(src, 'SKILL.md'), '# skill');
  const root = tmpRoot();

  const result = intake({ source: src, root });
  assert.equal(result.tier, 'T3', 'a local path has no verified publisher identity');
  assert.ok(fs.existsSync(path.join(result.dir, 'DO-NOT-READ.md')));
  assert.ok(fs.existsSync(path.join(result.dir, 'intake.json')));
  assert.ok(fs.existsSync(path.join(result.dir, 'payload', 'SKILL.md')));
});

test('a local non-archive file is preserved and copied inside payload', () => {
  const srcDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sgfile-'));
  const src = path.join(srcDir, 'pasted-text.txt');
  fs.writeFileSync(src, 'user supplied request');
  const root = tmpRoot();

  const result = intake({ source: src, root, sourceName: 'request.txt' });
  assert.equal(result.sourcePreserved, true);
  assert.equal(fs.readFileSync(path.join(result.dir, '_source', 'request.txt'), 'utf8'), 'user supplied request');
  assert.equal(fs.readFileSync(path.join(result.dir, 'payload', 'request.txt'), 'utf8'), 'user supplied request');
});

test('an archive is preserved in _source and extracted into payload', () => {
  const zip = buildZip('SKILL.md', '# from archive');
  const root = tmpRoot();

  const result = intake({ source: zip, root });
  assert.equal(result.sourcePreserved, true, 'the original archive is the only proof of what arrived');
  assert.ok(fs.existsSync(path.join(result.dir, '_source', 'pack.zip')));
  assert.equal(fs.readFileSync(path.join(result.dir, 'payload', 'SKILL.md'), 'utf8'), '# from archive');
});

test('a hostile archive is refused and nothing is extracted', () => {
  const zip = buildZip('../../escape.md', 'pwn');
  const root = tmpRoot();
  assert.throws(() => intake({ source: zip, root }), /rejected at ingress|traversal/i);
});

test('a missing source is refused rather than creating an empty quarantine entry', () => {
  const root = tmpRoot();
  assert.throws(() => intake({ source: '/does/not/exist/anywhere', root }), /unsupported or missing/i);
});

test('re-intaking the same source into an existing entry is refused', () => {
  const src = fs.mkdtempSync(path.join(os.tmpdir(), 'sgsrc2-'));
  fs.writeFileSync(path.join(src, 'a.md'), 'x');
  const root = tmpRoot();

  intake({ source: src, root });
  assert.throws(() => intake({ source: src, root }), /already exists/i);
});

test('a trusted publisher URL resolves to T1 without changing the pipeline', () => {
  // Tier affects scan DEPTH, never whether quarantine happens.
  const src = fs.mkdtempSync(path.join(os.tmpdir(), 'sgsrc3-'));
  fs.writeFileSync(path.join(src, 'a.md'), 'x');
  const root = tmpRoot();

  const result = intake({ source: src, root, sourceUrl: 'https://github.com/NVIDIA/SkillSpector' });
  assert.equal(result.tier, 'T1');
  assert.ok(fs.existsSync(path.join(result.dir, 'payload', 'a.md')), 'T1 content is still quarantined');
});

test('an approval-gated first-party container can supply an exact trust identity', () => {
  const src = fs.mkdtempSync(path.join(os.tmpdir(), 'sgsrc-container-'));
  fs.writeFileSync(path.join(src, 'a.md'), 'x');
  const root = tmpRoot();

  const result = intake({
    source: src,
    root,
    sourceIdentity: {
      host: 'files.example.test',
      org: 'approved-drop',
      repo: 'provider-file-id',
    },
  });
  assert.equal(result.tier, 'T1');
  const meta = JSON.parse(fs.readFileSync(path.join(result.dir, 'intake.json'), 'utf8'));
  assert.equal(meta.source_identity.repo, 'provider-file-id');
});

test('intake records provenance in intake.json', () => {
  const src = fs.mkdtempSync(path.join(os.tmpdir(), 'sgsrc4-'));
  fs.writeFileSync(path.join(src, 'a.md'), 'x');
  const root = tmpRoot();

  const result = intake({ source: src, root });
  const meta = JSON.parse(fs.readFileSync(path.join(result.dir, 'intake.json'), 'utf8'));
  assert.equal(meta.id, result.id);
  assert.equal(meta.tier, 'T3');
  assert.ok(meta.at, 'must record when it arrived');
});

test('a remote file streams directly into quarantine and validates its provider size', () => {
  const root = tmpRoot();
  const source = 'https://drive.usercontent.google.com/download?id=abc';
  const body = Buffer.from('provider bytes');

  const result = intake({
    source,
    root,
    sourceUrl: 'https://files.example.test/object/abc',
    sourceName: 'artifact.md',
    expectedSize: body.length,
    download: (_url, destination) => fs.writeFileSync(destination, body),
  });

  assert.equal(result.sourcePreserved, true);
  assert.equal(fs.readFileSync(path.join(result.dir, '_source', 'artifact.md'), 'utf8'), 'provider bytes');
  assert.equal(fs.readFileSync(path.join(result.dir, 'payload', 'artifact.md'), 'utf8'), 'provider bytes');
  const meta = JSON.parse(fs.readFileSync(path.join(result.dir, 'intake.json'), 'utf8'));
  assert.equal(meta.kind, 'url');
  assert.equal(meta.expected_size, body.length);
});

test('a remote size mismatch fails closed and removes the payload', () => {
  const root = tmpRoot();
  const source = 'https://drive.usercontent.google.com/download?id=wrong-size';
  let dir;

  assert.throws(() => {
    try {
      intake({
        source,
        root,
        sourceName: 'artifact.bin',
        expectedSize: 999,
        download: (_url, destination) => fs.writeFileSync(destination, 'short'),
      });
    } finally {
      dir = path.join(root, quarantineIdFor(source));
    }
  }, /size mismatch/i);

  assert.equal(fs.existsSync(path.join(dir, 'payload')), false);
  assert.ok(fs.existsSync(path.join(dir, '_source', 'artifact.bin')));
  assert.ok(fs.existsSync(path.join(dir, 'INTAKE-FAILED.md')));
});
