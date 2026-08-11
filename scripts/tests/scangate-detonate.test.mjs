// SCANGATE stage-2 detonation.
//
// This is the only stage that can catch self-extracting payloads — the technique that
// defeated over 90% of scanners in published testing. Static analysis cannot see a
// payload that does not exist until the skill runs; a file-tree diff across execution
// can see nothing else.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { hasExecutableContent, diffTrees, runDetonation } from '../scan-detonate.mjs';

const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sgd-'));
const fakeSpawn = (result) => () => ({ status: 0, stdout: '', stderr: '', error: null, ...result });

// --- executable-content detection -----------------------------------------------

test('a documentation-only payload needs no detonation', () => {
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, 'SKILL.md'), '# doc');
  fs.writeFileSync(path.join(dir, 'notes.txt'), 'text');
  assert.equal(hasExecutableContent(dir), false);
});

test('detects executable content by extension', () => {
  for (const name of ['setup.py', 'run.sh', 'x.ps1', 'a.js', 'lib.dll', 'tool.exe', 'nb.ipynb']) {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, 'SKILL.md'), '# doc');
    fs.writeFileSync(path.join(dir, name), 'content');
    assert.equal(hasExecutableContent(dir), true, `should detect: ${name}`);
  }
});

test('detects a package.json lifecycle hook as executable content', () => {
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ scripts: { postinstall: 'node evil.js' } }));
  assert.equal(hasExecutableContent(dir), true);
});

test('a package.json without lifecycle hooks is not executable content', () => {
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ scripts: { test: 'jest' } }));
  assert.equal(hasExecutableContent(dir), false);
});

test('a malformed package.json does not crash detection', () => {
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, 'package.json'), '{ not valid json');
  assert.doesNotThrow(() => hasExecutableContent(dir));
});

test('detects executable content nested in subdirectories', () => {
  const dir = tmpDir();
  fs.mkdirSync(path.join(dir, 'scripts'));
  fs.writeFileSync(path.join(dir, 'scripts', 'helper.py'), 'print(1)');
  assert.equal(hasExecutableContent(dir), true);
});

// --- tree diff ------------------------------------------------------------------

test('tree diff surfaces self-extraction as added files', () => {
  const before = [{ path: 'a.md', sha256: '1' }];
  const after = [{ path: 'a.md', sha256: '1' }, { path: '.cache/payload.sh', sha256: '2' }];
  const diff = diffTrees(before, after);
  assert.deepEqual(diff.added, ['.cache/payload.sh']);
  assert.deepEqual(diff.modified, []);
  assert.deepEqual(diff.removed, []);
});

test('tree diff surfaces in-place modification', () => {
  const diff = diffTrees([{ path: 'a.md', sha256: '1' }], [{ path: 'a.md', sha256: '9' }]);
  assert.deepEqual(diff.modified, ['a.md']);
});

test('tree diff surfaces deletion', () => {
  const diff = diffTrees([{ path: 'a.md', sha256: '1' }], []);
  assert.deepEqual(diff.removed, ['a.md']);
});

test('an unchanged tree produces an empty diff', () => {
  const tree = [{ path: 'a.md', sha256: '1' }, { path: 'b.md', sha256: '2' }];
  const diff = diffTrees(tree, tree);
  assert.deepEqual(diff, { added: [], modified: [], removed: [] });
});

// --- detonation orchestration ---------------------------------------------------

test('a payload with no executable content is skipped, not blocked', () => {
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, 'SKILL.md'), '# doc');
  const result = runDetonation(dir, { spawn: fakeSpawn({}) });
  assert.equal(result.ran, false);
  assert.equal(result.verdict, 'NO_FINDINGS');
});

test('a container failure BLOCKS rather than reporting clean', () => {
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, 'setup.py'), 'print(1)');
  const result = runDetonation(dir, {
    spawn: fakeSpawn({ status: null, error: new Error('timeout') }),
    ensureDocker: () => ({ ready: true }),
  });
  assert.equal(result.verdict, 'BLOCKED');
  assert.match(result.stdout, /failed|timeout/i);
});

test('a detonation that changes nothing yields NO_FINDINGS', () => {
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, 'setup.py'), 'x');
  const hash = createHash('sha256').update('x').digest('hex');
  const result = runDetonation(dir, { spawn: fakeSpawn({ status: 0, stdout: `${hash}  ./setup.py\n` }) });
  assert.equal(result.verdict, 'NO_FINDINGS');
  assert.deepEqual(result.added, []);
});

test('a detonation that creates a new file BLOCKS — this is the self-extraction signal', () => {
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, 'setup.py'), 'x');
  const hash = createHash('sha256').update('x').digest('hex');
  const stdout = `${hash}  ./setup.py\n${'b'.repeat(64)}  ./.cache/payload.sh\n`;
  const result = runDetonation(dir, { spawn: fakeSpawn({ status: 0, stdout }) });
  assert.equal(result.verdict, 'BLOCKED');
  assert.deepEqual(result.added, ['.cache/payload.sh']);
});

test('empty container output BLOCKS rather than reading as "nothing changed"', () => {
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, 'setup.py'), 'x');
  const result = runDetonation(dir, { spawn: fakeSpawn({ status: 0, stdout: '' }) });
  assert.equal(result.verdict, 'BLOCKED',
    'no manifest means the sandbox told us nothing — that is not the same as telling us it is clean');
});
