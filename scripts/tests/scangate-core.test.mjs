// SCANGATE core primitives — path safety, hashing, receipts.
//
// These are hostile-input tests. Every rejected name below corresponds to a real
// extraction escape: traversal, drive-absolute paths, NTFS alternate data streams,
// Windows reserved device names, and trailing dot/space (which Win32 silently strips,
// so "evil." and "evil" collide).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  isSafeMemberName, assertInside, WORKSPACE_ROOT,
  signReceipt, verifyReceipt, hashTree, sha256File,
} from '../scan-core.mjs';

test('rejects traversal, absolute paths, and Windows-specific escapes', () => {
  const bad = [
    '../escape.md',                 // traversal
    'a/../../escape.md',            // nested traversal
    '/etc/passwd',                  // posix absolute
    'C:\\Windows\\System32\\x.dll', // windows absolute
    'notes.md:hidden',              // NTFS alternate data stream
    'CON',                          // reserved device name
    'com1.txt',                     // reserved device name with extension
    'trailing.',                    // trailing dot -> resolves to 'trailing'
    'trailing ',                    // trailing space
    'bell\u0007.md',                // control character
  ];
  for (const name of bad) {
    assert.equal(isSafeMemberName(name).safe, false, `should reject: ${JSON.stringify(name)}`);
  }
});

test('accepts ordinary nested member names', () => {
  for (const name of ['SKILL.md', 'scripts/helper.py', 'a/b/c/d.json']) {
    assert.equal(isSafeMemberName(name).safe, true, `should accept: ${name}`);
  }
});

test('assertInside throws when the target escapes the root', () => {
  assert.throws(() => assertInside(WORKSPACE_ROOT, `${WORKSPACE_ROOT}/../outside.md`));
  assert.doesNotThrow(() => assertInside(WORKSPACE_ROOT, `${WORKSPACE_ROOT}/inside.md`));
});

// --- failure modes beyond the plan baseline -------------------------------------
// Added during implementation to cover newly discovered failure modes.
// Each of these is an escape a naive implementation permits.

test('rejects UNC and device-namespace paths', () => {
  for (const name of ['\\\\server\\share\\x.md', '//server/share/x.md', '\\\\?\\C:\\x.md', '\\\\.\\PhysicalDrive0']) {
    assert.equal(isSafeMemberName(name).safe, false, `should reject UNC/device: ${JSON.stringify(name)}`);
  }
});

test('rejects percent-encoded traversal', () => {
  // A zip member named "%2e%2e/x" is decoded by some consumers before use.
  for (const name of ['%2e%2e/escape.md', '%2E%2E/escape.md', 'a/%2e%2e/b.md']) {
    assert.equal(isSafeMemberName(name).safe, false, `should reject encoded traversal: ${name}`);
  }
});

test('rejects bidi override in member names (extension spoofing)', () => {
  // "photo\u202Egpj.exe" renders as "photoexe.jpg" in most file listings.
  assert.equal(isSafeMemberName('photo\u202Egpj.exe').safe, false);
  assert.equal(isSafeMemberName('doc\u200Bument.md').safe, false);
});

test('rejects non-string and degenerate input rather than throwing', () => {
  for (const value of [null, undefined, 42, {}, [], '', '   ', '.', '..']) {
    const result = isSafeMemberName(value);
    assert.equal(result.safe, false, `should reject: ${JSON.stringify(value)}`);
    assert.equal(typeof result.reason, 'string');
  }
});

test('rejects paths whose total length would break Win32 MAX_PATH handling', () => {
  assert.equal(isSafeMemberName(`${'a'.repeat(300)}.md`).safe, false);
  assert.equal(isSafeMemberName(`${'dir/'.repeat(80)}file.md`).safe, false);
});

test('assertInside rejects sibling-prefix confusion', () => {
  // "/root/workspace-evil" must not count as inside "/root/workspace".
  assert.throws(() => assertInside('/root/workspace', '/root/workspace-evil/x.md'));
  assert.doesNotThrow(() => assertInside('/root/workspace', '/root/workspace/x.md'));
});

test('assertInside handles non-string input by throwing, never by allowing', () => {
  for (const value of [null, undefined, 42, {}]) {
    assert.throws(() => assertInside(WORKSPACE_ROOT, value), `should throw for: ${JSON.stringify(value)}`);
    assert.throws(() => assertInside(value, WORKSPACE_ROOT), `should throw for root: ${JSON.stringify(value)}`);
  }
});

// --- Task 2: hashing, signing, receipts -----------------------------------------

test('a signed receipt verifies, and any mutation invalidates it', () => {
  const receipt = { receipt_id: 'test-1', files: [{ path: 'a.md', sha256: 'abc' }] };
  const signed = signReceipt(receipt);
  assert.equal(typeof signed.signature, 'string');
  assert.equal(verifyReceipt(signed).valid, true);

  const tampered = structuredClone(signed);
  tampered.files[0].sha256 = 'def';
  assert.equal(verifyReceipt(tampered).valid, false);
});

test('an unsigned receipt never verifies', () => {
  assert.equal(verifyReceipt({ receipt_id: 'test-2' }).valid, false);
  assert.equal(verifyReceipt(null).valid, false);
  assert.equal(verifyReceipt(undefined).valid, false);
  assert.equal(verifyReceipt('a string').valid, false);
});

test('a non-hex or wrong-length signature is rejected, not silently coerced', () => {
  // Buffer.from('zz', 'hex') yields an EMPTY buffer rather than throwing. A naive
  // implementation comparing two empty buffers would treat this as valid.
  const signed = signReceipt({ receipt_id: 'test-3' });
  for (const bad of ['zzzz', '', 'abc', signed.signature.slice(0, -2), `${signed.signature}ff`]) {
    assert.equal(verifyReceipt({ ...signed, signature: bad }).valid, false, `should reject signature: ${bad}`);
  }
});

test('adding any field changes the signature', () => {
  const signed = signReceipt({ receipt_id: 'test-4', files: [] });
  assert.equal(verifyReceipt({ ...signed, injected: 'extra' }).valid, false);
});

test('a NESTED key named "signature" is still covered by the hash', () => {
  // Excluding "signature" at every depth would leave a hole an attacker could hide
  // data in. Only the top-level signature field may be excluded.
  const signed = signReceipt({ receipt_id: 'test-5', stage3: { signature: 'original' } });
  assert.equal(verifyReceipt(signed).valid, true);
  const tampered = structuredClone(signed);
  tampered.stage3.signature = 'swapped';
  assert.equal(verifyReceipt(tampered).valid, false, 'nested signature field must be part of the signed payload');
});

test('key order does not affect the signature (canonical form)', () => {
  const a = signReceipt({ receipt_id: 'test-6', alpha: 1, beta: 2 });
  const b = signReceipt({ beta: 2, alpha: 1, receipt_id: 'test-6' });
  assert.equal(a.signature, b.signature);
});

test('hashTree returns one stable entry per file, sorted, POSIX-separated', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-'));
  fs.writeFileSync(path.join(dir, 'b.md'), 'bbb');
  fs.mkdirSync(path.join(dir, 'sub'));
  fs.writeFileSync(path.join(dir, 'sub', 'a.md'), 'aaa');

  const tree = hashTree(dir);
  assert.equal(tree.length, 2);
  assert.deepEqual(tree.map((f) => f.path), ['b.md', 'sub/a.md']);
  assert.equal(tree[0].sha256, hashTree(dir)[0].sha256);
  assert.match(tree[0].sha256, /^[0-9a-f]{64}$/);
});

test('hashTree fails loudly on a missing directory rather than returning empty', () => {
  // An empty result would make drift detection silently pass for a deleted artifact.
  assert.throws(() => hashTree(path.join(os.tmpdir(), 'sg-does-not-exist-12345')));
});

test('hashTree marks links instead of following them out of the tree', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sgl-'));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'sgo-'));
  fs.writeFileSync(path.join(outside, 'secret.md'), 'sensitive');
  try {
    fs.symlinkSync(outside, path.join(dir, 'link'), 'junction');
  } catch {
    return; // link creation unavailable in this environment; nothing to assert
  }
  const tree = hashTree(dir);
  assert.deepEqual(tree, [{ path: 'link', sha256: 'SYMLINK' }]);
});

test('sha256File is stable and matches a known vector', () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sgh-')), 'x.txt');
  fs.writeFileSync(file, 'abc');
  // Well-known SHA-256 of the ASCII string "abc".
  assert.equal(sha256File(file), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});
