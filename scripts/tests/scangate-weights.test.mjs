// SCANGATE weights scanner.
//
// Model files are executable in practice: a pickle's REDUCE opcode calls whatever the
// preceding GLOBAL imported, which makes "load this checkpoint" equivalent to "run this
// code". SkillSpector does not analyze tensor files, so this is SCANGATE's own check.
//
// Critically, this scanner READS OPCODES and never unpickles. Calling pickle.load to
// inspect a file executes the payload you were trying to inspect.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scanPickle, validateSafetensors, validateGguf, scanWeightFile } from '../scan-weights.mjs';

// GLOBAL opcode is 'c' followed by module\nname\n
const global_ = (mod, name) => Buffer.from(`c${mod}\n${name}\n`, 'latin1');
const REDUCE = Buffer.from('R', 'latin1');

const tmpFile = (name, data) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sgw-'));
  const file = path.join(dir, name);
  fs.writeFileSync(file, data);
  return file;
};

// --- pickle opcodes -------------------------------------------------------------

test('flags os.system + REDUCE as CRITICAL weights-borne RCE', () => {
  const findings = scanPickle(Buffer.concat([global_('os', 'system'), REDUCE]));
  assert.ok(findings.some((f) => f.severity === 'CRITICAL' && /os\.system/.test(f.detail)));
});

test('flags every known execution sink', () => {
  const sinks = [['posix', 'system'], ['nt', 'system'], ['subprocess', 'Popen'],
    ['builtins', 'eval'], ['builtins', 'exec'], ['builtins', '__import__'],
    ['socket', 'socket'], ['shutil', 'rmtree'], ['runpy', '_run_code'], ['importlib', 'import_module']];
  for (const [mod, name] of sinks) {
    const findings = scanPickle(Buffer.concat([global_(mod, name), REDUCE]));
    assert.ok(findings.some((f) => f.severity === 'CRITICAL'), `${mod}.${name} should be CRITICAL`);
  }
});

test('allows the ordinary torch rebuild path without a critical finding', () => {
  const findings = scanPickle(Buffer.concat([
    global_('torch._utils', '_rebuild_tensor_v2'),
    global_('collections', 'OrderedDict'),
    global_('numpy.core.multiarray', '_reconstruct'),
    REDUCE,
  ]));
  assert.equal(findings.filter((f) => f.severity === 'CRITICAL').length, 0);
  assert.equal(findings.filter((f) => f.rule === 'pickle-unknown-import').length, 0);
});

test('an unrecognized import is reported for review, not silently passed', () => {
  const findings = scanPickle(Buffer.concat([global_('some_vendor_lib', 'Thing'), REDUCE]));
  assert.ok(findings.some((f) => f.severity === 'MEDIUM' && /some_vendor_lib/.test(f.detail)));
});

test('STACK_GLOBAL and INST opcodes are flagged as dynamic import paths', () => {
  assert.ok(scanPickle(Buffer.from([0x93])).some((f) => f.rule === 'pickle-stack-global'));
  assert.ok(scanPickle(Buffer.from('ios\nsystem\n', 'latin1')).some((f) => f.rule === 'pickle-inst'));
});

test('scanPickle handles empty and non-buffer input without throwing', () => {
  assert.deepEqual(scanPickle(Buffer.alloc(0)), []);
  assert.deepEqual(scanPickle(null), []);
  assert.deepEqual(scanPickle('a string'), []);
});

test('a module reported once is not reported repeatedly', () => {
  const repeated = Buffer.concat([global_('os', 'system'), global_('os', 'system'), global_('os', 'system')]);
  assert.equal(scanPickle(repeated).filter((f) => f.rule === 'pickle-execution-sink').length, 1);
});

// --- safetensors ----------------------------------------------------------------

test('a well-formed safetensors file validates', () => {
  const header = Buffer.from(JSON.stringify({ t: { dtype: 'F32', shape: [1], data_offsets: [0, 4] } }), 'utf8');
  const len = Buffer.alloc(8);
  len.writeBigUInt64LE(BigInt(header.length));
  const file = tmpFile('m.safetensors', Buffer.concat([len, header, Buffer.alloc(4)]));
  assert.deepEqual(validateSafetensors(file), []);
});

test('safetensors with an out-of-bounds tensor offset is flagged', () => {
  const header = Buffer.from(JSON.stringify({ t: { dtype: 'F32', shape: [1], data_offsets: [0, 999999] } }), 'utf8');
  const len = Buffer.alloc(8);
  len.writeBigUInt64LE(BigInt(header.length));
  const file = tmpFile('bad.safetensors', Buffer.concat([len, header, Buffer.alloc(4)]));
  assert.ok(validateSafetensors(file).some((f) => /offset/i.test(f.rule)));
});

test('safetensors with a lying header length is flagged, not read past the end', () => {
  const len = Buffer.alloc(8);
  len.writeBigUInt64LE(BigInt(0xFFFFFF));
  const file = tmpFile('lying.safetensors', Buffer.concat([len, Buffer.from('{}')]));
  assert.ok(validateSafetensors(file).some((f) => /header-length/i.test(f.rule)));
});

test('a truncated safetensors file is flagged rather than crashing', () => {
  assert.ok(validateSafetensors(tmpFile('tiny.safetensors', Buffer.alloc(3))).some((f) => /truncated/i.test(f.rule)));
});

// --- gguf -----------------------------------------------------------------------

test('a well-formed GGUF header validates', () => {
  const head = Buffer.alloc(24);
  head.write('GGUF', 0, 'ascii');
  head.writeUInt32LE(3, 4);
  assert.deepEqual(validateGguf(tmpFile('m.gguf', head)), []);
});

test('a bad GGUF magic is flagged', () => {
  assert.ok(validateGguf(tmpFile('bad.gguf', Buffer.alloc(24))).some((f) => /magic/i.test(f.rule)));
});

// --- dispatch -------------------------------------------------------------------

test('scanWeightFile refuses a format it cannot parse instead of passing it', () => {
  // Refusing a format is honest; scanning it badly is not.
  const findings = scanWeightFile(tmpFile('weird.ckpt', Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00, 0x00])));
  assert.ok(findings.some((f) => f.severity === 'HIGH' || f.severity === 'MEDIUM'), JSON.stringify(findings));
});

test('scanWeightFile ignores files that are not weights', () => {
  assert.deepEqual(scanWeightFile(tmpFile('README.md', 'not a model')), []);
});

test('scanWeightFile tags findings with the file name', () => {
  const file = tmpFile('evil.pkl', Buffer.concat([global_('os', 'system'), REDUCE]));
  const findings = scanWeightFile(file);
  assert.ok(findings.length > 0);
  assert.equal(findings[0].file, 'evil.pkl');
});
