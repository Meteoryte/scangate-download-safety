// ---------------------------------------------------------------------------
// scan-weights.mjs — SCANGATE model-asset scanner.
//
// Model files are executable in practice. A pickle's REDUCE opcode calls whatever the
// preceding GLOBAL imported, so `torch.load` on a hostile checkpoint is arbitrary code
// execution. SkillSpector does not analyze tensor files, so this check is ours.
//
// THIS SCANNER READS OPCODES AND NEVER UNPICKLES. Calling pickle.load to inspect a file
// executes the payload you were trying to inspect. Everything here treats the file as
// bytes.
// ---------------------------------------------------------------------------

import fs from 'node:fs';
import path from 'node:path';
import { listEntries, readMemberBuffer } from './scan-zip.mjs';

// Modules that legitimately appear in a torch / numpy checkpoint.
const ALLOW = [
  /^torch(\.|$)/,
  /^collections$/,
  /^numpy(\.|$)/,
  /^_codecs$/,
  /^builtins$/,          // narrowed below by the DENY list, which is checked first
  /^__builtin__$/,
];

// Execution sinks. Reaching any of these from a pickle is remote code execution.
// Checked BEFORE the allowlist, so `builtins.eval` is denied even though `builtins` is
// otherwise permitted.
const DENY = [
  ['os', /.*/], ['posix', /.*/], ['nt', /.*/],
  ['subprocess', /.*/], ['socket', /.*/], ['shutil', /.*/],
  ['pty', /.*/], ['runpy', /.*/], ['importlib', /.*/], ['sys', /.*/],
  ['webbrowser', /.*/], ['pickle', /.*/], ['pdb', /.*/], ['bdb', /.*/], ['code', /.*/],
  ['builtins', /^(eval|exec|compile|__import__|getattr|setattr|open|input|breakpoint)$/],
  ['__builtin__', /^(eval|exec|compile|__import__|getattr|setattr|open|input)$/],
  ['operator', /^(attrgetter|methodcaller|itemgetter)$/],
  ['functools', /^(partial|reduce)$/],
];

const WEIGHTS_RE = /\.(safetensors|gguf|pt|pth|ckpt|bin|pkl)$/i;
const ZIP_MAGIC = 0x04034b50;
const MAX_PICKLE_SCAN_BYTES = 64 * 1024 * 1024;

/**
 * Scan a pickle opcode stream for dangerous imports.
 *
 * @param {Buffer} buffer
 * @returns {Array<{rule: string, severity: string, detail: string}>}
 */
export function scanPickle(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) return [];

  const findings = [];
  const text = buffer.toString('latin1');
  const seen = new Set();

  // GLOBAL: 'c' <module> '\n' <name> '\n'
  for (const match of text.matchAll(/c([A-Za-z_][\w.]*)\n([A-Za-z_]\w*)\n/g)) {
    const [, mod, name] = match;
    const key = `${mod}.${name}`;
    if (seen.has(key)) continue;
    seen.add(key);

    if (DENY.some(([denyMod, nameRe]) => denyMod === mod && nameRe.test(name))) {
      findings.push({
        rule: 'pickle-execution-sink', severity: 'CRITICAL',
        detail: `pickle imports ${key} — loading this file would execute code`,
      });
      continue;
    }
    if (ALLOW.some((re) => re.test(mod))) continue;
    findings.push({
      rule: 'pickle-unknown-import', severity: 'MEDIUM',
      detail: `pickle imports unrecognized ${key}`,
    });
  }

  // STACK_GLOBAL (0x93) resolves module and name from the stack, hiding them from the
  // static GLOBAL pattern above.
  if (buffer.includes(0x93)) {
    findings.push({
      rule: 'pickle-stack-global', severity: 'HIGH',
      detail: 'STACK_GLOBAL opcode present — import target is resolved dynamically',
    });
  }

  // INST: 'i' <module> '\n' <name> '\n' — direct instantiation, protocol 0.
  if (/i[A-Za-z_][\w.]*\n[A-Za-z_]\w*\n/.test(text)) {
    findings.push({
      rule: 'pickle-inst', severity: 'HIGH',
      detail: 'INST opcode present — direct class instantiation from the stream',
    });
  }

  return findings;
}

/**
 * Validate safetensors structure: header length, JSON header, and tensor offsets that
 * stay inside the data region.
 */
export function validateSafetensors(abs) {
  let fd;
  try { fd = fs.openSync(abs, 'r'); }
  catch (error) { return [{ rule: 'safetensors-unreadable', severity: 'HIGH', detail: error.message }]; }

  try {
    const size = fs.fstatSync(fd).size;
    if (size < 8) {
      return [{ rule: 'safetensors-truncated', severity: 'HIGH', detail: 'file shorter than its header-length field' }];
    }

    const lenBuf = Buffer.alloc(8);
    fs.readSync(fd, lenBuf, 0, 8, 0);
    const headerLen = Number(lenBuf.readBigUInt64LE(0));
    if (!Number.isSafeInteger(headerLen) || headerLen <= 0 || headerLen > size - 8) {
      return [{
        rule: 'safetensors-bad-header-length', severity: 'HIGH',
        detail: `declared header length ${headerLen} does not fit in a ${size}-byte file`,
      }];
    }

    const headerBuf = Buffer.alloc(headerLen);
    fs.readSync(fd, headerBuf, 0, headerLen, 8);
    let header;
    try { header = JSON.parse(headerBuf.toString('utf8')); }
    catch { return [{ rule: 'safetensors-bad-header-json', severity: 'HIGH', detail: 'header is not valid JSON' }]; }

    if (!header || typeof header !== 'object') {
      return [{ rule: 'safetensors-bad-header-json', severity: 'HIGH', detail: 'header is not a JSON object' }];
    }

    const dataSize = size - 8 - headerLen;
    for (const [name, meta] of Object.entries(header)) {
      if (name === '__metadata__') continue;
      const offsets = meta?.data_offsets;
      if (!Array.isArray(offsets) || offsets.length !== 2) continue;
      const [start, end] = offsets;
      if (!Number.isFinite(start) || !Number.isFinite(end) || start < 0 || end > dataSize || start > end) {
        return [{
          rule: 'safetensors-offset-out-of-bounds', severity: 'HIGH',
          detail: `tensor "${name}" offsets [${start},${end}] fall outside the ${dataSize}-byte data region`,
        }];
      }
    }
    return [];
  } catch (error) {
    return [{ rule: 'safetensors-unparseable', severity: 'HIGH', detail: error.message }];
  } finally {
    fs.closeSync(fd);
  }
}

/** Validate GGUF magic and version. */
export function validateGguf(abs) {
  let fd;
  try { fd = fs.openSync(abs, 'r'); }
  catch (error) { return [{ rule: 'gguf-unreadable', severity: 'HIGH', detail: error.message }]; }

  try {
    const size = fs.fstatSync(fd).size;
    if (size < 8) return [{ rule: 'gguf-truncated', severity: 'HIGH', detail: 'file too small to contain a GGUF header' }];

    const head = Buffer.alloc(Math.min(24, size));
    fs.readSync(fd, head, 0, head.length, 0);

    if (head.subarray(0, 4).toString('ascii') !== 'GGUF') {
      return [{ rule: 'gguf-bad-magic', severity: 'HIGH', detail: 'missing GGUF magic bytes' }];
    }
    const version = head.readUInt32LE(4);
    if (version < 1 || version > 3) {
      return [{ rule: 'gguf-unknown-version', severity: 'MEDIUM', detail: `unexpected GGUF version ${version}` }];
    }
    return [];
  } catch (error) {
    return [{ rule: 'gguf-unparseable', severity: 'HIGH', detail: error.message }];
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Dispatch on file type. Anything in scope that cannot be parsed is BLOCKED rather than
 * passed: refusing a format is honest, scanning it badly is not.
 *
 * @param {string} abs
 * @returns {Array<{rule, severity, file, detail}>}
 */
export function scanWeightFile(abs) {
  if (!WEIGHTS_RE.test(abs)) return [];

  const name = path.basename(abs);
  const tag = (findings) => findings.map((finding) => ({ ...finding, file: name }));

  if (/\.safetensors$/i.test(abs)) return tag(validateSafetensors(abs));
  if (/\.gguf$/i.test(abs)) return tag(validateGguf(abs));

  let stat;
  try { stat = fs.statSync(abs); }
  catch (error) { return tag([{ rule: 'weights-unreadable', severity: 'HIGH', detail: error.message }]); }

  const findings = [];
  let head;
  try {
    const fd = fs.openSync(abs, 'r');
    try {
      head = Buffer.alloc(Math.min(4, stat.size));
      if (head.length === 4) fs.readSync(fd, head, 0, 4, 0);
    } finally { fs.closeSync(fd); }
  } catch (error) {
    return tag([{ rule: 'weights-unreadable', severity: 'HIGH', detail: error.message }]);
  }

  const isZip = head.length === 4 && head.readUInt32LE(0) === ZIP_MAGIC;

  if (isZip) {
    // PyTorch .pt/.pth are zip containers. The pickle lives in a member and may be
    // DEFLATED, so it must be inflated before its opcodes are visible.
    let entries;
    try { entries = listEntries(abs); }
    catch (error) {
      return tag([{
        rule: 'weights-unparseable', severity: 'HIGH',
        detail: `refusing to pass an unparseable zip container: ${error.message}`,
      }]);
    }

    const pickles = entries.filter((entry) => /\.pkl$/i.test(entry.name) || /(^|\/)data\.pkl$/i.test(entry.name));
    if (pickles.length === 0) {
      return tag([{
        rule: 'weights-no-pickle-found', severity: 'MEDIUM',
        detail: 'zip container holds no recognizable pickle member — structure not understood',
      }]);
    }

    for (const entry of pickles) {
      try {
        findings.push(...scanPickle(readMemberBuffer(abs, entry)));
      } catch (error) {
        findings.push({
          rule: 'weights-member-unreadable', severity: 'HIGH',
          detail: `could not inflate ${entry.name}: ${error.message}`,
        });
      }
    }
    return tag(findings);
  }

  if (stat.size > MAX_PICKLE_SCAN_BYTES) {
    findings.push({
      rule: 'weights-partial-scan', severity: 'MEDIUM',
      detail: `only the first ${MAX_PICKLE_SCAN_BYTES} bytes were scanned of ${stat.size} — file not fully cleared`,
    });
  }

  try {
    const fd = fs.openSync(abs, 'r');
    try {
      const length = Math.min(stat.size, MAX_PICKLE_SCAN_BYTES);
      const buffer = Buffer.alloc(length);
      fs.readSync(fd, buffer, 0, length, 0);
      findings.push(...scanPickle(buffer));
    } finally { fs.closeSync(fd); }
  } catch (error) {
    findings.push({ rule: 'weights-unreadable', severity: 'HIGH', detail: error.message });
  }

  return tag(findings);
}
