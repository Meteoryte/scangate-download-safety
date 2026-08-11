// ---------------------------------------------------------------------------
// scan-zip.mjs — SCANGATE archive reader.
//
// Why this exists instead of shelling out to `tar` or `Expand-Archive`:
// both of those EXTRACT FIRST and let you inspect afterwards. By then a traversal member,
// a junction, or a duplicate-name overwrite has already written outside the destination.
// Reading the central directory ourselves means every member name is validated BEFORE a
// single byte reaches disk.
//
// This module never trusts local file headers. Where the central directory and the local
// header disagree, that disagreement is itself a known evasion technique — the central
// directory is authoritative and a mismatch is a violation.
// ---------------------------------------------------------------------------

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { isSafeMemberName, assertInside } from './scan-core.mjs';

export const CAPS = {
  MAX_ARCHIVE_BYTES: 100 * 1024 * 1024,   // 100 MiB on disk
  MAX_MEMBERS: 10_000,
  MAX_UNCOMPRESSED: 500 * 1024 * 1024,    // 500 MiB expanded
  MAX_RATIO: 100,                          // per-member compression ratio
};

const EOCD_SIG = 0x06054b50;
const CD_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;
const ZIP64_SENTINEL = 0xFFFFFFFF;
const FLAG_ENCRYPTED = 0x0001;
const UNIX_MODE_SHIFT = 16;
const S_IFMT = 0o170000;
const S_IFLNK = 0o120000;

/**
 * Read the central directory. Throws on anything it cannot parse — an unreadable archive
 * must never be reported as an empty one, because "no members" reads as "nothing to scan".
 *
 * @param {string} zipPath
 * @returns {Array<{name, compressedSize, uncompressedSize, method, offset, flags, externalAttrs}>}
 */
export function listEntries(zipPath) {
  const buf = fs.readFileSync(zipPath);
  if (buf.length < 22) throw new Error('file is too small to be a zip archive');

  // The EOCD sits at the end, possibly followed by up to 64KB of comment.
  let eocd = -1;
  const floor = Math.max(0, buf.length - 22 - 65_536);
  for (let i = buf.length - 22; i >= floor; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('not a zip archive (no end-of-central-directory record)');

  const count = buf.readUInt16LE(eocd + 10);
  let ptr = buf.readUInt32LE(eocd + 16);
  const entries = [];

  for (let i = 0; i < count; i++) {
    if (ptr + 46 > buf.length) throw new Error(`central directory truncated at entry ${i}`);
    if (buf.readUInt32LE(ptr) !== CD_SIG) throw new Error(`corrupt central directory at entry ${i}`);

    const flags = buf.readUInt16LE(ptr + 8);
    const method = buf.readUInt16LE(ptr + 10);
    const compressedSize = buf.readUInt32LE(ptr + 20);
    const uncompressedSize = buf.readUInt32LE(ptr + 24);
    const nameLen = buf.readUInt16LE(ptr + 28);
    const extraLen = buf.readUInt16LE(ptr + 30);
    const commentLen = buf.readUInt16LE(ptr + 32);
    const externalAttrs = buf.readUInt32LE(ptr + 38);
    const offset = buf.readUInt32LE(ptr + 42);

    if (ptr + 46 + nameLen > buf.length) throw new Error(`entry ${i} name extends past end of file`);
    const name = buf.subarray(ptr + 46, ptr + 46 + nameLen).toString('utf8');

    entries.push({ name, compressedSize, uncompressedSize, method, offset, flags, externalAttrs });
    ptr += 46 + nameLen + extraLen + commentLen;
  }

  return entries;
}

/**
 * Validate an archive without extracting it.
 *
 * @param {string} zipPath
 * @param {typeof CAPS} caps
 * @returns {{ ok: boolean, violations: string[], entries: Array }}
 */
export function validateArchive(zipPath, caps = CAPS) {
  const violations = [];

  let size;
  try { size = fs.statSync(zipPath).size; }
  catch (error) { return { ok: false, violations: [`unreadable archive: ${error.message}`], entries: [] }; }
  if (size > caps.MAX_ARCHIVE_BYTES) violations.push(`archive exceeds size cap: ${size} bytes`);

  let entries;
  try { entries = listEntries(zipPath); }
  catch (error) { return { ok: false, violations: [`unreadable archive: ${error.message}`], entries: [] }; }

  if (entries.length > caps.MAX_MEMBERS) {
    violations.push(`archive exceeds member cap: ${entries.length} members`);
  }

  let total = 0;
  const seen = new Set();

  for (const entry of entries) {
    const label = JSON.stringify(entry.name);

    // Duplicate names mean the later member silently overwrites the earlier one, so what
    // a reviewer reads is not necessarily what ends up on disk.
    const key = entry.name.toLowerCase();
    if (seen.has(key)) violations.push(`duplicate member name ${label}`);
    seen.add(key);

    const check = isSafeMemberName(entry.name);
    if (!check.safe && !entry.name.endsWith('/')) {
      violations.push(`unsafe member ${label}: ${check.reason}`);
    }

    if (entry.flags & FLAG_ENCRYPTED) {
      violations.push(`encrypted member ${label} cannot be scanned`);
    }

    // 0xFFFFFFFF is the zip64 sentinel meaning "real size lives in the extra field".
    // Reading it literally produces a 4GB size and nonsense ratio arithmetic.
    if (entry.compressedSize === ZIP64_SENTINEL || entry.uncompressedSize === ZIP64_SENTINEL) {
      violations.push(`zip64 archive member ${label} is not supported — refusing rather than guessing sizes`);
      continue;
    }

    const unixMode = (entry.externalAttrs >>> UNIX_MODE_SHIFT) & 0xFFFF;
    if ((unixMode & S_IFMT) === S_IFLNK) {
      violations.push(`symlink member ${label} — links may point outside the destination`);
    }

    total += entry.uncompressedSize;
    if (entry.compressedSize > 0) {
      const ratio = entry.uncompressedSize / entry.compressedSize;
      if (ratio > caps.MAX_RATIO) {
        violations.push(`compression ratio ${Math.round(ratio)}:1 exceeds cap for ${label}`);
      }
    }
  }

  if (total > caps.MAX_UNCOMPRESSED) {
    violations.push(`uncompressed total exceeds cap: ${total} bytes`);
  }

  return { ok: violations.length === 0, violations, entries };
}

/**
 * Read a single member into memory without writing anything to disk.
 *
 * Needed by the weights scanner: a PyTorch `.pt` is a zip container, and its `data.pkl`
 * may be DEFLATED — in which case scanning the container's raw bytes would see compressed
 * noise and miss every opcode. The member has to be inflated to be scanned.
 *
 * @param {string} zipPath
 * @param {{name, offset, compressedSize, method}} entry
 * @param {number} maxBytes
 * @returns {Buffer}
 */
export function readMemberBuffer(zipPath, entry, maxBytes = CAPS.MAX_UNCOMPRESSED) {
  const buf = fs.readFileSync(zipPath);
  if (buf.readUInt32LE(entry.offset) !== LOCAL_SIG) {
    throw new Error(`local header missing for ${entry.name}`);
  }
  const nameLen = buf.readUInt16LE(entry.offset + 26);
  const extraLen = buf.readUInt16LE(entry.offset + 28);
  const start = entry.offset + 30 + nameLen + extraLen;
  const end = start + entry.compressedSize;
  if (end > buf.length) throw new Error(`member ${entry.name} extends past end of file`);

  const raw = buf.subarray(start, end);
  if (entry.method === 0) return raw;
  if (entry.method === 8) return zlib.inflateRawSync(raw, { maxOutputLength: maxBytes });
  throw new Error(`unsupported compression method ${entry.method} for ${entry.name}`);
}

/**
 * Extract a validated archive. Refuses outright if validation failed — partial extraction
 * of a hostile archive is worse than none.
 *
 * @param {string} zipPath
 * @param {string} destDir
 * @param {typeof CAPS} caps
 * @returns {{ extracted: number }}
 */
export function extractTo(zipPath, destDir, caps = CAPS) {
  const validation = validateArchive(zipPath, caps);
  if (!validation.ok) {
    throw new Error(`refusing to extract: ${validation.violations.join('; ')}`);
  }

  const buf = fs.readFileSync(zipPath);
  let extracted = 0;

  for (const entry of validation.entries) {
    if (entry.name.endsWith('/')) continue;

    const target = path.join(destDir, entry.name);
    assertInside(destDir, target);   // lexical containment before any write

    // Verify the local header agrees with the central directory before reading data.
    if (buf.readUInt32LE(entry.offset) !== LOCAL_SIG) {
      throw new Error(`local header missing for ${entry.name} — central directory disagrees with file body`);
    }
    const nameLen = buf.readUInt16LE(entry.offset + 26);
    const extraLen = buf.readUInt16LE(entry.offset + 28);
    const localName = buf.subarray(entry.offset + 30, entry.offset + 30 + nameLen).toString('utf8');
    if (localName !== entry.name) {
      throw new Error(`local header name "${localName}" disagrees with central directory "${entry.name}"`);
    }

    const start = entry.offset + 30 + nameLen + extraLen;
    const end = start + entry.compressedSize;
    if (end > buf.length) throw new Error(`member ${entry.name} extends past end of file`);

    const raw = buf.subarray(start, end);
    let data;
    if (entry.method === 0) {
      data = raw;
    } else if (entry.method === 8) {
      data = zlib.inflateRawSync(raw, { maxOutputLength: caps.MAX_UNCOMPRESSED });
    } else {
      throw new Error(`unsupported compression method ${entry.method} for ${entry.name}`);
    }

    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, data);
    extracted++;
  }

  return { extracted };
}
