// SCANGATE safe ZIP reader.
//
// Archives are built byte-by-byte here rather than shelled out to a zip tool, so the
// tests can construct malformed and hostile structures that no well-behaved packer would
// produce — which is exactly the input this module exists to survive.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { validateArchive, listEntries, extractTo, CAPS } from '../scan-zip.mjs';

/**
 * Build a ZIP archive. `members` is [{ name, data, externalAttrs?, flags?, forceSizes? }].
 */
function buildZip(members, options = {}) {
  const chunks = [];
  const records = [];
  let offset = 0;

  for (const member of members) {
    const raw = Buffer.from(member.data ?? '');
    const deflated = zlib.deflateRawSync(raw);
    const nameBuf = Buffer.from(member.name, 'utf8');
    const compressedSize = member.forceSizes?.compressed ?? deflated.length;
    const uncompressedSize = member.forceSizes?.uncompressed ?? raw.length;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(member.flags ?? 0, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(0, 14);
    local.writeUInt32LE(compressedSize, 18);
    local.writeUInt32LE(uncompressedSize, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);

    chunks.push(local, nameBuf, deflated);
    records.push({ member, nameBuf, compressedSize, uncompressedSize, offset });
    offset += 30 + nameBuf.length + deflated.length;
  }

  const cdStart = offset;
  for (const record of records) {
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(record.member.flags ?? 0, 8);
    cd.writeUInt16LE(8, 10);
    cd.writeUInt32LE(0, 16);
    cd.writeUInt32LE(record.compressedSize, 20);
    cd.writeUInt32LE(record.uncompressedSize, 24);
    cd.writeUInt16LE(record.nameBuf.length, 28);
    cd.writeUInt16LE(0, 30);
    cd.writeUInt16LE(0, 32);
    cd.writeUInt32LE(record.member.externalAttrs ?? 0, 38);
    cd.writeUInt32LE(record.offset, 42);
    chunks.push(cd, record.nameBuf);
    offset += 46 + record.nameBuf.length;
  }

  if (!options.omitEocd) {
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(records.length, 8);
    eocd.writeUInt16LE(records.length, 10);
    eocd.writeUInt32LE(offset - cdStart, 12);
    eocd.writeUInt32LE(cdStart, 16);
    chunks.push(eocd);
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sgz-'));
  const zip = path.join(dir, 'a.zip');
  fs.writeFileSync(zip, Buffer.concat(chunks));
  return zip;
}

// --- baseline -------------------------------------------------------------------

test('a benign archive validates and lists its entries', () => {
  const zip = buildZip([{ name: 'SKILL.md', data: 'hello' }]);
  const result = validateArchive(zip);
  assert.equal(result.ok, true, result.violations.join('; '));
  assert.equal(result.entries.length, 1);
  assert.equal(result.entries[0].name, 'SKILL.md');
});

test('extraction writes the real content', () => {
  const zip = buildZip([{ name: 'a/b.md', data: 'payload-content' }]);
  const dest = fs.mkdtempSync(path.join(os.tmpdir(), 'sgx-'));
  const result = extractTo(zip, dest);
  assert.equal(result.extracted, 1);
  assert.equal(fs.readFileSync(path.join(dest, 'a', 'b.md'), 'utf8'), 'payload-content');
});

// --- hostile structures ---------------------------------------------------------

test('a traversal member is rejected before extraction', () => {
  const zip = buildZip([{ name: '../../evil.md', data: 'pwn' }]);
  const result = validateArchive(zip);
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => /traversal/i.test(v)), result.violations.join('; '));
});

test('extractTo refuses an archive that failed validation', () => {
  const zip = buildZip([{ name: '../../evil.md', data: 'pwn' }]);
  const dest = fs.mkdtempSync(path.join(os.tmpdir(), 'sgx2-'));
  assert.throws(() => extractTo(zip, dest), /refusing to extract/i);
  assert.equal(fs.readdirSync(dest).length, 0, 'nothing may be written when validation fails');
});

test('an over-count archive is rejected by the member cap', () => {
  const zip = buildZip([{ name: 'a.md', data: 'x' }, { name: 'b.md', data: 'y' }]);
  const result = validateArchive(zip, { ...CAPS, MAX_MEMBERS: 1 });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => /member/i.test(v)));
});

test('a high compression ratio is rejected as a zip bomb', () => {
  const zip = buildZip([{ name: 'bomb.txt', data: 'A'.repeat(2_000_000) }]);
  const result = validateArchive(zip, { ...CAPS, MAX_RATIO: 5 });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => /ratio/i.test(v)));
});

test('an uncompressed total over the cap is rejected', () => {
  const zip = buildZip([{ name: 'big.txt', data: 'A'.repeat(100_000) }]);
  const result = validateArchive(zip, { ...CAPS, MAX_UNCOMPRESSED: 1000 });
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => /uncompressed total/i.test(v)));
});

test('a missing end-of-central-directory record is an unreadable archive, not an empty one', () => {
  const zip = buildZip([{ name: 'a.md', data: 'x' }], { omitEocd: true });
  const result = validateArchive(zip);
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => /unreadable|central directory/i.test(v)));
});

test('a non-zip file is rejected rather than parsed as empty', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sgn-'));
  const notZip = path.join(dir, 'x.zip');
  fs.writeFileSync(notZip, 'this is plain text, not an archive');
  const result = validateArchive(notZip);
  assert.equal(result.ok, false);
  assert.throws(() => listEntries(notZip));
});

test('duplicate member names are rejected (last-write-wins overwrite)', () => {
  const zip = buildZip([{ name: 'a.md', data: 'first' }, { name: 'a.md', data: 'second' }]);
  const result = validateArchive(zip);
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => /duplicate/i.test(v)), result.violations.join('; '));
});

test('zip64 sentinel sizes are rejected rather than read as bogus numbers', () => {
  // 0xFFFFFFFF means "the real size is in the zip64 extra field". Reading it literally
  // yields a 4GB size and nonsense ratio math.
  const zip = buildZip([{ name: 'a.md', data: 'x', forceSizes: { compressed: 0xFFFFFFFF, uncompressed: 0xFFFFFFFF } }]);
  const result = validateArchive(zip);
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => /zip64/i.test(v)), result.violations.join('; '));
});

test('an encrypted entry is rejected because it cannot be scanned', () => {
  // General-purpose bit 0 set = encrypted. Content we cannot read is content we cannot clear.
  const zip = buildZip([{ name: 'a.md', data: 'x', flags: 0x0001 }]);
  const result = validateArchive(zip);
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => /encrypt/i.test(v)), result.violations.join('; '));
});

test('a unix symlink member is rejected', () => {
  // External attributes high 16 bits carry the unix mode; S_IFLNK is 0xA000.
  const zip = buildZip([{ name: 'link', data: '/etc/passwd', externalAttrs: 0xA1FF0000 }]);
  const result = validateArchive(zip);
  assert.equal(result.ok, false);
  assert.ok(result.violations.some((v) => /symlink/i.test(v)), result.violations.join('; '));
});
