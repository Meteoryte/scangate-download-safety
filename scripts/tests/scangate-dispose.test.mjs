import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { dispose } from '../scan-dispose.mjs';
import { receiptPathFor, verifyReceipt } from '../scan-core.mjs';

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sgd-'));
  const id = `fixture-${crypto.randomUUID()}`;
  const entry = path.join(root, id);
  fs.mkdirSync(path.join(entry, 'payload'), { recursive: true });
  fs.mkdirSync(path.join(entry, '_source'), { recursive: true });
  fs.writeFileSync(path.join(entry, 'payload', 'artifact.txt'), 'quarantine-copy');
  fs.writeFileSync(path.join(entry, '_source', 'artifact.txt'), 'landed-copy');
  fs.writeFileSync(path.join(entry, 'intake.json'), JSON.stringify({ tier: 'T1', source: 'fixture' }));
  const adopted = path.join(root, 'landed.txt');
  fs.writeFileSync(adopted, 'landed-copy');
  return { root, id, adopted };
}

test('ALLOW receipt attests the real landed file when an adopted path is supplied', () => {
  const { root, id, adopted } = fixture();
  try {
    const result = dispose({ id, decision: 'ALLOW', by: 'test', root, adoptedPath: adopted });
    const receipt = JSON.parse(fs.readFileSync(result.receiptPath, 'utf8'));
    assert.equal(receipt.adopted_path, adopted);
    assert.equal(receipt.files.length, 1);
    assert.equal(receipt.files[0].path, 'landed.txt');
    assert.equal(verifyReceipt(receipt).valid, true);
  } finally {
    fs.rmSync(receiptPathFor(id), { force: true });
  }
});

test('non-ALLOW decisions cannot smuggle an adopted path into a receipt', () => {
  const { root, id, adopted } = fixture();
  assert.throws(
    () => dispose({ id, decision: 'DEFERRED', by: 'test', root, adoptedPath: adopted }),
    /valid only for an ALLOW/i,
  );
});
