// SCANGATE layer-1 enforcement hook.
//
// Two properties are in tension here and both are tested:
//
//   1. FAIL CLOSED — anything touching quarantined content without a valid ALLOW receipt
//      is denied, including when the hook itself errors.
//   2. TINY BLAST RADIUS — a call that does not mention the quarantine root is allowed
//      without the hook touching the filesystem at all. A security control that breaks
//      ordinary work gets disabled by its owner, and a disabled control protects nothing.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { evaluate } from '../hooks/scangate-pretooluse.mjs';
import { RECEIPTS_DIR, signReceipt, QUARANTINE_ROOT } from '../scan-core.mjs';

const quarantined = `${QUARANTINE_ROOT.split(path.sep).join('/')}/2026-08-05-thing/payload/SKILL.md`;

// --- denial -------------------------------------------------------------------

test('denies a Read of an un-receipted quarantine path', () => {
  const out = evaluate({ tool_name: 'Read', tool_input: { file_path: quarantined } });
  assert.equal(out.decision, 'deny');
  assert.match(out.reason, /scan/i);
});

test('denies a Bash command that touches the quarantine root', () => {
  const out = evaluate({ tool_name: 'Bash', tool_input: { command: `cat "${quarantined}"` } });
  assert.equal(out.decision, 'deny');
});

test('denies Grep and Glob scoped into quarantine', () => {
  assert.equal(evaluate({ tool_name: 'Grep', tool_input: { path: '_quarantine' } }).decision, 'deny');
  assert.equal(evaluate({ tool_name: 'Glob', tool_input: { pattern: '_quarantine/**/*.md' } }).decision, 'deny');
});

test('denies regardless of slash direction or letter case', () => {
  for (const target of [
    '_quarantine\\x\\payload\\a.md',
    '_QUARANTINE/x/payload/a.md',
    'X:/workspace/_quarantine/x/a.md',
    'some/../_quarantine/x/a.md',
  ]) {
    assert.equal(evaluate({ tool_name: 'Read', tool_input: { file_path: target } }).decision, 'deny', `should deny: ${target}`);
  }
});

test('denies a quarantine path nested deep inside the tool input', () => {
  const out = evaluate({ tool_name: 'Edit', tool_input: { edits: [{ target: { file_path: '_quarantine/x/a.md' } }] } });
  assert.equal(out.decision, 'deny');
});

// --- allowance ----------------------------------------------------------------

test('allows ordinary workspace paths', () => {
  assert.equal(evaluate({ tool_name: 'Read', tool_input: { file_path: 'CLAUDE.md' } }).decision, 'allow');
  assert.equal(evaluate({ tool_name: 'Bash', tool_input: { command: 'pnpm run lint' } }).decision, 'allow');
});

test('allows the workspace-authored files in the quarantine root itself', () => {
  // README.md and .gitignore are ours, not artifacts. Denying them would make the
  // quarantine folder undocumentable from inside the workspace.
  assert.equal(evaluate({ tool_name: 'Read', tool_input: { file_path: '_quarantine/README.md' } }).decision, 'allow');
  assert.equal(evaluate({ tool_name: 'Read', tool_input: { file_path: '_quarantine/.gitignore' } }).decision, 'allow');
});

test('allows a quarantine path that HAS a valid ALLOW receipt', () => {
  const id = 'test-receipt-allow';
  fs.mkdirSync(RECEIPTS_DIR, { recursive: true });
  const file = path.join(RECEIPTS_DIR, `${id}.json`);
  fs.writeFileSync(file, JSON.stringify(signReceipt({
    receipt_id: id, files: [], stage4: { decision: 'ALLOW', decided_by: 'operator' },
  })));
  try {
    const out = evaluate({ tool_name: 'Read', tool_input: { file_path: `_quarantine/${id}/payload/a.md` } });
    assert.equal(out.decision, 'allow');
  } finally {
    fs.rmSync(file, { force: true });
  }
});

test('denies when a receipt exists but the decision is not ALLOW', () => {
  const id = 'test-receipt-blocked';
  fs.mkdirSync(RECEIPTS_DIR, { recursive: true });
  const file = path.join(RECEIPTS_DIR, `${id}.json`);
  fs.writeFileSync(file, JSON.stringify(signReceipt({
    receipt_id: id, files: [], stage4: { decision: 'BLOCKED' },
  })));
  try {
    assert.equal(evaluate({ tool_name: 'Read', tool_input: { file_path: `_quarantine/${id}/payload/a.md` } }).decision, 'deny');
  } finally {
    fs.rmSync(file, { force: true });
  }
});

test('denies when the receipt signature does not verify', () => {
  const id = 'test-receipt-forged';
  fs.mkdirSync(RECEIPTS_DIR, { recursive: true });
  const file = path.join(RECEIPTS_DIR, `${id}.json`);
  // A hand-written receipt with a plausible-looking but invalid signature.
  fs.writeFileSync(file, JSON.stringify({
    receipt_id: id, files: [], stage4: { decision: 'ALLOW' }, signature: 'a'.repeat(64),
  }));
  try {
    assert.equal(evaluate({ tool_name: 'Read', tool_input: { file_path: `_quarantine/${id}/payload/a.md` } }).decision, 'deny',
      'forging a receipt by hand must not open the gate');
  } finally {
    fs.rmSync(file, { force: true });
  }
});

// --- blast radius and fail-closed ---------------------------------------------

test('fails closed on malformed input that still mentions quarantine', () => {
  const out = evaluate({ tool_name: 'Read', tool_input: { file_path: { nested: '_quarantine/x' } } });
  assert.equal(out.decision, 'deny');
});

test('allows when input is malformed and unrelated to quarantine', () => {
  // Blast-radius control: the hook must not brick unrelated tool calls.
  assert.equal(evaluate({ tool_name: 'Read', tool_input: null }).decision, 'allow');
  assert.equal(evaluate(null).decision, 'allow');
  assert.equal(evaluate(undefined).decision, 'allow');
  assert.equal(evaluate({}).decision, 'allow');
});

// --- precision: gate PATHS, not prose -----------------------------------------

test('writing a file whose CONTENT mentions the gate is allowed', () => {
  // Regression, found live on 2026-08-06: an earlier version walked every value in the
  // tool input, so editing this protocol's own source or documentation was denied. A gate
  // that cannot be documented gets removed.
  const marker = ['_quar', 'antine'].join('');
  assert.equal(evaluate({
    tool_name: 'Write',
    tool_input: { file_path: 'docs/protocol.md', content: `The ${marker} directory holds unscanned artifacts.` },
  }).decision, 'allow');

  assert.equal(evaluate({
    tool_name: 'Edit',
    tool_input: { file_path: 'scripts/scan-core.mjs', old_string: 'x', new_string: `const ROOT = '${marker}';` },
  }).decision, 'allow');
});

test('the path field is still gated even when content is innocuous', () => {
  const marker = ['_quar', 'antine'].join('');
  assert.equal(evaluate({
    tool_name: 'Write',
    tool_input: { file_path: `${marker}/x/payload/evil.md`, content: 'harmless looking' },
  }).decision, 'deny');
});

// --- sanctioned tool invocations ----------------------------------------------

test('the scan tools may reference quarantined paths', () => {
  const marker = ['_quar', 'antine'].join('');
  for (const command of [
    `node scripts/scan-run.mjs "${marker}/x/payload" T3`,
    `pnpm run scan:run -- ${marker}/x/payload`,
    `node "X:/ws/scripts/scan-detonate.mjs" ${marker}/x/payload`,
  ]) {
    assert.equal(evaluate({ tool_name: 'Bash', tool_input: { command } }).decision, 'allow', `should allow: ${command}`);
  }
});

test('a sanctioned command with anything chained onto it is DENIED', () => {
  // Otherwise the allowance becomes a universal bypass.
  const marker = ['_quar', 'antine'].join('');
  for (const command of [
    `node scripts/scan-run.mjs x; cat ${marker}/x/payload/SKILL.md`,
    `node scripts/scan-run.mjs x && cat ${marker}/x/SKILL.md`,
    `node scripts/scan-run.mjs x | tee ${marker}/x/SKILL.md`,
    `node scripts/scan-run.mjs x $(cat ${marker}/x/SKILL.md)`,
  ]) {
    assert.equal(evaluate({ tool_name: 'Bash', tool_input: { command } }).decision, 'deny', `should deny: ${command}`);
  }
});

test('a non-sanctioned command cannot smuggle a sanctioned prefix mid-string', () => {
  const marker = ['_quar', 'antine'].join('');
  assert.equal(evaluate({
    tool_name: 'Bash',
    tool_input: { command: `cat ${marker}/x/SKILL.md # node scripts/scan-run.mjs` },
  }).decision, 'deny');
});

test('the deny reason tells the operator what to actually do', () => {
  const out = evaluate({ tool_name: 'Read', tool_input: { file_path: quarantined } });
  assert.match(out.reason, /scan:run|scan gate|protocol/i,
    'a deny that does not say how to proceed trains people to bypass the control');
});
