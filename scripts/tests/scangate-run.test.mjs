// SCANGATE stage-1 orchestration.
//
// The most important behaviour tested here is the scanner-unavailable path. Every real
// scanner integration eventually hits a day when the daemon is down or the image is
// missing, and the tempting response is to log a warning and continue — which silently
// converts a security gate into a decoration. An unavailable scanner must block exactly
// as hard as a detected payload.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scoreFromFindings, decide, parseScanReport, runStage1 } from '../scan-run.mjs';

const emptyDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sgr-'));

const fakeSpawn = (result) => () => ({ status: 0, stdout: '', stderr: '', error: null, ...result });

const REPORT_CLEAN = JSON.stringify({
  issues: [],
  components: [{ path: 'SKILL.md', type: 'markdown' }],
  analysis_completeness: { coverage_percent: 100, fully_inspected_files: 1, entirely_uninspected_files: 0 },
  risk_assessment: { score: 0, severity: 'LOW', recommendation: 'SAFE' },
});

// --- scoring --------------------------------------------------------------------

test('score accumulates per spec: CRITICAL 50, HIGH 25, MEDIUM 10, LOW 5', () => {
  assert.equal(scoreFromFindings([{ severity: 'CRITICAL' }]), 50);
  assert.equal(scoreFromFindings([{ severity: 'HIGH' }, { severity: 'MEDIUM' }, { severity: 'LOW' }]), 40);
  assert.equal(scoreFromFindings([]), 0);
  assert.equal(scoreFromFindings([{ severity: 'NONSENSE' }]), 0);
});

test('T3 is held to the SAFE band while T1 keeps the default cut', () => {
  assert.equal(decide(30, 'T3'), 'BLOCKED');            // 30 > 20
  assert.equal(decide(30, 'T1'), 'FINDINGS_ACCEPTED');
  assert.equal(decide(0, 'T1'), 'NO_FINDINGS');
  assert.equal(decide(0, 'T3'), 'NO_FINDINGS');
  assert.equal(decide(60, 'T1'), 'BLOCKED');            // 60 > 50
});

test('the verdict vocabulary never includes SAFE', () => {
  for (const [score, tier] of [[0, 'T1'], [30, 'T1'], [90, 'T3'], [0, 'T3']]) {
    assert.notEqual(decide(score, tier), 'SAFE');
  }
});

// --- report parsing -------------------------------------------------------------
// Fixtures below use SkillSpector v2.5.3's real JSON schema, captured from a live run.
//
// The JSON format is used instead of SARIF because SARIF only emits `artifacts` when
// there ARE findings. On a clean scan it reports zero analyzed paths, which made the
// unpack-gap check flag every file of every clean artifact — noise that would have got
// the check switched off. JSON carries `components[]` and `analysis_completeness`.

test('parseScanReport extracts findings and the set of analyzed paths', () => {
  const report = JSON.stringify({
    issues: [{
      id: 'PE3', category: 'Privilege Escalation', pattern: 'Credential Access',
      severity: 'HIGH', location: { file: 'SKILL.md', start_line: 3 }, finding: '~/.ssh/id_rsa',
    }],
    components: [{ path: 'SKILL.md' }, { path: 'setup.py' }],
    analysis_completeness: { coverage_percent: 100, entirely_uninspected_files: 0 },
    risk_assessment: { score: 11 },
  });
  const parsed = parseScanReport(report);
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.findings[0].rule, 'PE3');
  assert.equal(parsed.findings[0].severity, 'HIGH');
  assert.equal(parsed.findings[0].file, 'SKILL.md');
  assert.deepEqual(parsed.analyzedPaths, ['SKILL.md', 'setup.py']);
  assert.equal(parsed.scannerScore, 11);
});

test('a clean report still reports full coverage, so nothing looks like a gap', () => {
  const parsed = parseScanReport(REPORT_CLEAN);
  assert.equal(parsed.findings.length, 0);
  assert.deepEqual(parsed.analyzedPaths, ['SKILL.md']);
});

test("the scanner's own admission of uninspected files becomes a HIGH finding", () => {
  const report = JSON.stringify({
    issues: [], components: [{ path: 'a.md' }],
    analysis_completeness: { coverage_percent: 50, entirely_uninspected_files: 3 },
  });
  const parsed = parseScanReport(report);
  assert.ok(parsed.findings.some((f) => f.rule === 'scanner-uninspected-files' && f.severity === 'HIGH'));
});

test('parseScanReport throws on malformed input rather than returning empty', () => {
  // An empty result reads as "nothing found", which is the opposite of "could not parse".
  assert.throws(() => parseScanReport('not json'));
});

// --- fail-closed ----------------------------------------------------------------

test('a missing Docker daemon BLOCKS with a critical finding, never skips', () => {
  const result = runStage1(emptyDir(), 'T1', {
    spawn: fakeSpawn({ status: null, error: new Error('daemon not running') }),
  });
  assert.equal(result.verdict, 'BLOCKED');
  assert.equal(result.score, 100);
  assert.ok(result.findings.some((f) => f.rule === 'scanner-unavailable' && f.severity === 'CRITICAL'));
});

test('scanner exit code 2 is treated as BLOCKED, not as a pass', () => {
  const result = runStage1(emptyDir(), 'T1', { spawn: fakeSpawn({ status: 2, stderr: 'internal error' }) });
  assert.equal(result.verdict, 'BLOCKED');
  assert.equal(result.score, 100);
});

test('a dead daemon exiting 1 with empty stdout is scanner-unavailable, not a scan result', () => {
  // Regression: observed live on 2026-08-05 with Docker Desktop stopped. `docker run`
  // exits 1 — the same code SkillSpector uses for DO_NOT_INSTALL — so exit status alone
  // cannot tell "found a lot" from "never ran". Empty stdout is the discriminator.
  const result = runStage1(emptyDir(), 'T1', {
    spawn: fakeSpawn({ status: 1, stdout: '', stderr: 'error during connect: open //./pipe/dockerDesktopLinuxEngine' }),
  });
  assert.equal(result.verdict, 'BLOCKED');
  assert.equal(result.findings[0].rule, 'scanner-unavailable',
    'must not be misreported as unparseable output — that sends debugging at the wrong component');
});

test('a real DO_NOT_INSTALL (exit 1 WITH a valid report) is still parsed as a scan result', () => {
  const report = JSON.stringify({
    issues: [{ id: 'PI1', severity: 'HIGH', pattern: 'Instruction Override', location: { file: 'SKILL.md' } }],
    components: [{ path: 'SKILL.md' }],
    analysis_completeness: { coverage_percent: 100, entirely_uninspected_files: 0 },
  });
  const result = runStage1(emptyDir(), 'T1', { spawn: fakeSpawn({ status: 1, stdout: report }) });
  assert.ok(result.findings.some((f) => f.rule === 'PI1'), 'exit 1 with a valid report is a genuine finding, not an outage');
});

test('unparseable scanner output is BLOCKED', () => {
  const result = runStage1(emptyDir(), 'T1', { spawn: fakeSpawn({ status: 0, stdout: '<<<not a report>>>' }) });
  assert.equal(result.verdict, 'BLOCKED');
  assert.ok(result.findings.some((f) => f.rule === 'scanner-output-unparseable'));
});

test('a clean scan of an empty payload yields NO_FINDINGS', () => {
  const result = runStage1(emptyDir(), 'T1', { spawn: fakeSpawn({ status: 0, stdout: REPORT_CLEAN }) });
  assert.equal(result.verdict, 'NO_FINDINGS');
  assert.equal(result.score, 0);
});

// --- integration with local checks ----------------------------------------------

test('an unpack-gap finding from local checks reaches the verdict', () => {
  const dir = emptyDir();
  fs.writeFileSync(path.join(dir, 'never-analyzed.md'), 'content');
  // SkillSpector reports analyzing nothing, so the file on disk is a gap: HIGH = 25.
  const result = runStage1(dir, 'T3', { spawn: fakeSpawn({ status: 0, stdout: REPORT_CLEAN }) });
  assert.ok(result.findings.some((f) => f.rule === 'unpack-gap'));
  assert.equal(result.verdict, 'BLOCKED', 'T3 threshold is 20; a HIGH gap finding scores 25');
});

test('a malicious pickle in the payload reaches the verdict as CRITICAL', () => {
  const dir = emptyDir();
  fs.writeFileSync(path.join(dir, 'model.pkl'), Buffer.from('cos\nsystem\nR', 'latin1'));
  const result = runStage1(dir, 'T1', { spawn: fakeSpawn({ status: 0, stdout: REPORT_CLEAN }) });
  assert.ok(result.findings.some((f) => f.rule === 'pickle-execution-sink'));
  assert.equal(result.verdict, 'BLOCKED');
});

test('the tier is carried through to the result for the receipt', () => {
  const result = runStage1(emptyDir(), 'T2', { spawn: fakeSpawn({ status: 0, stdout: REPORT_CLEAN }) });
  assert.equal(result.tier, 'T2');
});
