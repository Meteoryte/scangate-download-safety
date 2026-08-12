#!/usr/bin/env node
// Optional Microsoft Defender corroboration. The artifact content is never printed and
// remediation is disabled; only engine outcome and source-tree identity are recorded.

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { treeDigest } from './scan-core.mjs';

function main() {
  const args = process.argv.slice(2);
  const targetArg = args[0];
  const outputIndex = args.indexOf('--output');
  const output = outputIndex >= 0 ? path.resolve(args[outputIndex + 1] || '') : null;
  if (!targetArg || targetArg.startsWith('--')) {
    throw new Error('usage: node scripts/scan-defender.mjs <quarantine-source-directory> [--output report.json]');
  }
  const target = path.resolve(targetArg);
  if (!fs.existsSync(target) || !fs.statSync(target).isDirectory()) throw new Error('target must be a source directory');
  const defender = path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Windows Defender', 'MpCmdRun.exe');
  if (!fs.existsSync(defender)) throw new Error('Microsoft Defender MpCmdRun.exe is unavailable');

  const started = Date.now();
  const scan = spawnSync(defender, ['-Scan', '-ScanType', '3', '-File', target, '-DisableRemediation'], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 900_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  const engineOutput = String(scan.stdout || '') + '\n' + String(scan.stderr || '');
  const noThreats = /found no threats/i.test(engineOutput);
  const timedOut = scan.error?.code === 'ETIMEDOUT';
  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    engine: 'Microsoft Defender MpCmdRun custom scan',
    remediationDisabled: true,
    modelBlind: true,
    contentPrinted: false,
    target,
    sourceTreeDigest: treeDigest(target),
    verdict: scan.status === 0 && noThreats && !timedOut ? 'NO_FINDINGS' : 'BLOCKED',
    exitCode: Number.isInteger(scan.status) ? scan.status : null,
    noThreatsMarker: noThreats,
    timedOut,
    durationMs: Date.now() - started,
  };
  const serialized = JSON.stringify(report, null, 2);
  if (output) {
    fs.writeFileSync(output, serialized + '\n', 'utf8');
    console.log('report=' + output);
  } else {
    console.log(serialized);
  }
  if (report.verdict !== 'NO_FINDINGS') process.exit(1);
}

try { main(); }
catch (error) {
  console.error('Defender scan failed closed: ' + error.message);
  process.exit(1);
}
