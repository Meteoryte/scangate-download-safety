// SCANGATE Docker auto-launch.
//
// The security-critical property under test: auto-launch removes FALSE blocks and never
// converts a failure into a pass. Every path where the daemon cannot be started must
// still end in a block.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyDockerFailure, isDaemonReady, findDockerDesktop, ensureDockerRunning } from '../scan-docker.mjs';
import { runStage1 } from '../scan-run.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Must be a SMALL directory: runStage1 runs local content checks over the whole tree,
// and pointing it at the workspace root would walk node_modules.
const emptyDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sgd-'));

const ok = { status: 0, stdout: '28.1.2', stderr: '', error: null };
const daemonDown = {
  status: 1, stdout: '', error: null,
  stderr: 'error during connect: Head "http://%2F%2F.%2Fpipe%2FdockerDesktopLinuxEngine/_ping": open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.',
};
const noSleep = () => {};

test('classifies a dead daemon, a missing CLI, and success distinctly', () => {
  assert.equal(classifyDockerFailure(daemonDown), 'daemon-down');
  assert.equal(classifyDockerFailure({ status: 1, stderr: 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock' }), 'daemon-down');
  assert.equal(classifyDockerFailure({ error: { code: 'ENOENT' } }), 'cli-missing');
  assert.equal(classifyDockerFailure(ok), null);
});

test('a scanner finding is not misread as a daemon problem', () => {
  // Exit 1 with real output is DO_NOT_INSTALL, not an outage.
  assert.equal(classifyDockerFailure({ status: 1, stdout: '{"runs":[]}', stderr: '' }), 'other');
});

test('isDaemonReady requires a real version string, not merely exit 0', () => {
  assert.equal(isDaemonReady(() => ok), true);
  assert.equal(isDaemonReady(() => ({ status: 0, stdout: '   ' })), false);
  assert.equal(isDaemonReady(() => daemonDown), false);
});

test('findDockerDesktop returns null when nothing is installed', () => {
  assert.equal(findDockerDesktop(() => false), null);
  assert.match(findDockerDesktop(() => true), /Docker Desktop\.exe$/);
});

test('a already-running daemon short-circuits without launching anything', () => {
  let launches = 0;
  const result = ensureDockerRunning({
    spawn: (cmd) => { if (cmd === 'cmd') launches++; return ok; },
    exists: () => true, sleep: noSleep,
  });
  assert.equal(result.ready, true);
  assert.equal(result.launched, false);
  assert.equal(launches, 0, 'must not launch Docker Desktop when it is already up');
});

test('launches and reports ready once the daemon answers', () => {
  let calls = 0;
  const result = ensureDockerRunning({
    spawn: (cmd) => {
      if (cmd === 'cmd') return { status: 0 };
      calls++;
      return calls <= 1 ? daemonDown : ok;   // down on probe, up after launch
    },
    exists: () => true, sleep: noSleep, timeoutMs: 30_000,
  });
  assert.equal(result.ready, true);
  assert.equal(result.launched, true);
});

test('a launch that never becomes ready reports NOT ready', () => {
  const result = ensureDockerRunning({
    spawn: (cmd) => (cmd === 'cmd' ? { status: 0 } : daemonDown),
    exists: () => true, sleep: noSleep, timeoutMs: 9_000,
  });
  assert.equal(result.ready, false);
  assert.match(result.reason, /did not become ready/i);
});

test('SCANGATE_NO_AUTOLAUNCH=1 disables launching entirely', () => {
  let launches = 0;
  const result = ensureDockerRunning({
    spawn: (cmd) => { if (cmd === 'cmd') launches++; return daemonDown; },
    exists: () => true, sleep: noSleep, env: { SCANGATE_NO_AUTOLAUNCH: '1' },
  });
  assert.equal(result.ready, false);
  assert.equal(launches, 0);
  assert.match(result.reason, /disabled/i);
});

test('a missing Docker Desktop install is reported, not silently retried forever', () => {
  const result = ensureDockerRunning({ spawn: () => daemonDown, exists: () => false, sleep: noSleep });
  assert.equal(result.ready, false);
  assert.match(result.reason, /not found/i);
});

// --- integration: fail-closed is preserved ---------------------------------------

test('runStage1 retries after a successful auto-launch', () => {
  const sarif = JSON.stringify({ runs: [{ artifacts: [], results: [] }] });
  let attempt = 0;
  const result = runStage1(emptyDir(), 'T1', {
    spawn: () => { attempt++; return attempt === 1 ? daemonDown : { status: 0, stdout: sarif, stderr: '' }; },
    ensureDocker: () => ({ ready: true, launched: true, waitedMs: 5000, reason: 'started' }),
  });
  assert.equal(attempt, 2, 'should invoke the scanner again after the daemon comes up');
  assert.notEqual(result.verdict, 'BLOCKED');
});

test('runStage1 STILL BLOCKS when auto-launch fails', () => {
  // The whole point: convenience must never become an escape hatch.
  const result = runStage1(emptyDir(), 'T1', {
    spawn: () => daemonDown,
    ensureDocker: () => ({ ready: false, launched: true, waitedMs: 180000, reason: 'Docker Desktop did not become ready within 180s' }),
  });
  assert.equal(result.verdict, 'BLOCKED');
  assert.equal(result.score, 100);
  assert.equal(result.findings[0].rule, 'scanner-unavailable');
  assert.match(result.findings[0].detail, /auto-launch/i, 'the block reason should say the launch was attempted and failed');
});

test('runStage1 does not attempt a launch for non-daemon failures', () => {
  let launched = false;
  runStage1(emptyDir(), 'T1', {
    spawn: () => ({ status: 2, stdout: '', stderr: 'internal scanner error' }),
    ensureDocker: () => { launched = true; return { ready: false }; },
  });
  assert.equal(launched, false, 'a scanner crash is not a daemon problem');
});
