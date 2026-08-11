// ---------------------------------------------------------------------------
// scan-docker.mjs — SCANGATE Docker lifecycle helper.
//
// Docker Desktop is not always running, and the weekly sweep fires at 03:00 when it
// usually is not. Rather than blocking a legitimate scan because a daemon was closed,
// SCANGATE starts it on demand.
//
// THIS MUST NEVER WEAKEN FAIL-CLOSED. Auto-launch removes FALSE blocks; it never turns a
// failure into a pass. If the daemon cannot be started within the timeout, the caller
// still blocks. The only thing that changes is whether a human has to go click an icon.
//
// The launch is LAZY: nothing probes Docker on the happy path. A scan runs, and only if
// it fails with a daemon-connectivity error do we try to start Docker and retry once.
// That keeps the common case free of a per-scan probe cost.
// ---------------------------------------------------------------------------

import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

const DESKTOP_PATHS = [
  'C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe',
  'C:\\Program Files (x86)\\Docker\\Docker\\Docker Desktop.exe',
];

export const DEFAULT_LAUNCH_TIMEOUT_MS = 180_000;
const POLL_INTERVAL_MS = 3_000;

/** Synchronous sleep — the surrounding scan pipeline is spawnSync-based throughout. */
function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Classify a failed docker invocation.
 *
 * @returns {'daemon-down'|'cli-missing'|'other'|null} null when the call succeeded
 */
export function classifyDockerFailure(result) {
  if (!result) return 'other';
  if (result.error?.code === 'ENOENT') return 'cli-missing';

  const text = `${result.error?.message || ''} ${result.stderr || ''}`.toLowerCase();
  if (!text.trim() && (result.status === 0)) return null;

  if (/pipe\/docker|dockerdesktoplinuxengine|cannot connect to the docker daemon|is the docker daemon running|error during connect|docker_engine/.test(text)) {
    return 'daemon-down';
  }
  if (/executable file not found|command not found|not recognized/.test(text)) return 'cli-missing';
  if (result.status === 0) return null;
  return 'other';
}

/** @returns {boolean} true when the daemon answers. */
export function isDaemonReady(spawn = spawnSync) {
  const result = spawn('docker', ['version', '--format', '{{.Server.Version}}'],
    { encoding: 'utf8', windowsHide: true, timeout: 20_000 });
  return !result.error && result.status === 0 && Boolean(String(result.stdout || '').trim());
}

export function findDockerDesktop(exists = fs.existsSync) {
  return DESKTOP_PATHS.find((candidate) => exists(candidate)) || null;
}

/**
 * Ensure the Docker daemon is running, launching Docker Desktop if needed.
 *
 * Bounded and idempotent. Opt out entirely with SCANGATE_NO_AUTOLAUNCH=1 — useful in CI,
 * where silently starting a desktop app would be the wrong behaviour.
 *
 * @returns {{ ready: boolean, launched: boolean, waitedMs: number, reason: string }}
 */
export function ensureDockerRunning(options = {}) {
  const {
    spawn = spawnSync,
    exists = fs.existsSync,
    sleep = sleepSync,
    timeoutMs = DEFAULT_LAUNCH_TIMEOUT_MS,
    env = process.env,
  } = options;

  if (isDaemonReady(spawn)) {
    return { ready: true, launched: false, waitedMs: 0, reason: 'daemon already running' };
  }

  if (env.SCANGATE_NO_AUTOLAUNCH === '1') {
    return { ready: false, launched: false, waitedMs: 0, reason: 'auto-launch disabled by SCANGATE_NO_AUTOLAUNCH=1' };
  }

  const desktop = findDockerDesktop(exists);
  if (!desktop) {
    return { ready: false, launched: false, waitedMs: 0, reason: 'Docker Desktop executable not found in any known location' };
  }

  const launch = spawn('cmd', ['/c', 'start', '', desktop], { windowsHide: true, timeout: 30_000 });
  if (launch.error) {
    return { ready: false, launched: false, waitedMs: 0, reason: `failed to launch Docker Desktop: ${launch.error.message}` };
  }

  let waited = 0;
  while (waited < timeoutMs) {
    sleep(POLL_INTERVAL_MS);
    waited += POLL_INTERVAL_MS;
    if (isDaemonReady(spawn)) {
      return { ready: true, launched: true, waitedMs: waited, reason: `daemon became ready after ${Math.round(waited / 1000)}s` };
    }
  }

  // Timed out. The caller BLOCKS — this helper never reports readiness it cannot prove.
  return { ready: false, launched: true, waitedMs: waited, reason: `Docker Desktop did not become ready within ${Math.round(timeoutMs / 1000)}s` };
}

if (process.argv[1] && process.argv[1].endsWith('scan-docker.mjs')) {
  const outcome = ensureDockerRunning();
  console.log(JSON.stringify(outcome, null, 2));
  process.exit(outcome.ready ? 0 : 1);
}
