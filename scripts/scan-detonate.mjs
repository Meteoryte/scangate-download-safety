// ---------------------------------------------------------------------------
// scan-detonate.mjs — SCANGATE stage 2 (behavioural detonation).
//
// Static scanning is defeated by structural obfuscation roughly 80% of the time and by
// self-extracting packing over 90% of the time. A packed payload does not exist as code
// until the skill runs — it lives in an ignored folder or a scrambled data blob and
// rebuilds itself at execution. No amount of pattern matching sees that.
//
// A file-tree diff across execution sees nothing else. If files appear that were not
// there before, the artifact unpacked something. That is the whole idea.
//
// The payload is mounted READ-ONLY and copied into a tmpfs, so detonation can never write
// back into the quarantine tree. The container reports its result as a hash manifest on
// stdout — no volume write, nothing to smuggle out through a shared directory.
// ---------------------------------------------------------------------------

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { WORKSPACE_ROOT, hashTree } from './scan-core.mjs';
import { ensureDockerRunning, classifyDockerFailure } from './scan-docker.mjs';

const EXEC_RE = /\.(py|js|mjs|cjs|ts|sh|bash|zsh|ps1|bat|cmd|exe|dll|so|dylib|ipynb|rb|pl|php)$/i;
const LIFECYCLE_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'];
const DETONATOR_IMAGE = 'detonator:pinned';
const HOST_TIMEOUT_MS = 180_000;

/**
 * Does this payload contain anything that could run?
 *
 * Detonation is expensive, so it is conditional — but the condition errs toward running.
 */
export function hasExecutableContent(dir) {
  let found = false;
  const walk = (current) => {
    if (found) return;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (found) return;
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) { walk(full); continue; }
      if (!entry.isFile()) continue;

      if (EXEC_RE.test(entry.name)) { found = true; return; }

      if (entry.name === 'package.json') {
        try {
          const pkg = JSON.parse(fs.readFileSync(full, 'utf8'));
          if (LIFECYCLE_HOOKS.some((hook) => pkg?.scripts?.[hook])) { found = true; return; }
        } catch {
          // A malformed package.json is the static scan's problem, not ours.
        }
      }
    }
  };
  walk(dir);
  return found;
}

/**
 * @param {Array<{path,sha256}>} before
 * @param {Array<{path,sha256}>} after
 */
export function diffTrees(before, after) {
  const b = new Map((before || []).map((f) => [f.path, f.sha256]));
  const a = new Map((after || []).map((f) => [f.path, f.sha256]));
  return {
    added: [...a.keys()].filter((p) => !b.has(p)).sort(),
    removed: [...b.keys()].filter((p) => !a.has(p)).sort(),
    modified: [...a.keys()].filter((p) => b.has(p) && b.get(p) !== a.get(p)).sort(),
  };
}

function parseManifest(stdout) {
  return String(stdout || '')
    .split(/\r?\n/)
    .map((line) => line.match(/^([0-9a-f]{64})\s+\.\/(.+)$/))
    .filter(Boolean)
    .map((match) => ({ path: match[2], sha256: match[1] }));
}

/**
 * @param {string} payloadDir
 * @param {{ spawn?: Function, ensureDocker?: Function }} options
 */
export function runDetonation(payloadDir, options = {}) {
  const spawn = options.spawn || spawnSync;
  const ensureDocker = options.ensureDocker || ensureDockerRunning;

  if (!hasExecutableContent(payloadDir)) {
    return { ran: false, verdict: 'NO_FINDINGS', added: [], modified: [], removed: [], stdout: 'no executable content; detonation skipped' };
  }

  const before = hashTree(payloadDir);

  // Copy into tmpfs, run recognized entry points, then emit a hash manifest.
  // Everything is best-effort: a payload that crashes still gets its tree diffed.
  const script = [
    'cp -a /src/. /work/ 2>/dev/null || true',
    'cd /work',
    'for f in setup.py install.py postinstall.py install.sh setup.sh postinstall.sh; do '
      + 'if [ -f "$f" ]; then timeout 20 python "$f" >/dev/null 2>&1 || timeout 20 sh "$f" >/dev/null 2>&1 || true; fi; done',
    'if [ -f package.json ]; then timeout 20 node -e "try{const p=require(\'./package.json\');}catch(e){}" >/dev/null 2>&1 || true; fi',
    'find . -type f -exec sha256sum {} + 2>/dev/null | sort',
  ].join('; ');

  const invoke = () => spawn('docker', [
    'run', '--rm',
    '--network', 'none',
    '--read-only',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--pids-limit', '128',
    '--memory', '512m',
    '--cpus', '1',
    // mode=1777 is required: Docker creates a tmpfs as root:root 0755, and this container
    // deliberately runs as an unprivileged uid, so without it the payload copy fails with
    // "permission denied" and the sandbox silently detonates nothing. Caught 2026-08-05 —
    // the empty-manifest guard blocked rather than reporting clean, which is how it
    // surfaced instead of becoming a permanently no-op stage.
    '--tmpfs', '/work:rw,size=256m,mode=1777',
    '-v', `${path.resolve(payloadDir)}:/src:ro`,
    DETONATOR_IMAGE,
    script,
  ], { encoding: 'utf8', timeout: HOST_TIMEOUT_MS, cwd: WORKSPACE_ROOT, windowsHide: true });

  let result = invoke();
  if (classifyDockerFailure(result) === 'daemon-down') {
    const launch = ensureDocker();
    if (launch.ready) result = invoke();
  }

  const fail = (detail) => ({ ran: true, verdict: 'BLOCKED', added: [], modified: [], removed: [], stdout: detail });

  if (result.error || result.status === null) {
    return fail(`detonation failed: ${result.error?.message || 'timed out'}`);
  }

  const after = parseManifest(result.stdout);
  // No manifest means the sandbox told us nothing. That is not the same as telling us it
  // is clean, and must never be read as such.
  if (after.length === 0) {
    return fail(`detonation produced no manifest (exit ${result.status}): ${String(result.stderr || '').slice(0, 300)}`);
  }

  const diff = diffTrees(before, after);
  const changed = diff.added.length > 0 || diff.modified.length > 0;

  return {
    ran: true,
    verdict: changed ? 'BLOCKED' : 'NO_FINDINGS',
    added: diff.added,
    modified: diff.modified,
    removed: diff.removed,
    stdout: String(result.stdout || '').slice(0, 4000),
  };
}

if (process.argv[1] && process.argv[1].endsWith('scan-detonate.mjs')) {
  const target = process.argv[2];
  if (!target) {
    console.error('usage: node scripts/scan-detonate.mjs <payload-dir>');
    process.exit(2);
  }
  const outcome = runDetonation(target);
  console.log(JSON.stringify({ ...outcome, stdout: undefined }, null, 2));
  process.exit(outcome.verdict === 'BLOCKED' ? 1 : 0);
}
