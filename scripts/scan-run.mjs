// ---------------------------------------------------------------------------
// scan-run.mjs — SCANGATE stage 1 (deterministic scan).
//
// Runs NVIDIA SkillSpector in a pinned container with `--network none` and `--no-llm`,
// then layers on the workspace-local checks SkillSpector does not perform: unpack-gap
// detection, entropy, Unicode deception, and model-weight opcode scanning.
//
// No model is involved at this stage. That is the point — a JSON report and a risk score
// are things a hook can act on without any agent reading a byte of the artifact.
// ---------------------------------------------------------------------------

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { WORKSPACE_ROOT, thresholdForTier } from './scan-core.mjs';
import { runPreChecks } from './scan-checks.mjs';
import { scanWeightFile } from './scan-weights.mjs';
import { ensureDockerRunning, classifyDockerFailure } from './scan-docker.mjs';

const WEIGHTS_RE = /\.(safetensors|gguf|pt|pth|ckpt|bin|pkl)$/i;
const SCANNER_IMAGE = 'skillspector:pinned';

// Per spec section 3: points accumulate per finding.
const POINTS = { CRITICAL: 50, HIGH: 25, MEDIUM: 10, LOW: 5 };

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

/**
 * Parse SkillSpector's JSON report.
 *
 * The JSON format is used rather than SARIF for one specific reason: SARIF only emits an
 * `artifacts` array when there are findings, so a CLEAN scan reports zero analyzed paths —
 * which made the unpack-gap check flag every file in every clean artifact. The JSON report
 * carries `components[]` (what was actually inspected) and an `analysis_completeness`
 * block, so coverage comes from the scanner's own accounting instead of being inferred.
 *
 * @param {string} jsonText
 * @returns {{ findings: Array, analyzedPaths: string[], completeness: object, scannerScore: number|null }}
 * @throws when the text is not parseable — an empty result would read as "nothing found",
 *         which is the opposite of "could not parse".
 */
export function parseScanReport(jsonText) {
  const report = JSON.parse(jsonText);
  if (!report || typeof report !== 'object') throw new Error('scan report is not an object');

  const findings = (report.issues || []).map((issue) => ({
    rule: issue.id || 'unknown',
    severity: SEVERITIES.includes(issue.severity) ? issue.severity : 'MEDIUM',
    file: issue.location?.file || '-',
    detail: [issue.pattern, issue.finding].filter(Boolean).join(' — ').slice(0, 300),
  }));

  const analyzedPaths = (report.components || [])
    .map((component) => component?.path)
    .filter((p) => typeof p === 'string');

  const completeness = report.analysis_completeness || {};

  // The scanner's own admission that it could not inspect something is at least as
  // important as anything it did find.
  const uninspected = Number(completeness.entirely_uninspected_files || 0);
  if (uninspected > 0) {
    findings.push({
      rule: 'scanner-uninspected-files', severity: 'HIGH', file: '-',
      detail: `scanner reports ${uninspected} entirely uninspected file(s); coverage ${completeness.coverage_percent}%`,
    });
  }

  return {
    findings,
    analyzedPaths,
    completeness,
    scannerScore: report.risk_assessment?.score ?? null,
  };
}

export function scoreFromFindings(findings) {
  return (findings || []).reduce((total, finding) => total + (POINTS[finding.severity] || 0), 0);
}

/**
 * Verdict vocabulary is exactly BLOCKED / NO_FINDINGS / FINDINGS_ACCEPTED.
 *
 * `SAFE` is deliberately absent. Obfuscation defeats static scanning roughly 80% of the
 * time and packing over 90%, so a clean scan means "no known-bad found", never "safe".
 */
export function decide(score, tier) {
  if (score > thresholdForTier(tier)) return 'BLOCKED';
  return score === 0 ? 'NO_FINDINGS' : 'FINDINGS_ACCEPTED';
}

function blockedResult(tier, rule, detail) {
  return {
    verdict: 'BLOCKED',
    score: 100,
    tier,
    findings: [{ rule, severity: 'CRITICAL', file: '-', detail: String(detail).slice(0, 500) }],
    analyzedPaths: [],
  };
}

function collectWeightFindings(dir) {
  const findings = [];
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) { walk(full); continue; }
      if (entry.isFile() && WEIGHTS_RE.test(entry.name)) findings.push(...scanWeightFile(full));
    }
  };
  walk(dir);
  return findings;
}

/**
 * @param {string} payloadDir
 * @param {string} tier
 * @param {{ spawn?: Function, memory?: string }} options injectable spawn, for deterministic tests
 */
export function runStage1(payloadDir, tier, options = {}) {
  const spawn = options.spawn || spawnSync;
  const ensureDocker = options.ensureDocker || ensureDockerRunning;
  const mount = `${path.resolve(payloadDir)}:/scan:ro`;

  // The intake gate keeps 1g: a single artifact that needs more than that is itself
  // suspicious. Bulk retro-scans of existing inventory pass a larger ceiling because they
  // legitimately cover hundreds of megabytes at once — observed as exit 137 (OOM-kill) on
  // SORT, which fail-closed correctly reported as `scanner-unavailable` rather than a pass.
  //
  // Memory is not the isolation boundary. `--network none`, `--read-only`, `--cap-drop ALL`,
  // `--no-new-privileges` and `--pids-limit` are, and none of them move.
  const memory = options.memory || '1g';

  const invoke = () => spawn('docker', [
    'run', '--rm',
    '--network', 'none',
    '--read-only',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--memory', memory,
    '--pids-limit', '256',
    '-v', mount,
    SCANNER_IMAGE,
    'scan', '/scan', '--no-llm', '--format', 'json',
    // Node's default stdout cap is 1 MB, which a whole-repository SARIF report exceeds —
    // observed as ENOBUFS while scanning SkillSpector's own source for the N-1-scans-N
    // ratchet. It fail-closed to `scanner-unavailable`, which is right but is a FALSE
    // block: the scanner ran fine and the harness threw its answer away.
  ], { encoding: 'utf8', cwd: WORKSPACE_ROOT, windowsHide: true, timeout: 600_000, maxBuffer: 128 * 1024 * 1024 });

  let result = invoke();
  let autolaunch = null;

  // Docker Desktop is frequently closed, and the weekly sweep fires at 03:00. Rather than
  // blocking a legitimate scan over a stopped daemon, start it and retry ONCE.
  //
  // This does not weaken fail-closed: if the daemon cannot be started, `result` stays a
  // failure and the guards below still block. Auto-launch removes FALSE blocks only.
  if (classifyDockerFailure(result) === 'daemon-down') {
    autolaunch = ensureDocker();
    if (autolaunch.ready) result = invoke();
  }

  // FAIL CLOSED. A scanner that cannot run is not a scan that passed.
  //
  // Exit-code handling is subtle and was corrected after observing the real failure:
  //   0 = score <= 50, 1 = score > 50 (DO_NOT_INSTALL), 2 = scanner error.
  // But a DEAD DOCKER DAEMON also exits 1, with the error on stderr and NOTHING on
  // stdout. Exit code alone therefore cannot distinguish "scanner found a lot" from
  // "scanner never ran" — empty stdout is what separates them. Without this check the
  // run still blocked, but reported "unparseable output" and sent anyone debugging it
  // chasing the scanner instead of the daemon.
  const launchNote = autolaunch && !autolaunch.ready ? ` [auto-launch: ${autolaunch.reason}]` : '';
  if (result.error || result.status === null || result.status === 2) {
    return blockedResult(tier, 'scanner-unavailable',
      `${result.error?.message || result.stderr || `scanner exited ${result.status}`}${launchNote}`);
  }
  if (!String(result.stdout || '').trim()) {
    return blockedResult(tier, 'scanner-unavailable',
      `scanner produced no output (exit ${result.status}): ${String(result.stderr || '').slice(0, 300)}${launchNote}`);
  }

  let report;
  try {
    report = parseScanReport(result.stdout);
  } catch (error) {
    return blockedResult(tier, 'scanner-output-unparseable', error.message);
  }

  let local = [];
  let weights = [];
  try {
    local = runPreChecks(payloadDir, report.analyzedPaths);
    weights = collectWeightFindings(payloadDir);
  } catch (error) {
    return blockedResult(tier, 'local-checks-failed', error.message);
  }

  const findings = [...report.findings, ...local, ...weights];
  const score = scoreFromFindings(findings);

  return {
    verdict: decide(score, tier),
    score,
    tier,
    findings,
    analyzedPaths: report.analyzedPaths,
    // Recorded for the receipt as independent evidence. SkillSpector's own score is
    // deliberately NOT the verdict — observed 2026-08-05, it rated a skill that
    // exfiltrates ~/.ssh/id_rsa and pipes curl to bash as 11/100 "SAFE". SCANGATE scores
    // findings itself and applies a tier-dependent threshold.
    scannerScore: report.scannerScore,
    coverage: report.completeness,
  };
}

if (process.argv[1] && process.argv[1].endsWith('scan-run.mjs')) {
  const target = process.argv[2];
  const tier = process.argv[3] || 'T3';
  if (!target) {
    console.error('usage: pnpm run scan:run -- <quarantine-payload-dir> [tier]');
    process.exit(2);
  }
  const outcome = runStage1(target, tier);
  console.log(JSON.stringify(outcome, null, 2));
  process.exit(outcome.verdict === 'BLOCKED' ? 1 : 0);
}
