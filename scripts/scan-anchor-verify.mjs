#!/usr/bin/env node
// scripts/scan-anchor-verify.mjs — SCANGATE section 5.1.
// The scanner is the most privileged component here. It does not get permanent trust.

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { WORKSPACE_ROOT } from './scan-core.mjs';
import { intake } from './scan-intake.mjs';
import { runStage1 } from './scan-run.mjs';

const PIN_PATH = path.join(WORKSPACE_ROOT, 'docker/skillspector.pin.json');

export function upstreamHead(repo) {
  const remote = spawnSync('git', ['ls-remote', repo, 'HEAD'], { encoding: 'utf8', windowsHide: true, timeout: 30_000 });
  return String(remote.stdout).split(/\s+/)[0] || null;
}

export function verifyAnchor() {
  const reasons = [];
  if (!fs.existsSync(PIN_PATH)) return { ok: false, reasons: ['pin file missing'] };
  const pin = JSON.parse(fs.readFileSync(PIN_PATH, 'utf8'));

  if (!/^[0-9a-f]{40}$/.test(pin.ref || '')) reasons.push(`pin is not a 40-char commit SHA: ${pin.ref}`);

  const images = spawnSync('docker', ['images', '--format', '{{.Repository}}:{{.Tag}}'], { encoding: 'utf8', windowsHide: true });
  if (!String(images.stdout).includes(`skillspector:${pin.ref}`)) {
    reasons.push(`running image does not match pinned SHA ${pin.ref}`);
  }

  // A moved tag or force-push upstream is a red flag in its own right.
  const head = upstreamHead(pin.repo);
  if (head && head !== pin.ref) {
    reasons.push(`upstream HEAD ${head.slice(0, 12)} differs from pin ${pin.ref.slice(0, 12)} — review the diff before bumping (N-1 scans N)`);
  }

  return { ok: reasons.length === 0, reasons };
}

/**
 * The N-1-scans-N ratchet, spec §5.1: the scanner currently pinned (N-1) must scan the
 * version proposed to replace it (N) before any bump.
 *
 * Until this existed the ratchet was a sentence in a protocol with nothing implementing it
 * — precisely the kind of rule that holds only while an agent chooses to follow it. It now
 * runs the proposed source through the ordinary gate: quarantined by `intake`, then scanned
 * by `runStage1`, which uses `skillspector:pinned` — the CURRENT image — by construction.
 *
 * It deliberately does NOT bump the pin. A scanner upgrade is an ALLOW decision, and ALLOW
 * decisions are human. This produces the evidence that decision needs.
 *
 * @returns {{ sha: string, id: string, dir: string, verdict: string, score: number, findings: Array }}
 */
export function proposeBump(sha, options = {}) {
  const pin = JSON.parse(fs.readFileSync(PIN_PATH, 'utf8'));
  const doIntake = options.intake || intake;
  const doScan = options.runStage1 || runStage1;

  const target = sha || upstreamHead(pin.repo);
  if (!/^[0-9a-f]{40}$/.test(target || '')) {
    throw new Error(`cannot resolve a 40-char commit SHA to propose (got: ${target})`);
  }
  if (target === pin.ref) {
    return { sha: target, id: null, dir: null, verdict: 'NO_FINDINGS', score: 0, findings: [], note: 'already pinned to this SHA' };
  }

  // Intake clones at --depth 1, which lands upstream HEAD — the same commit resolved as
  // `target` above. Fetching a per-commit archive URL instead would bypass the clone path
  // and land nothing, since intake only accepts git remotes, local zips, and local dirs.
  const landed = doIntake({ source: pin.repo, kind: 'git', sourceUrl: pin.repo });

  // Scanned by the CURRENT pinned image. Tier comes from the registry, so a
  // typosquatted or moved repo does not inherit NVIDIA's T1 standing.
  const result = doScan(landed.dir, landed.tier);

  return {
    sha: target,
    id: landed.id,
    dir: landed.dir,
    tier: landed.tier,
    verdict: result.verdict,
    score: result.score,
    findings: result.findings || [],
  };
}

if (process.argv[1] && process.argv[1].endsWith('scan-anchor-verify.mjs')) {
  const args = process.argv.slice(2);
  const proposeIndex = args.indexOf('--propose');

  if (proposeIndex >= 0) {
    const requested = args[proposeIndex + 1] && !args[proposeIndex + 1].startsWith('--')
      ? args[proposeIndex + 1]
      : null;
    try {
      const outcome = proposeBump(requested);
      console.log('N-1 scans N — the currently pinned scanner scanning its proposed replacement');
      console.log('='.repeat(70));
      console.log(`proposed SHA: ${outcome.sha}`);
      if (outcome.note) {
        console.log(outcome.note);
        process.exit(0);
      }
      console.log(`quarantine:   ${outcome.id}`);
      console.log(`tier:         ${outcome.tier}`);
      console.log(`verdict:      ${outcome.verdict} (score ${outcome.score})`);
      for (const f of outcome.findings.slice(0, 20)) {
        console.log(`  [${f.severity}] ${f.rule || f.category}: ${f.file || '-'} — ${String(f.detail || f.evidence || '').slice(0, 120)}`);
      }
      console.log('');
      console.log('The pin has NOT been changed. A scanner upgrade is an ALLOW decision, and');
      console.log('ALLOW decisions are human. To accept:');
      console.log(`  pnpm run scan:dispose -- ${outcome.id} --decision ALLOW --by <you>`);
      console.log('  then rebuild the image at the new SHA and update docker/skillspector.pin.json');
      process.exit(outcome.verdict === 'BLOCKED' ? 1 : 0);
    } catch (error) {
      console.error(`propose refused: ${error.message}`);
      process.exit(1);
    }
  }

  const result = verifyAnchor();
  console.log(result.ok ? 'anchor OK' : 'anchor needs review:');
  for (const reason of result.reasons) console.log(`  - ${reason}`);
  if (!result.ok) {
    console.log('');
    console.log('To run the ratchet: pnpm run scan:anchor -- --propose [sha]');
  }
  process.exit(result.ok ? 0 : 1);
}
