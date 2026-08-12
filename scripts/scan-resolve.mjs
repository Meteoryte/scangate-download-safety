#!/usr/bin/env node
// Additively resolve an immutable DEFERRED receipt after format-complete review.

import fs from 'node:fs';
import path from 'node:path';
import {
  QUARANTINE_ROOT,
  isSafeMemberName,
  readReceipt,
  realpathIsInside,
  receiptPathFor,
  sha256File,
  treeDigest,
  verifyReceipt,
  writeReceipt,
} from './scan-core.mjs';

const COMMITMENT_STATES = new Set(['ADOPTED', 'MIRROR', 'VERIFIED-NO-FOLD']);
const GOVERNANCE_STATES = new Set(['ADOPTED', 'MIRROR', 'VERIFIED-NO-FOLD', 'REJECTED']);

function fail(message) { throw new Error(message); }

function candidateIdentity(candidate) {
  return `${candidate.path}\0${candidate.sha256}`;
}

export function validateResolutionEvidence({ original, payloadDir, sourceDir, formatReport, defenderReport = null, governanceDecision = null }) {
  if (formatReport.modelBlind !== true || formatReport.contentPrinted !== false) fail('format report is not model-blind metadata');
  if (formatReport.targetTreeDigest !== treeDigest(payloadDir)) fail('format report does not bind the current payload tree');
  if ((formatReport.formatReview?.blockers || []).length) fail('format blockers remain');
  if (!['NO_FINDINGS', 'REVIEW'].includes(formatReport.formatReview?.verdict)) fail('format verdict is not resolvable');
  if (defenderReport) {
    if (defenderReport.modelBlind !== true || defenderReport.contentPrinted !== false
        || defenderReport.remediationDisabled !== true) fail('Defender report is not model-blind/non-remediating evidence');
    if (defenderReport.sourceTreeDigest !== treeDigest(sourceDir)
        || defenderReport.sourceTreeDigest !== original.source_sha256) fail('Defender report does not bind the original source tree');
    if (defenderReport.verdict !== 'NO_FINDINGS' || defenderReport.exitCode !== 0
        || defenderReport.noThreatsMarker !== true || defenderReport.timedOut !== false) fail('Defender did not return NO_FINDINGS');
  }

  const candidates = formatReport.formatReview.governanceCandidates || [];
  if (candidates.length) {
    if (!governanceDecision || !GOVERNANCE_STATES.has(governanceDecision.disposition)) {
      fail('embedded governance requires a closed reconciliation decision');
    }
    const expected = candidates.map(candidateIdentity).sort();
    const decided = (governanceDecision.candidates || []).map(candidateIdentity).sort();
    if (JSON.stringify(expected) !== JSON.stringify(decided)) fail('governance decision does not cover the exact candidate set');
  }
  return {
    warningRules: [...new Set((formatReport.formatReview.warnings || []).map((item) => item.rule))].sort(),
    governanceCandidateCount: candidates.length,
    governanceDisposition: candidates.length ? governanceDecision.disposition : 'NOT_APPLICABLE',
  };
}

function flag(args, name) {
  const index = args.indexOf(`--${name}`);
  return index >= 0 ? args[index + 1] : null;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(path.resolve(file), 'utf8'));
}

function main() {
  const args = process.argv.slice(2);
  const id = args[0];
  const by = flag(args, 'by');
  const landingDir = path.resolve(flag(args, 'landing-dir') || '');
  const formatPath = flag(args, 'format-report');
  const defenderPath = flag(args, 'defender-report');
  const commitmentState = (flag(args, 'commitment-state') || 'MIRROR').toUpperCase();
  if (!id || id.startsWith('--') || !by || !flag(args, 'landing-dir') || !formatPath) {
    fail('usage: node scripts/scan-resolve.mjs <id> --by <identity> --landing-dir <dir> --format-report <json> [--defender-report <json>] [--governance-decision <json>] [--commitment-state MIRROR|ADOPTED|VERIFIED-NO-FOLD]');
  }
  if (path.basename(id) !== id || !isSafeMemberName(id).safe) fail('invalid quarantine ID');
  if (!COMMITMENT_STATES.has(commitmentState)) fail('invalid commitment state');
  const relativeToQuarantine = path.relative(QUARANTINE_ROOT, landingDir);
  if (relativeToQuarantine === '' || (!relativeToQuarantine.startsWith('..') && !path.isAbsolute(relativeToQuarantine))) {
    fail('landing directory must be outside quarantine');
  }

  const original = readReceipt(id);
  if (!original || !verifyReceipt(original).valid || original.stage4?.decision !== 'DEFERRED') {
    fail('original receipt must be a valid signed DEFERRED decision');
  }
  const entryDir = path.join(QUARANTINE_ROOT, id);
  const payloadDir = path.join(entryDir, 'payload');
  const sourceDir = path.join(entryDir, '_source');
  if (treeDigest(sourceDir) !== original.source_sha256) fail('source provenance drifted after deferral');
  const sourceEntries = fs.readdirSync(sourceDir, { withFileTypes: true });
  if (sourceEntries.length !== 1 || !sourceEntries[0].isFile()) fail('resolver currently requires exactly one regular source file');
  const sourceName = sourceEntries[0].name;
  const safe = isSafeMemberName(sourceName);
  if (!safe.safe || path.basename(sourceName) !== sourceName) fail(`unsafe source filename: ${safe.reason || sourceName}`);

  const formatReport = readJson(formatPath);
  const defenderReport = defenderPath ? readJson(defenderPath) : null;
  const governancePath = flag(args, 'governance-decision');
  const governanceDecision = governancePath ? readJson(governancePath) : null;
  const evidence = validateResolutionEvidence({ original, payloadDir, sourceDir, formatReport, defenderReport, governanceDecision });

  fs.mkdirSync(landingDir, { recursive: true });
  if (realpathIsInside(QUARANTINE_ROOT, landingDir)) fail('landing directory resolves inside quarantine');
  const target = path.join(landingDir, sourceName);
  let created = false;
  if (fs.existsSync(target)) {
    if (!fs.statSync(target).isFile() || sha256File(target) !== sha256File(path.join(sourceDir, sourceName))) {
      fail('additive landing collision differs; choose another landing directory');
    }
  } else {
    const temp = path.join(landingDir, '.' + sourceName + '.' + process.pid + '.part');
    fs.copyFileSync(path.join(sourceDir, sourceName), temp, fs.constants.COPYFILE_EXCL);
    try {
      if (sha256File(temp) !== sha256File(path.join(sourceDir, sourceName))) fail('copy verification failed');
      fs.renameSync(temp, target);
      created = true;
    } finally {
      fs.rmSync(temp, { force: true });
    }
  }

  const suffix = new Date().toISOString().replace(/[^0-9A-Za-z]+/g, '-').replace(/-+$/, '');
  const resolutionId = flag(args, 'resolution-id') || `${id}--resolution-${suffix}`;
  if (path.basename(resolutionId) !== resolutionId || !isSafeMemberName(resolutionId).safe) fail('invalid resolution receipt ID');
  if (readReceipt(resolutionId)) fail('resolution receipt already exists');
  const now = new Date().toISOString();
  const receipt = {
    receipt_id: resolutionId,
    quarantine_entry_id: id,
    supersedes_receipt_id: id,
    artifact: original.artifact,
    adopted_path: target,
    files: [{ path: path.basename(target), sha256: sha256File(target) }],
    source_sha256: original.source_sha256,
    purged: false,
    evidence: {
      original_deferred_receipt: { path: receiptPathFor(id), sha256: sha256File(receiptPathFor(id)) },
      format_report: { path: path.resolve(formatPath), sha256: sha256File(path.resolve(formatPath)) },
      defender_report: defenderPath ? { path: path.resolve(defenderPath), sha256: sha256File(path.resolve(defenderPath)) } : null,
      governance_decision: governancePath ? { path: path.resolve(governancePath), sha256: sha256File(path.resolve(governancePath)) } : null,
      format_verdict: formatReport.formatReview.verdict,
      accepted_warning_rules: evidence.warningRules,
      governance_candidate_count: evidence.governanceCandidateCount,
      governance_disposition: evidence.governanceDisposition,
    },
    resolution: {
      commitment_state: commitmentState,
      basis: defenderPath
        ? 'FORMAT_NATIVE_NO_BLOCKERS_AND_DEFENDER_NO_FINDINGS_WITH_ACCOUNTABLE_REVIEW'
        : 'FORMAT_NATIVE_NO_BLOCKERS_WITH_ACCOUNTABLE_REVIEW',
    },
    stage4: { decision: 'ALLOW', decided_by: by, at: now },
    last_verified: now,
  };
  try {
    const receiptPath = writeReceipt(receipt);
    console.log(JSON.stringify({ id, resolutionId, receiptPath, adoptedPath: target, commitmentState }, null, 2));
  } catch (error) {
    if (created) fs.rmSync(target, { force: true });
    throw error;
  }
}

const invokedDirectly = process.argv[1] && process.argv[1].endsWith('scan-resolve.mjs');
if (invokedDirectly) {
  try { main(); }
  catch (error) {
    console.error('deferred resolution failed closed: ' + error.message);
    process.exit(1);
  }
}
