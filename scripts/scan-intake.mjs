#!/usr/bin/env node
// ---------------------------------------------------------------------------
// scan-intake.mjs — SCANGATE stage 0 (ingress).
//
// The ONLY sanctioned path for foreign content to reach disk. The PreToolUse hook denies
// agent writes into the quarantine tree, so anything arriving there comes through here —
// which makes this the place every containment check has to live.
//
// This tool NEVER prints artifact file contents. Its output is metadata only. Printing
// content would re-open the ingestion hole the whole gate exists to close: an operator
// reading the tool's output would be reading the artifact.
// ---------------------------------------------------------------------------

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { QUARANTINE_ROOT, resolveTier, realpathIsInside } from './scan-core.mjs';
import { extractTo, validateArchive } from './scan-zip.mjs';

export function slugFor(source) {
  return String(source)
    .replace(/^https?:\/\//, '')
    .replace(/\.git$/, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
}

export function quarantineIdFor(source, date = new Date().toISOString().slice(0, 10)) {
  const digest = crypto.createHash('sha256').update(String(source)).digest('hex').slice(0, 6);
  return `${date}-${slugFor(source)}-${digest}`;
}

/** Extract host/org/repo for trust resolution. Never throws on a non-URL. */
export function parseSource(source) {
  try {
    const url = new URL(source);
    const [, org, repo] = url.pathname.split('/');
    return {
      host: url.hostname,
      org: org || null,
      repo: (repo || '').replace(/\.git$/, '') || null,
    };
  } catch {
    return { host: null, org: null, repo: null };
  }
}

const GIT_RE = /^https?:\/\/.*\.git$|github\.com|gitlab\.com|bitbucket\.org/i;

function safeSourceName(value) {
  const name = String(value || 'downloaded-artifact')
    .replace(/[\\/\u0000-\u001f<>:"|?*]+/g, '_')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/[. ]+$/g, '')
    .slice(0, 220);
  return !name || name === '.' || name === '..' ? 'downloaded-artifact' : name;
}

function downloadRemote(source, destination) {
  const result = spawnSync('curl', [
    '--location', '--fail', '--silent', '--show-error',
    '--retry', '3', '--retry-delay', '2', '--retry-all-errors',
    '--max-time', '900', '--output', destination, source,
  ], { encoding: 'utf8', windowsHide: true, timeout: 930_000 });
  if (result.status !== 0 || result.error) {
    throw new Error(`download failed: ${String(result.stderr || result.error?.message || `curl exited ${result.status}`).slice(0, 300)}`);
  }
}

/**
 * @param {{ source: string, kind?: string, root?: string, sourceUrl?: string,
 *   sourceName?: string, expectedSize?: number|null, sourceIdentity?: object|null,
 *   download?: Function }} options
 * @returns {{ id: string, dir: string, tier: string, sourcePreserved: boolean }}
 */
export function intake({
  source,
  kind = 'auto',
  root = QUARANTINE_ROOT,
  sourceUrl = null,
  sourceName = null,
  expectedSize = null,
  sourceIdentity = null,
  download = downloadRemote,
}) {
  const id = quarantineIdFor(source);
  const dir = path.join(root, id);
  if (fs.existsSync(dir)) throw new Error(`quarantine entry already exists: ${id}`);

  const isGit = kind === 'git' || (kind === 'auto' && GIT_RE.test(source));
  const isRemote = !isGit && /^https?:\/\//i.test(source);
  const remoteName = isRemote
    ? safeSourceName(sourceName || (() => { try { return path.basename(new URL(source).pathname); } catch { return ''; } })())
    : null;
  const isZip = isRemote ? /\.zip$/i.test(remoteName) : /\.zip$/i.test(source) && fs.existsSync(source);
  const isLocal = fs.existsSync(source);

  if (!isGit && !isLocal && !isRemote) throw new Error(`unsupported or missing source: ${source}`);

  const sourceDir = path.join(dir, '_source');
  const payloadDir = path.join(dir, 'payload');
  fs.mkdirSync(sourceDir, { recursive: true });
  fs.mkdirSync(payloadDir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'DO-NOT-READ.md'),
    '# Do not read\n\nThis artifact has not passed the SCANGATE scan.\n\n'
    + 'A malicious artifact compromises an agent the moment its text enters context — not\n'
    + 'when it is installed. Reading anything here before a verdict defeats the entire gate.\n\n'
    + 'Run `pnpm run scan:run -- <this-directory>/payload` and get a human decision.\n',
  );

  const tier = resolveTier(sourceIdentity || parseSource(sourceUrl || source));

  try {
    if (isGit) {
      const result = spawnSync('git', ['clone', '--depth', '1', source, payloadDir],
        { encoding: 'utf8', windowsHide: true, timeout: 300_000 });
      if (result.status !== 0) {
        throw new Error(`clone failed: ${String(result.stderr || result.error?.message).slice(0, 300)}`);
      }
      // The .git directory is not part of the artifact and carries its own hooks.
      fs.rmSync(path.join(payloadDir, '.git'), { recursive: true, force: true });
    } else if (isRemote) {
      const preserved = path.join(sourceDir, remoteName);
      download(source, preserved);

      const actualSize = fs.statSync(preserved).size;
      if (expectedSize != null && actualSize !== Number(expectedSize)) {
        throw new Error(`download size mismatch: expected ${expectedSize}, received ${actualSize}`);
      }

      if (isZip) {
        const validation = validateArchive(preserved);
        if (!validation.ok) {
          throw new Error(`archive rejected at ingress: ${validation.violations.join('; ')}`);
        }
        extractTo(preserved, payloadDir);
      } else {
        fs.copyFileSync(preserved, path.join(payloadDir, remoteName));
      }
    } else if (isZip) {
      const preserved = path.join(sourceDir, path.basename(source));
      fs.copyFileSync(source, preserved);          // UDL rule 3: preserve the original

      const validation = validateArchive(preserved);
      if (!validation.ok) {
        throw new Error(`archive rejected at ingress: ${validation.violations.join('; ')}`);
      }
      extractTo(preserved, payloadDir);
    } else {
      const sourceStat = fs.statSync(source);
      if (sourceStat.isDirectory()) {
        fs.cpSync(source, sourceDir, { recursive: true });
        fs.cpSync(source, payloadDir, { recursive: true });
      } else {
        const localName = safeSourceName(sourceName || path.basename(source));
        fs.copyFileSync(source, path.join(sourceDir, localName));
        fs.copyFileSync(source, path.join(payloadDir, localName));
      }
    }

    // Post-extraction real-path check. A lexical check cannot catch a link created DURING
    // extraction, and this workspace's own memory/ directory is a junction — so this is a
    // live vector, not a theoretical one.
    const escapes = [];
    const walk = (current) => {
      for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
        const full = path.join(current, entry.name);
        if (entry.isSymbolicLink() || !realpathIsInside(payloadDir, full)) {
          escapes.push(path.relative(payloadDir, full));
          continue;
        }
        if (entry.isDirectory()) walk(full);
      }
    };
    walk(payloadDir);
    if (escapes.length) {
      throw new Error(`payload escapes quarantine via link(s): ${escapes.join(', ')}`);
    }
  } catch (error) {
    // Leave _source in place for forensics; remove the unusable payload so nothing
    // half-extracted looks like a completed intake.
    fs.rmSync(payloadDir, { recursive: true, force: true });
    fs.writeFileSync(path.join(dir, 'INTAKE-FAILED.md'),
      `# Intake failed\n\n${new Date().toISOString()}\n\n${error.message}\n\nThe original is preserved in _source/ as provenance.\n`);
    throw error;
  }

  const meta = {
    id,
    source,
    source_url: sourceUrl,
    source_name: sourceName,
    expected_size: expectedSize,
    source_identity: sourceIdentity,
    tier,
    kind: isRemote ? 'url' : kind,
    at: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(dir, 'intake.json'), JSON.stringify(meta, null, 2));

  return { id, dir, tier, sourcePreserved: fs.readdirSync(sourceDir).length > 0 };
}

const invokedDirectly = process.argv[1] && process.argv[1].endsWith('scan-intake.mjs');

if (invokedDirectly) {
  const source = process.argv[2];
  if (!source) {
    console.error('usage: pnpm run scan:intake -- <url-or-path> [--url <provenance-url>] [--name <filename>] [--size <bytes>]');
    process.exit(2);
  }
  const urlFlag = process.argv.indexOf('--url');
  const sourceUrl = urlFlag > 0 ? process.argv[urlFlag + 1] : null;
  const nameFlag = process.argv.indexOf('--name');
  const sourceName = nameFlag > 0 ? process.argv[nameFlag + 1] : null;
  const sizeFlag = process.argv.indexOf('--size');
  const expectedSize = sizeFlag > 0 ? Number(process.argv[sizeFlag + 1]) : null;

  try {
    if (sizeFlag > 0 && (!Number.isSafeInteger(expectedSize) || expectedSize < 0)) {
      throw new Error('--size must be a non-negative integer');
    }
    const result = intake({ source, sourceUrl, sourceName, expectedSize });
    console.log(JSON.stringify(result, null, 2));
    console.log(`\nNext: pnpm run scan:run -- "${path.join(result.dir, 'payload')}" ${result.tier}`);
    console.log('Then record the artifact as PULLED in your system-of-record before review.');
  } catch (error) {
    console.error(`intake refused: ${error.message}`);
    process.exit(1);
  }
}
