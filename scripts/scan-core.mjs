// ---------------------------------------------------------------------------
// scan-core.mjs — SCANGATE shared primitives.
//
// Path safety, content hashing, receipt signing and verification, and trust-tier
// resolution. No Docker, no network, no artifact execution — this module only ever
// reads bytes and compares them.
//
// Governing doctrine: docs/PROTOCOL.md
// Threat model:       docs/THREAT-MODEL.md
//
// Every function here is called on attacker-controlled input. The rule throughout is
// deny-by-default: an input that cannot be understood is rejected, never passed through.
// ---------------------------------------------------------------------------

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const WORKSPACE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const QUARANTINE_ROOT = path.join(WORKSPACE_ROOT, '_quarantine');
export const RECEIPTS_DIR = path.join(WORKSPACE_ROOT, 'state/scan-receipts');
const KEY_PATH = path.join(WORKSPACE_ROOT, '.secrets/scangate-receipt.key');

// Win32 reserved device names. Creating "CON" or "com1.txt" does not create a file —
// it opens a device, and the resulting behaviour is not something we want to discover
// during extraction of an untrusted archive.
const RESERVED = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)/i;

// Bidi overrides and zero-width characters. "photo\u202Egpj.exe" displays as
// "photoexe.jpg" in Explorer and in most terminal listings — classic extension spoofing.
const DECEPTIVE = /[\u202A-\u202E\u2066-\u2069\u200B-\u200D\u2060\uFEFF]/;

// Windows MAX_PATH is 260 including the drive and separators. We reserve headroom for
// the quarantine root prefix, which is itself ~60 characters here.
const MAX_SEGMENT_LENGTH = 255;
const MAX_TOTAL_LENGTH = 200;

/**
 * Validate an archive member name or relative path before it is ever written to disk.
 *
 * @param {string} name
 * @returns {{ safe: boolean, reason: string|null }}
 */
export function isSafeMemberName(name) {
  const fail = (reason) => ({ safe: false, reason });

  if (typeof name !== 'string') return fail(`not a string (got ${name === null ? 'null' : typeof name})`);
  if (name.length === 0) return fail('empty name');
  if (name.trim().length === 0) return fail('whitespace-only name');
  if (name.length > MAX_TOTAL_LENGTH) return fail(`path length ${name.length} exceeds ${MAX_TOTAL_LENGTH}`);

  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(name)) return fail('control character');
  if (DECEPTIVE.test(name)) return fail('bidi override or zero-width character (extension spoofing)');

  // Percent-encoded traversal: some consumers decode before use, so "%2e%2e" is "..".
  if (/%2e/i.test(name) || /%2f/i.test(name) || /%5c/i.test(name)) {
    return fail('percent-encoded path separator or traversal');
  }

  // UNC (\\server\share), device namespace (\\?\, \\.\), and forward-slash UNC.
  if (/^[\\/]{2}/.test(name)) return fail('UNC or device-namespace path');
  if (/^[a-zA-Z]:/.test(name)) return fail('windows drive-absolute path');
  if (name.startsWith('/') || name.startsWith('\\')) return fail('absolute path');
  if (name.includes(':')) return fail('NTFS alternate data stream');

  const segments = name.split(/[\\/]/);
  const meaningful = segments.filter((segment) => segment !== '');
  if (meaningful.length === 0) return fail('no path segments');

  for (const segment of meaningful) {
    if (segment === '.' || segment === '..') return fail('path traversal');
    if (segment.length > MAX_SEGMENT_LENGTH) return fail(`segment length ${segment.length} exceeds ${MAX_SEGMENT_LENGTH}`);
    if (RESERVED.test(segment)) return fail(`reserved device name: ${segment}`);
    // Win32 silently strips trailing dots and spaces, so "evil." and "evil" collide —
    // which lets an archive overwrite a file it appears not to name.
    if (/[. ]$/.test(segment)) return fail('segment ends with dot or space');
  }

  return { safe: true, reason: null };
}

/**
 * Lexical containment check. Works on paths that do not exist yet, which is what makes
 * it usable *before* extraction. Throws rather than returning false so a missing call
 * site cannot silently degrade into an allow.
 *
 * @param {string} root
 * @param {string} target
 */
export function assertInside(root, target) {
  if (typeof root !== 'string' || root.length === 0) {
    throw new Error(`assertInside: root must be a non-empty string, got ${typeof root}`);
  }
  if (typeof target !== 'string' || target.length === 0) {
    throw new Error(`assertInside: target must be a non-empty string, got ${typeof target}`);
  }

  const resolvedRoot = path.resolve(root);
  const resolvedTarget = path.resolve(target);

  // path.relative() handles the sibling-prefix case correctly: relative from
  // "/root/workspace" to "/root/workspace-evil" is "../workspace-evil", not "-evil".
  const rel = path.relative(resolvedRoot, resolvedTarget);
  if (rel === '') return;
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(`path escapes root: ${target}`);
  }
}

/**
 * Real-path containment check. Resolves symlinks and NTFS junctions, so it only works
 * after the file exists — but it is the only check that catches a link created *during*
 * extraction. The workspace's own memory/ directory is a junction, so this is not
 * hypothetical.
 *
 * Returns false on any error, including a missing path: unknown means unsafe.
 *
 * @param {string} root
 * @param {string} target
 * @returns {boolean}
 */
export function realpathIsInside(root, target) {
  try {
    const realRoot = fs.realpathSync(root);
    const realTarget = fs.realpathSync(target);
    assertInside(realRoot, realTarget);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Content hashing and receipt signing
//
// The receipt is the enforcement mechanism: it binds a human ALLOW decision to the exact
// bytes that were reviewed. Change one byte and the receipt stops matching, so the gate
// reverts to deny.
//
// HONEST LIMIT: the HMAC key lives on the same filesystem as the receipts. This stops an
// agent from forging a receipt through ordinary tool calls and detects careless or
// accidental mutation. It does NOT stop an attacker who already has arbitrary local file
// access. That is the correct threat model — SCANGATE defends against untrusted CONTENT,
// not against a fully compromised host. Do not describe this as tamper-proof.
// ---------------------------------------------------------------------------

const SIGNATURE_RE = /^[0-9a-f]{64}$/i;
const MAX_CANONICAL_DEPTH = 32;

function receiptKey() {
  if (!fs.existsSync(KEY_PATH)) {
    fs.mkdirSync(path.dirname(KEY_PATH), { recursive: true });
    fs.writeFileSync(KEY_PATH, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  }
  const key = fs.readFileSync(KEY_PATH, 'utf8').trim();
  // A truncated or emptied key file would silently weaken every signature in the ledger.
  if (!SIGNATURE_RE.test(key)) {
    throw new Error(`SCANGATE receipt key is malformed at ${KEY_PATH} — refusing to sign or verify`);
  }
  return key;
}

/**
 * Deterministic serialization: keys sorted, undefined normalized to null.
 *
 * `signature` is stripped at the TOP LEVEL ONLY. Stripping it at every depth would leave
 * a hole — an attacker could hide arbitrary data inside any nested object under a key
 * named "signature" and it would not be covered by the HMAC.
 */
function canonical(value, depth = 0, isTop = false) {
  if (depth > MAX_CANONICAL_DEPTH) throw new Error('receipt nesting too deep (possible cycle)');
  if (Array.isArray(value)) return `[${value.map((item) => canonical(item, depth + 1)).join(',')}]`;
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).filter((key) => !(isTop && key === 'signature')).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key], depth + 1)}`).join(',')}}`;
  }
  return JSON.stringify(value === undefined ? null : value);
}

export function signReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    throw new Error('signReceipt: receipt must be a plain object');
  }
  const signature = crypto.createHmac('sha256', receiptKey())
    .update(canonical(receipt, 0, true)).digest('hex');
  return { ...receipt, signature };
}

export function verifyReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    return { valid: false, reason: 'not a receipt object' };
  }
  // Buffer.from('zz', 'hex') returns an EMPTY buffer instead of throwing, so an invalid
  // signature must be rejected by format BEFORE it reaches any comparison.
  if (typeof receipt.signature !== 'string' || !SIGNATURE_RE.test(receipt.signature)) {
    return { valid: false, reason: 'missing or malformed signature' };
  }

  let expected;
  try {
    expected = crypto.createHmac('sha256', receiptKey()).update(canonical(receipt, 0, true)).digest('hex');
  } catch (error) {
    return { valid: false, reason: `cannot verify: ${error.message}` };
  }

  const provided = Buffer.from(receipt.signature.toLowerCase(), 'hex');
  const computed = Buffer.from(expected, 'hex');
  if (provided.length !== computed.length || !crypto.timingSafeEqual(provided, computed)) {
    return { valid: false, reason: 'signature mismatch' };
  }
  return { valid: true, reason: null };
}

export function sha256File(abs) {
  return crypto.createHash('sha256').update(fs.readFileSync(abs)).digest('hex');
}

/**
 * Hash every file under `dir`, returning sorted `{ path, sha256 }` entries with POSIX
 * separators so receipts compare identically across platforms.
 *
 * Links are RECORDED, never followed — following a junction would hash content outside
 * the tree and let an artifact claim coverage it does not have.
 *
 * Throws on a missing directory: returning an empty array would make drift detection
 * silently pass for an artifact that had been deleted.
 */
export function hashTree(dir) {
  if (!fs.existsSync(dir)) throw new Error(`hashTree: directory does not exist: ${dir}`);
  if (!fs.statSync(dir).isDirectory()) throw new Error(`hashTree: not a directory: ${dir}`);

  const out = [];
  const rel = (full) => path.relative(dir, full).split(path.sep).join('/');
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) { out.push({ path: rel(full), sha256: 'SYMLINK' }); continue; }
      if (entry.isDirectory()) { walk(full); continue; }
      if (!entry.isFile()) { out.push({ path: rel(full), sha256: 'NONREGULAR' }); continue; }
      try {
        out.push({ path: rel(full), sha256: sha256File(full) });
      } catch (error) {
        // Recorded as a distinct marker so a drift comparison reports a mismatch rather
        // than the whole sweep crashing on one locked file.
        out.push({ path: rel(full), sha256: `UNREADABLE:${error.code || 'ERR'}` });
      }
    }
  };
  walk(dir);
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

// One digest over a whole directory tree, used as the provenance baseline for `_source/`.
// Shared rather than recomputed at each call site for the same reason `canonical()` is:
// the writer and the verifier must agree byte-for-byte or every check is a false alarm.
// hashTree already sorts by path, so this is order-independent across filesystems.
export function treeDigest(dir) {
  if (!fs.existsSync(dir)) return null;
  const tree = hashTree(dir);
  const material = tree.map((f) => `${f.path} ${f.sha256}`).join('');
  return crypto.createHash('sha256').update(material).digest('hex');
}

export function receiptPathFor(id) {
  return path.join(RECEIPTS_DIR, `${id}.json`);
}

export function writeReceipt(receipt) {
  fs.mkdirSync(RECEIPTS_DIR, { recursive: true });
  const target = receiptPathFor(receipt.receipt_id);
  fs.writeFileSync(target, JSON.stringify(signReceipt(receipt), null, 2), 'utf8');
  return target;
}

export function readReceipt(id) {
  const target = receiptPathFor(id);
  if (!fs.existsSync(target)) return null;
  try { return JSON.parse(fs.readFileSync(target, 'utf8')); } catch { return null; }
}

// ---------------------------------------------------------------------------
// Trust tiers
//
// Trust modulates scan DEPTH, never scan EXISTENCE. Stages 0 and 1 run at every tier,
// including T0, because a COMPROMISED TRUSTED SOURCE is exactly the case that must not
// sail through — and those are the two cheapest stages anyway.
// ---------------------------------------------------------------------------

export const TRUST_REGISTRY_PATH = path.join(WORKSPACE_ROOT, 'config/scan-trust-registry.json');

const DEFAULT_REGISTRY = {
  schema_version: 1,
  sources: [],
  demotions: [],
  denylist: [],
  default_policy: { unknown_tier: 'T3', configured_is_trusted: false },
};

export function loadTrustRegistry() {
  try {
    const parsed = JSON.parse(fs.readFileSync(TRUST_REGISTRY_PATH, 'utf8'));
    if (!parsed || typeof parsed !== 'object') return DEFAULT_REGISTRY;
    return parsed;
  } catch {
    // A missing or corrupt registry must not grant trust. Falling back to an empty
    // registry means everything resolves to T3 — strictest, not most permissive.
    return DEFAULT_REGISTRY;
  }
}

/**
 * Exact, ASCII-only, case-insensitive identity comparison.
 *
 * Non-ASCII input NEVER matches. That is deliberate and load-bearing: no legitimate
 * trusted identity here needs a non-ASCII character, while every homoglyph typosquat
 * does. Rejecting them at the type level makes "improve this with Unicode normalization"
 * a regression that fails a test rather than a subtle privilege escalation.
 */
function asciiEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  // eslint-disable-next-line no-control-regex
  const printableAscii = /^[ -~]*$/;
  if (!printableAscii.test(a) || !printableAscii.test(b)) return false;
  return a.toLowerCase() === b.toLowerCase();
}

/**
 * @param {{host?: string, org?: string, repo?: string}} source
 * @returns {'T0'|'T1'|'T2'|'T3'|'T4'}
 */
export function resolveTierFromRegistry(source, registry) {
  if (!source || typeof source !== 'object' || Array.isArray(source)) return 'T3';
  const fallback = registry.default_policy?.unknown_tier || 'T3';

  // Denylist wins over everything, including an entry that also appears in sources.
  for (const entry of Array.isArray(registry.denylist) ? registry.denylist : []) {
    if (asciiEq(entry?.host, source.host) && asciiEq(entry?.org, source.org)) return 'T4';
  }

  // Demotions are exact artifact identities. A finding in one file from an approved
  // container must not revoke trust for every sibling file in that container.
  for (const entry of Array.isArray(registry.demotions) ? registry.demotions : []) {
    if (asciiEq(entry?.host, source.host)
        && asciiEq(entry?.org, source.org)
        && asciiEq(entry?.repo, source.repo)) return 'T2';
  }

  for (const entry of Array.isArray(registry.sources) ? registry.sources : []) {
    if (!/^T[0-4]$/.test(entry?.tier || '')) continue;      // malformed entry grants nothing
    if (!asciiEq(entry.host, source.host)) continue;
    if (!asciiEq(entry.org, source.org)) continue;
    if (entry.repo !== '*' && !asciiEq(entry.repo, source.repo)) continue;
    return entry.tier;
  }

  return fallback;
}

export function resolveTier(source) {
  return resolveTierFromRegistry(source, loadTrustRegistry());
}

/**
 * Maximum acceptable risk score for a tier.
 *
 * T3 (unknown) must land in SkillSpector's SAFE band (<= 20) rather than merely under its
 * default CAUTION cut of 50. An anonymous artifact scoring MEDIUM is not worth accepting
 * when refusing it costs nothing. Anything unrecognized gets the strictest bar.
 */
export function thresholdForTier(tier) {
  return tier === 'T1' || tier === 'T2' ? 50 : 20;
}

/**
 * Demote a source to T2 after it produces a CRITICAL or HIGH finding. Restoring it is a
 * human action — automatic demotion is safe, automatic promotion never is.
 */
export function demoteSource(org, repo, reason, host = null) {
  const registry = loadTrustRegistry();
  registry.demotions = Array.isArray(registry.demotions) ? registry.demotions : [];
  let matchedHost = null;
  for (const entry of Array.isArray(registry.sources) ? registry.sources : []) {
    if (entry.tier === 'T1'
        && asciiEq(entry.org, org)
        && (entry.repo === '*' || asciiEq(entry.repo, repo))
        && (!host || asciiEq(entry.host, host))) {
      matchedHost = entry.host;
      break;
    }
  }
  if (!matchedHost) return false;
  if (registry.demotions.some((entry) => asciiEq(entry.host, matchedHost)
      && asciiEq(entry.org, org) && asciiEq(entry.repo, repo))) return false;

  registry.demotions.push({
    tier: 'T2',
    host: matchedHost,
    org,
    repo,
    demoted: { at: new Date().toISOString(), reason: String(reason).slice(0, 300) },
  });
  fs.writeFileSync(TRUST_REGISTRY_PATH, JSON.stringify(registry, null, 2), 'utf8');
  return true;
}
