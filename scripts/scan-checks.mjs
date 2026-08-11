// ---------------------------------------------------------------------------
// scan-checks.mjs — SCANGATE workspace-local content pre-checks.
//
// These run alongside SkillSpector, not instead of it. They exist because static pattern
// matching is structurally blind to the highest-yield evasion in the wild: a payload
// hidden where the scanner never looks (an ignored folder, a scrambled data blob) and
// reassembled only when the agent runs the skill. Published measurements put that
// technique's bypass rate above 90% across eight scanners.
//
// The unpack-gap check is the direct answer: enumerate what is on disk, diff against what
// the scanner actually opened, and treat the difference as a HIGH finding.
// ---------------------------------------------------------------------------

import fs from 'node:fs';
import path from 'node:path';

const BIDI = /[‪-‮⁦-⁩]/;
const ZERO_WIDTH = /[​-‍⁠﻿]/;
// Cyrillic and Greek blocks contain letters that render identically to Latin ones.
const HOMOGLYPH = /[Ѐ-ӿͰ-Ͽ]/;

// Formats that are high-entropy by construction. Flagging every PNG and gzip would bury
// the one embedded blob that actually matters, so entropy is not measured on these.
const NATURALLY_COMPRESSED = /\.(png|jpe?g|gif|webp|avif|ico|bmp|mp[34]|mov|avi|mkv|webm|ogg|flac|wav|zip|gz|bz2|xz|7z|rar|woff2?|ttf|otf|eot|pdf|safetensors|gguf|wasm|so|dll|dylib|exe)$/i;

const TEXTUAL = /\.(md|txt|json|ya?ml|toml|ini|cfg|py|js|mjs|cjs|ts|tsx|jsx|sh|bash|zsh|ps1|bat|cmd|rb|pl|php|go|rs|java|c|h|cpp|hpp|cs|sql|html?|xml|csv|env)$/i;

const MAX_READ_BYTES = 8 * 1024 * 1024;
const ENTROPY_MIN_BYTES = 1024;
// Fraction of bytes that must be printable/whitespace for a buffer to count as text.
const TEXT_RATIO_MIN = 0.85;
// Unbroken base64/hex characters that signal an encoded payload rather than prose or code.
const ENCODED_RUN_MIN = 512;
// Above measured dense-markdown entropy (~4.8–5.0), not above the textbook prose figure.
const TEXT_ENTROPY_CEILING = 5.5;

/**
 * @param {string} text
 * @returns {Array<{rule: string, detail: string}>}
 */
export function checkUnicode(text) {
  if (typeof text !== 'string') return [];
  const findings = [];
  if (BIDI.test(text)) {
    findings.push({ rule: 'unicode-bidi-override', detail: 'bidirectional override character (renders differently than it parses)' });
  }
  if (ZERO_WIDTH.test(text)) {
    findings.push({ rule: 'unicode-zero-width', detail: 'zero-width or invisible character' });
  }
  if (HOMOGLYPH.test(text)) {
    findings.push({ rule: 'unicode-homoglyph', detail: 'Cyrillic or Greek homoglyph in otherwise-Latin text' });
  }
  return findings;
}

function shannonEntropy(buffer) {
  const counts = new Array(256).fill(0);
  for (const byte of buffer) counts[byte]++;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const p = count / buffer.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Is this buffer text? Null bytes or a low printable ratio mean binary.
function isTextual(buffer) {
  let printable = 0;
  for (const byte of buffer) {
    if (byte === 0) return false;
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) printable++;
  }
  return printable / buffer.length >= TEXT_RATIO_MIN;
}

// Longest unbroken run of characters from the base64/hex alphabet. Prose and code break
// every few characters on whitespace and punctuation; an encoded payload does not.
function longestEncodedRun(text) {
  let longest = 0;
  let current = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const encodedChar = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
      || (c >= '0' && c <= '9') || c === '+' || c === '/' || c === '=';
    if (encodedChar) {
      current++;
      if (current > longest) longest = current;
    } else {
      current = 0;
    }
  }
  return longest;
}

/**
 * Detect payloads *encoded inside text*, which is the threat this rule exists for.
 *
 * The original whole-file Shannon test was recalibrated on 2026-08-09 against real
 * inventory: it produced 76 of 109 stage-1 retro-scan findings, including a 4.82 bits/byte
 * reading on this gate's own sealed-reviewer agent file. Dense markdown — tables, code
 * fences, punctuation — sits well above the 4.0 "English prose" figure the threshold
 * assumed, so the rule was firing on ordinary documentation.
 *
 * Two changes, both narrowing *detection* rather than lowering severity (which the doctrine
 * forbids):
 *   1. Binary files are skipped. Images, archives, and model shards are compressed and sit
 *      near 8 bits/byte by nature; flagging them buries the finding that matters. Weight
 *      files are covered by scan-weights.mjs, which reads structure instead of guessing.
 *   2. Text files are judged on the longest unbroken base64/hex run, not on file-wide
 *      average. A payload hidden in a SKILL.md is a long contiguous encoded run; prose is
 *      not, however dense it gets.
 *
 * @param {Buffer} buffer
 * @returns {Array<{rule: string, detail: string}>}
 */
export function checkEntropy(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < ENTROPY_MIN_BYTES) return [];
  if (!isTextual(buffer)) return [];

  const findings = [];
  const text = buffer.toString('latin1');

  const run = longestEncodedRun(text);
  if (run >= ENCODED_RUN_MIN) {
    findings.push({
      rule: 'encoded-blob-in-text',
      detail: `${run}-character unbroken base64/hex run inside a text file (possible encoded payload)`,
    });
  }

  // Retained as a backstop for text that is neither prose nor a clean encoded run —
  // obfuscated or compressed content pasted into a text file. The ceiling is set above
  // measured dense-markdown values rather than above the textbook prose figure.
  const entropy = shannonEntropy(buffer);
  if (entropy > TEXT_ENTROPY_CEILING && run < ENCODED_RUN_MIN) {
    findings.push({
      rule: 'high-entropy-text',
      detail: `entropy ${entropy.toFixed(2)} bits/byte across ${buffer.length} bytes of text (well above dense markdown)`,
    });
  }

  return findings;
}

function walkFiles(dir) {
  if (!fs.existsSync(dir)) throw new Error(`scan-checks: directory does not exist: ${dir}`);
  const out = [];
  const rel = (full) => path.relative(dir, full).split(path.sep).join('/');
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) { out.push(rel(full)); continue; }
      if (entry.isDirectory()) { walk(full); continue; }
      if (entry.isFile()) out.push(rel(full));
    }
  };
  walk(dir);
  return out.sort();
}

/** Dotfiles and dot-directories, listed explicitly rather than silently skipped. */
export function findHiddenPaths(dir) {
  return walkFiles(dir).filter((rel) => rel.split('/').some((segment) => segment.startsWith('.')));
}

/**
 * Files present on disk that the scanner never analyzed.
 *
 * @param {string} dir
 * @param {string[]} analyzedPaths
 * @returns {string[]}
 */
export function findUnpackGap(dir, analyzedPaths = []) {
  const analyzed = new Set(
    (Array.isArray(analyzedPaths) ? analyzedPaths : [])
      .map((p) => String(p).split(path.sep).join('/').replace(/^\.\//, ''))
  );
  return walkFiles(dir).filter((rel) => !analyzed.has(rel));
}

/**
 * @param {string} dir
 * @param {string[]} analyzedPaths paths SkillSpector reported analyzing
 * @returns {Array<{rule, severity, file, detail}>}
 */
export function runPreChecks(dir, analyzedPaths = []) {
  const findings = [];

  for (const rel of walkFiles(dir)) {
    const full = path.join(dir, rel);
    let buffer;
    try {
      const stat = fs.statSync(full);
      if (!stat.isFile()) continue;
      if (stat.size > MAX_READ_BYTES) {
        findings.push({
          rule: 'oversized-file', severity: 'LOW', file: rel,
          detail: `${stat.size} bytes exceeds the ${MAX_READ_BYTES}-byte inspection cap; not content-checked`,
        });
        continue;
      }
      buffer = fs.readFileSync(full);
    } catch (error) {
      findings.push({
        rule: 'unreadable-file', severity: 'MEDIUM', file: rel,
        detail: `could not read for inspection: ${error.code || error.message}`,
      });
      continue;
    }

    if (!NATURALLY_COMPRESSED.test(rel)) {
      for (const finding of checkEntropy(buffer)) {
        findings.push({ ...finding, severity: 'MEDIUM', file: rel });
      }
    }

    if (TEXTUAL.test(rel)) {
      for (const finding of checkUnicode(buffer.toString('utf8'))) {
        findings.push({ ...finding, severity: 'HIGH', file: rel });
      }
    }
  }

  for (const rel of findHiddenPaths(dir)) {
    findings.push({
      rule: 'hidden-path', severity: 'LOW', file: rel,
      detail: 'dotfile or dot-directory — a common place to park a payload',
    });
  }

  // HIGH on purpose. Expect noise on legitimate archives at first; tune by reporting what
  // the scanner analyzed more accurately, NEVER by lowering this severity.
  for (const rel of findUnpackGap(dir, analyzedPaths)) {
    findings.push({
      rule: 'unpack-gap', severity: 'HIGH', file: rel,
      detail: 'present on disk but never analyzed by the scanner',
    });
  }

  return findings;
}
