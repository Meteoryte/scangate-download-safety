#!/usr/bin/env node
// ---------------------------------------------------------------------------
// scangate-pretooluse.mjs — SCANGATE layer 1.
//
// Blocks model ingestion of quarantined content that has no valid ALLOW receipt.
//
// This is the gate that makes "scan before a model interacts with it" real rather than
// aspirational. A malicious SKILL.md does not need to be installed to win — it wins the
// moment its text enters the context of an agent holding filesystem, shell, credentials,
// and MCP servers. So the gate sits at READ, not at install.
//
// TWO PROPERTIES IN TENSION, BOTH DELIBERATE:
//
//   FAIL CLOSED — any error while evaluating a quarantine-touching call denies.
//   TINY BLAST RADIUS — a call that does not mention the quarantine root is allowed
//   without touching the filesystem at all. A security control that breaks ordinary work
//   gets switched off by its owner, and a disabled control protects nothing.
//
// The second property is why the marker test runs on the raw input BEFORE any fs call.
// ---------------------------------------------------------------------------

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// scan-core is loaded LAZILY and defensively, never as a static import.
//
// A static `import` that fails takes the whole module down before any of this file's code
// runs. Node then exits 1 — and Claude Code treats a non-zero-but-not-2 exit as a
// NON-BLOCKING error, so a crashed hook would silently ALLOW. That is the exact
// fail-open this gate exists to prevent.
//
// With a guarded dynamic import, a broken or missing scan-core leaves `core` null, receipt
// verification cannot succeed, and every quarantine-touching call denies.
let core = null;
try {
  core = await import('../scan-core.mjs');
} catch {
  core = null;
}

// Computed locally so the deny path does not depend on scan-core resolving at all.
const HOOK_DIR = path.dirname(fileURLToPath(import.meta.url));
const FALLBACK_RECEIPTS_DIR = path.resolve(HOOK_DIR, '../../state/scan-receipts');

const MARKER = '_quarantine';
const MAX_DEPTH = 6;

// Workspace-authored files that live in the quarantine ROOT and are not artifacts.
// Denying these would make the quarantine folder undocumentable from inside the workspace.
const ROOT_ALLOWLIST = new Set(['readme.md', '.gitignore', 'do-not-read.md']);

// Sanctioned invocations, anchored at the start of the command with no shell chaining.
const SANCTIONED_COMMAND = /^\s*(pnpm\s+run\s+scan:[a-z-]+|node\s+"?[^"]*scripts[/\\]scan-[a-z-]+\.mjs)/;
const SHELL_CHAINING = /[;&|`]|\$\(|\n/;

function isSanctionedToolInvocation(input) {
  const command = input?.command;
  if (typeof command !== 'string') return false;
  if (SHELL_CHAINING.test(command)) return false;
  return SANCTIONED_COMMAND.test(command);
}

// Only PATH-BEARING fields are inspected — never free text such as `content`,
// `new_string`, or `old_string`.
//
// An earlier version walked every value in the tool input. That blocked writing any file
// whose CONTENTS merely mentioned the quarantine directory, including this protocol's own
// documentation and source. A gate that cannot be documented gets removed, so precision
// here is a durability property, not a convenience.
const PATH_KEYS = new Set([
  'file_path', 'filePath', 'path', 'paths', 'file_paths',
  'notebook_path', 'notebookPath', 'pattern', 'glob', 'url', 'cwd', 'directory',
]);

/** Every string beneath a value, regardless of key. */
function collectStrings(value, depth = 0) {
  if (depth > MAX_DEPTH) return [];
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap((item) => collectStrings(item, depth + 1));
  if (value && typeof value === 'object') return Object.values(value).flatMap((item) => collectStrings(item, depth + 1));
  return [];
}

function collectPathLike(value, depth = 0, key = null) {
  if (depth > MAX_DEPTH) return [];

  // Once inside a path-bearing field, collect EVERY nested string. A well-formed
  // `file_path` is a plain string; a malformed one hiding a path inside an object is
  // exactly the case where guessing wrong should deny rather than allow.
  if (PATH_KEYS.has(key)) return collectStrings(value, depth);

  if (Array.isArray(value)) return value.flatMap((item) => collectPathLike(item, depth + 1, key));
  if (value && typeof value === 'object') {
    return Object.entries(value).flatMap(([k, v]) => collectPathLike(v, depth + 1, k));
  }
  return [];
}

function hitsMarker(text) {
  return String(text).replace(/\\/g, '/').toLowerCase().includes(MARKER);
}

function mentionsQuarantine(input) {
  // Bash has no structured path field, so its command string is checked directly.
  const command = input?.command;
  if (typeof command === 'string' && hitsMarker(command)) return true;
  return collectPathLike(input).some(hitsMarker);
}

/**
 * Decide whether a quarantine-touching reference is permitted.
 *
 * The directory name immediately under `_quarantine/` IS the receipt id, which is what
 * binds a filesystem path to a human ALLOW decision.
 */
function referenceIsCleared(text) {
  const normalized = text.replace(/\\\\/g, '/').replace(/\\/g, '/').toLowerCase();
  const match = normalized.match(/_quarantine\/([^/"'\s,)\]}]+)/);
  if (!match) return false;

  const segment = match[1];
  if (ROOT_ALLOWLIST.has(segment)) return true;

  // No verifier means no way to prove a receipt is genuine, so nothing is cleared.
  if (!core?.verifyReceipt) return false;

  const receiptsDir = core.RECEIPTS_DIR || FALLBACK_RECEIPTS_DIR;
  const receiptFile = path.join(receiptsDir, `${segment}.json`);
  if (!fs.existsSync(receiptFile)) return false;

  const receipt = JSON.parse(fs.readFileSync(receiptFile, 'utf8'));
  if (!core.verifyReceipt(receipt).valid) return false;
  return receipt.stage4?.decision === 'ALLOW';
}

const DENY_REASON =
  'SCANGATE: this path is quarantined and has no valid ALLOW receipt. Nothing may read it '
  + 'until it passes the scan gate — a malicious artifact compromises an agent the moment its '
  + 'text enters context, not when it is installed. '
  + 'Run `pnpm run scan:run -- <quarantine-dir>` and get a human decision. '
  + 'Protocol: docs/PROTOCOL.md';

/**
 * @param {object} hookInput Claude Code PreToolUse payload
 * @returns {{ decision: 'allow'|'deny', reason: string }}
 */
export function evaluate(hookInput) {
  try {
    const input = hookInput?.tool_input;
    if (!mentionsQuarantine(input)) return { decision: 'allow', reason: '' };

    // The sanctioned scan tools must be able to reference quarantined paths, or the gate
    // blocks the only thing capable of opening it. Narrow by construction: the command
    // must START with a sanctioned invocation and contain no shell chaining, so appending
    // a second command to read the artifact is still denied. Safe because these tools
    // emit METADATA ONLY and never print artifact contents into anyone's context.
    if (isSanctionedToolInvocation(input)) {
      return { decision: 'allow', reason: 'sanctioned SCANGATE tool invocation' };
    }

    if (referenceIsCleared(JSON.stringify(input))) {
      return { decision: 'allow', reason: 'valid ALLOW receipt' };
    }
    return { decision: 'deny', reason: DENY_REASON };
  } catch (error) {
    // Fail closed — but only for calls that already mentioned quarantine, so a bug here
    // cannot take down unrelated tool use.
    return { decision: 'deny', reason: `SCANGATE failed closed: ${error.message}` };
  }
}

/** Raw-text fallback: used when the payload will not parse as JSON at all. */
export function evaluateRaw(rawText) {
  const text = String(rawText || '');
  if (!text.replace(/\\/g, '/').toLowerCase().includes(MARKER)) {
    return { decision: 'allow', reason: '' };
  }
  return { decision: 'deny', reason: `SCANGATE failed closed: unparseable hook payload referencing ${MARKER}` };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  let raw = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => { raw += chunk; });
  process.stdin.on('end', () => {
    let result;
    try {
      result = evaluate(JSON.parse(raw));
    } catch {
      // Unparseable payload: cannot inspect structurally, so fall back to raw text.
      result = evaluateRaw(raw);
    }

    if (result.decision === 'deny') {
      process.stdout.write(JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: result.reason,
        },
      }));
    }
    process.exit(0);
  });
}
