#!/usr/bin/env node
// SCANGATE format-native review.
//
// This script reads quarantined bytes model-blind and emits metadata only. It exists to
// close the coverage gap left when a general prompt/skill scanner encounters APK, DOCX,
// PDF, SVG, HTML, JSON, source trees, or nested APK tarballs. It never prints extracted
// text, URLs, secrets, or binary strings.

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { isSafeMemberName, sha256File, treeDigest } from './scan-core.mjs';
import { CAPS, readMemberBuffer, validateArchive } from './scan-zip.mjs';

const REVIEW_CAPS = {
  ...CAPS,
  MAX_ARCHIVE_BYTES: 256 * 1024 * 1024,
  MAX_MEMBERS: 50_000,
  MAX_UNCOMPRESSED: 1024 * 1024 * 1024,
};

const TEXT_EXT = new Set([
  '.md', '.txt', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.xml',
  '.html', '.htm', '.svg', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
  '.py', '.ps1', '.sh', '.bash', '.bat', '.cmd', '.java', '.kt', '.kts',
  '.gradle', '.properties', '.csv', '.css',
]);
const GOVERNANCE_RE = /(^|[/\\._ -])(protocol|protocols|skill|skills|rule|rules|guidance|governance|contract|contracts|playbook|runbook)([/\\._ -]|$)/i;
const SCRIPT_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.ps1', '.sh', '.bash', '.bat', '.cmd', '.java', '.kt', '.kts', '.gradle']);
const PASSIVE_BINARY_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.bmp', '.ico',
  '.woff', '.woff2', '.ttf', '.otf', '.mp3', '.wav', '.mp4', '.webm', '.mov',
]);
const MAX_TEXT_BYTES = 16 * 1024 * 1024;

function count(text, regex) {
  return [...String(text).matchAll(regex)].length;
}

function finding(rule, file, countValue = 1, severity = 'REVIEW') {
  return { rule, file, count: countValue, severity };
}

function matchingDictionaryStart(text, dictionaryEnd) {
  let depth = 1;
  for (let index = dictionaryEnd - 1; index >= 1; index--) {
    const token = text.slice(index - 1, index + 1);
    if (token === '>>') {
      depth++;
      index--;
    } else if (token === '<<') {
      depth--;
      if (depth === 0) return index - 1;
      index--;
    }
  }
  return -1;
}

function pdfFilterNames(dictionary) {
  return [...dictionary.matchAll(/\/(FlateDecode|ASCIIHexDecode|ASCII85Decode|LZWDecode|RunLengthDecode|DCTDecode|JPXDecode|CCITTFaxDecode|JBIG2Decode|Crypt)\b/g)]
    .map((match) => match[1]);
}

function decodeAscii85(input) {
  const text = input.toString('ascii').replace(/\s+/g, '').replace(/^<~/, '').replace(/~>$/, '');
  const out = [];
  let group = [];
  const flush = (final = false) => {
    if (!group.length) return;
    if (final && group.length === 1) throw new Error('invalid ASCII85 tail');
    const original = group.length;
    while (group.length < 5) group.push(84); // 'u' - 33
    let value = 0;
    for (const digit of group) value = value * 85 + digit;
    const bytes = [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
    out.push(...bytes.slice(0, final ? original - 1 : 4));
    group = [];
  };
  for (const char of text) {
    if (char === 'z') {
      if (group.length) throw new Error('ASCII85 z inside group');
      out.push(0, 0, 0, 0);
      continue;
    }
    const digit = char.charCodeAt(0) - 33;
    if (digit < 0 || digit > 84) throw new Error('invalid ASCII85 digit');
    group.push(digit);
    if (group.length === 5) flush(false);
  }
  flush(true);
  return Buffer.from(out);
}

function inflatePdfBytes(input) {
  const candidates = [input];
  let offset = 0;
  while (offset < Math.min(4, input.length) && (input[offset] === 0x0a || input[offset] === 0x0d)) {
    offset++;
    candidates.push(input.subarray(offset));
  }
  for (const candidate of candidates) {
    try { return zlib.inflateSync(candidate, { maxOutputLength: 128 * 1024 * 1024 }); } catch { /* next */ }
    try { return zlib.inflateRawSync(candidate, { maxOutputLength: 128 * 1024 * 1024 }); } catch { /* next */ }
  }
  throw new Error('Flate decode failed');
}

function decodePdfStream(raw, filterNames) {
  let decoded = raw;
  for (const filter of filterNames) {
    if (filter === 'ASCII85Decode') decoded = decodeAscii85(decoded);
    else if (filter === 'FlateDecode') decoded = inflatePdfBytes(decoded);
    else throw new Error(`unsupported PDF filter: ${filter}`);
  }
  return decoded;
}

function emptyResult(kind, file) {
  return {
    kind,
    file,
    verdict: 'NO_FINDINGS',
    blockers: [],
    warnings: [],
    observations: [],
    governanceCandidates: [],
  };
}

function finalize(result) {
  result.verdict = result.blockers.length ? 'BLOCKED'
    : result.warnings.length ? 'REVIEW'
      : 'NO_FINDINGS';
  return result;
}

function unicodeMetadata(text, file, result) {
  const zeroWidth = count(text, /[\u200B-\u200D\u2060\uFEFF]/gu);
  const bidi = count(text, /[\u202A-\u202E\u2066-\u2069]/gu);
  const cyrillicGreek = count(text, /[\u0370-\u03FF\u0400-\u04FF]/gu);
  if (zeroWidth) result.warnings.push(finding('unicode-zero-width', file, zeroWidth));
  if (bidi) result.blockers.push(finding('unicode-bidi-override', file, bidi, 'BLOCK'));
  if (cyrillicGreek) result.warnings.push(finding('unicode-greek-or-cyrillic', file, cyrillicGreek));
  const codepoints = {};
  for (const char of String(text)) {
    const cp = char.codePointAt(0);
    if ((cp >= 0x0370 && cp <= 0x04ff)
        || (cp >= 0x200b && cp <= 0x200d)
        || cp === 0x2060 || cp === 0xfeff
        || (cp >= 0x202a && cp <= 0x202e)
        || (cp >= 0x2066 && cp <= 0x2069)) {
      const key = 'U+' + cp.toString(16).toUpperCase().padStart(4, '0');
      codepoints[key] = (codepoints[key] || 0) + 1;
    }
  }
  if (Object.keys(codepoints).length) {
    result.observations.push({ rule: 'unicode-codepoint-counts', file, counts: codepoints });
  }
}

export function inspectJsonText(text, file = 'input.json') {
  const result = emptyResult('json', file);
  let parsed = null;
  const hasBom = text.charCodeAt(0) === 0xfeff;
  const parseText = hasBom ? text.slice(1) : text;
  if (hasBom) result.observations.push({ rule: 'json-utf8-bom', file, count: 1 });
  try {
    parsed = JSON.parse(parseText);
    result.observations.push({ rule: 'json-valid', file, count: 1 });
  } catch {
    result.blockers.push(finding('json-invalid', file, 1, 'BLOCK'));
  }
  unicodeMetadata(parsed === null ? parseText : JSON.stringify(parsed), file, result);
  const prototypeKeys = count(parseText, /"(?:__proto__|prototype|constructor)"\s*:/g);
  if (prototypeKeys) result.warnings.push(finding('prototype-sensitive-key', file, prototypeKeys));
  return finalize(result);
}

export function inspectSvgText(text, file = 'input.svg') {
  const result = emptyResult('svg', file);
  const checks = [
    ['svg-script-element', /<\s*script\b/gi],
    ['svg-event-handler', /\son[a-z]+\s*=/gi],
    ['svg-javascript-uri', /(?:href|xlink:href)\s*=\s*["']\s*javascript:/gi],
    ['svg-foreign-object', /<\s*foreignObject\b/gi],
    ['svg-doctype-or-entity', /<!DOCTYPE|<!ENTITY/gi],
    ['svg-external-reference', /(?:href|xlink:href|src)\s*=\s*["']\s*(?:https?:|file:|\\\\|\/\/)/gi],
    ['svg-css-import', /@import\s+(?:url\s*\()?/gi],
  ];
  for (const [rule, regex] of checks) {
    const hits = count(text, regex);
    if (hits) result.blockers.push(finding(rule, file, hits, 'BLOCK'));
  }
  if (!/<\s*svg\b/i.test(text)) result.blockers.push(finding('svg-root-missing', file, 1, 'BLOCK'));
  unicodeMetadata(text, file, result);
  result.observations.push({
    rule: 'svg-element-count',
    file,
    count: count(text, /<\s*(?!\/|!|\?)[A-Za-z][^>]*>/g),
  });
  return finalize(result);
}

export function inspectHtmlText(text, file = 'input.html') {
  const result = emptyResult('html', file);
  const blockers = [
    ['html-eval', /\beval\s*\(/g],
    ['html-function-constructor', /\bnew\s+Function\s*\(/g],
    ['html-document-write', /\bdocument\.write(?:ln)?\s*\(/g],
    ['html-javascript-uri', /(?:href|src|action)\s*=\s*["']\s*javascript:/gi],
    ['html-meta-refresh', /<meta[^>]+http-equiv\s*=\s*["']?refresh/gi],
    ['html-external-script', /<script[^>]+src\s*=\s*["']\s*(?:https?:)?\/\//gi],
    ['html-object-embed', /<(?:object|embed)\b/gi],
  ];
  for (const [rule, regex] of blockers) {
    const hits = count(text, regex);
    if (hits) result.blockers.push(finding(rule, file, hits, 'BLOCK'));
  }

  const warnings = [
    ['html-network-api', /\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon)\b/g],
    ['html-storage-api', /\b(?:localStorage|sessionStorage|indexedDB)\b/g],
    ['html-iframe', /<iframe\b/gi],
    ['html-form', /<form\b/gi],
    ['html-inline-event-handler', /\son[a-z]+\s*=/gi],
  ];
  for (const [rule, regex] of warnings) {
    const hits = count(text, regex);
    if (hits) result.warnings.push(finding(rule, file, hits));
  }

  const dataUris = [...String(text).matchAll(/data:([^;, "'()]+)(?:;base64)?,([A-Za-z0-9+/=\s_-]{32,})/gi)];
  let nonPassiveData = 0;
  for (const match of dataUris) {
    const mime = String(match[1] || '').toLowerCase();
    if (!(mime.startsWith('image/') || mime.startsWith('font/') || mime === 'text/css')) nonPassiveData++;
  }
  if (nonPassiveData) result.blockers.push(finding('html-active-or-unknown-data-uri', file, nonPassiveData, 'BLOCK'));
  if (dataUris.length) result.observations.push({ rule: 'html-passive-data-uri', file, count: dataUris.length - nonPassiveData });

  const externalRefs = count(text, /(?:href|src|action)\s*=\s*["']\s*(?:https?:)?\/\//gi);
  if (externalRefs) result.warnings.push(finding('html-external-reference', file, externalRefs));
  result.observations.push({ rule: 'html-inline-script-count', file, count: count(text, /<script\b(?![^>]*\bsrc=)/gi) });
  unicodeMetadata(text, file, result);
  return finalize(result);
}

export function inspectPdfBuffer(buffer, file = 'input.pdf') {
  const result = emptyResult('pdf', file);
  const text = buffer.toString('latin1');
  if (!text.startsWith('%PDF-')) result.blockers.push(finding('pdf-header-invalid', file, 1, 'BLOCK'));
  if (!/%%EOF\s*$/.test(text.slice(-4096))) result.warnings.push(finding('pdf-eof-marker-missing', file));

  const active = [
    ['pdf-launch', /\/Launch\b/g],
    ['pdf-embedded-file', /\/EmbeddedFile\b|\/EmbeddedFiles\b/g],
    ['pdf-rich-media', /\/RichMedia\b/g],
    ['pdf-submit-form', /\/SubmitForm\b/g],
    ['pdf-remote-goto', /\/GoToR\b/g],
    ['pdf-xfa', /\/XFA\b/g],
  ];
  for (const [rule, regex] of active) {
    const hits = count(text, regex);
    if (hits) result.blockers.push(finding(rule, file, hits, 'BLOCK'));
  }
  const chunks = [text];
  let decodedStreams = 0;
  let undecodedStreams = 0;
  let passiveImageStreams = 0;
  const undecodedReasons = {};
  const recordUndecoded = (reason) => {
    undecodedStreams++;
    undecodedReasons[reason] = (undecodedReasons[reason] || 0) + 1;
  };
  const streamRe = /\bstream\r?\n/g;
  let streamMatch;
  while ((streamMatch = streamRe.exec(text)) !== null) {
    const dictionaryEnd = text.lastIndexOf('>>', streamMatch.index);
    const dictionaryStart = dictionaryEnd >= 0 ? matchingDictionaryStart(text, dictionaryEnd) : -1;
    if (dictionaryStart < 0 || !/^\s*$/.test(text.slice(dictionaryEnd + 2, streamMatch.index))) {
      // A token inside compressed data is not a PDF stream boundary.
      continue;
    }
    const dictionary = text.slice(dictionaryStart, dictionaryEnd + 2);
    const start = streamRe.lastIndex;
    const end = text.indexOf('endstream', start);
    if (end < 0) {
      recordUndecoded('missing-endstream');
      break;
    }
    const directLengthMatch = dictionary.match(/\/Length\s+(\d+)\b/);
    const directLength = directLengthMatch ? Number.parseInt(directLengthMatch[1], 10) : null;
    let dataEnd = Number.isSafeInteger(directLength) && start + directLength <= end
      ? start + directLength
      : end;
    if (dataEnd === end) {
      while (dataEnd > start && (buffer[dataEnd - 1] === 0x0a || buffer[dataEnd - 1] === 0x0d)) dataEnd--;
    }
    const raw = buffer.subarray(start, dataEnd);
    const filterNames = pdfFilterNames(dictionary);
    try {
      const passiveImage = /\/Subtype\s*\/Image\b/.test(dictionary)
        && filterNames.length > 0
        && filterNames.every((name) => name !== 'Crypt');
      if (passiveImage) {
        // Image codecs are deliberately not executed here. Their compressed bytes are
        // passive PDF image data, not an uninspected executable/document stream.
        passiveImageStreams++;
      } else if (filterNames.length && filterNames.every((name) => name === 'ASCII85Decode' || name === 'FlateDecode')) {
        chunks.push(decodePdfStream(raw, filterNames).toString('latin1'));
        decodedStreams++;
      } else if (!/\/Filter\b/.test(dictionary)) {
        chunks.push(raw.toString('latin1'));
        decodedStreams++;
      } else {
        recordUndecoded(filterNames.length ? `unsupported-${[...new Set(filterNames)].sort().join('+')}` : 'unsupported-filter');
      }
    } catch {
      recordUndecoded(filterNames.length
        ? `decode-failed-${[...new Set(filterNames)].sort().join('+')}`
        : 'flate-decode-failed');
    }
    streamRe.lastIndex = end + 'endstream'.length;
  }
  const searchable = chunks.join('\n');
  const javascript = count(searchable, /\/JavaScript\b|\/JS\s*(?:\(|<|\d)/g);
  const additionalActions = count(searchable, /\/AA\b/g);
  const riskyJavaScript = count(searchable,
    /\b(?:launchURL|getURL|submitForm|mailDoc|mailMsg|exportDataObject|importDataObject|getDataObjectContents|saveAs|openDoc|readFileIntoStream|Net\.HTTP|SOAP|Collab|eval\s*\(|new\s+Function\s*\()/g);
  if (riskyJavaScript) result.blockers.push(finding('pdf-javascript-high-risk-api', file, riskyJavaScript, 'BLOCK'));
  if (javascript) result.warnings.push(finding('pdf-javascript-present', file, javascript));
  if (additionalActions) result.warnings.push(finding('pdf-additional-action', file, additionalActions));
  if (undecodedStreams) result.warnings.push(finding('pdf-undecoded-stream', file, undecodedStreams));
  result.observations.push({ rule: 'pdf-decoded-stream-count', file, count: decodedStreams });
  result.observations.push({ rule: 'pdf-passive-image-stream-count', file, count: passiveImageStreams });
  if (undecodedStreams) result.observations.push({ rule: 'pdf-undecoded-stream-reasons', file, counts: undecodedReasons });
  const openAction = count(text, /\/OpenAction\b/g);
  if (openAction) result.warnings.push(finding('pdf-open-action', file, openAction));
  if (/\/Encrypt\b/.test(text)) result.blockers.push(finding('pdf-encrypted', file, 1, 'BLOCK'));
  const uriCount = count(text, /\/URI\b/g);
  if (uriCount) result.warnings.push(finding('pdf-uri-reference', file, uriCount));
  result.observations.push({ rule: 'pdf-page-object-count', file, count: count(text, /\/Type\s*\/Page\b/g) });
  return finalize(result);
}

function inspectDocx(abs, file) {
  const result = emptyResult('docx', file);
  const validation = validateArchive(abs, REVIEW_CAPS);
  if (!validation.ok) {
    for (const violation of validation.violations) {
      result.blockers.push({ rule: 'docx-archive-invalid', file, count: 1, severity: 'BLOCK', metadata: violation.slice(0, 240) });
    }
    return finalize(result);
  }

  const names = validation.entries.map((entry) => entry.name);
  const forbiddenNameRules = [
    ['docx-vba-macro', /(?:^|\/)vbaProject\.bin$/i],
    ['docx-embedded-object', /\/embeddings\//i],
    ['docx-activex', /\/activeX\//i],
    ['docx-ole-object', /oleObject/i],
    ['docx-encrypted-package', /^(?:EncryptionInfo|EncryptedPackage)$/i],
  ];
  for (const [rule, regex] of forbiddenNameRules) {
    const hits = names.filter((name) => regex.test(name)).length;
    if (hits) result.blockers.push(finding(rule, file, hits, 'BLOCK'));
  }

  let externalRelationships = 0;
  let dangerousExternalRelationships = 0;
  let ddeFields = 0;
  let xmlFiles = 0;
  for (const entry of validation.entries) {
    if (!/\.xml$|\.rels$/i.test(entry.name) || entry.uncompressedSize > MAX_TEXT_BYTES) continue;
    const text = readMemberBuffer(abs, entry, MAX_TEXT_BYTES).toString('utf8');
    xmlFiles++;
    externalRelationships += count(text, /TargetMode\s*=\s*["']External["']/gi);
    dangerousExternalRelationships += count(text, /Target\s*=\s*["']\s*(?:javascript:|file:|\\\\|\/\/)/gi);
    ddeFields += count(text, /\b(?:DDEAUTO|DDE|INCLUDETEXT|INCLUDEPICTURE)\b/gi);
  }
  if (dangerousExternalRelationships) result.blockers.push(finding('docx-dangerous-external-relationship', file, dangerousExternalRelationships, 'BLOCK'));
  if (ddeFields) result.blockers.push(finding('docx-dde-or-external-field', file, ddeFields, 'BLOCK'));
  if (externalRelationships) result.warnings.push(finding('docx-external-relationship', file, externalRelationships));
  result.observations.push({ rule: 'docx-member-count', file, count: validation.entries.length });
  result.observations.push({ rule: 'docx-xml-part-count', file, count: xmlFiles });
  return finalize(result);
}

function dexMetadata(buffer, file, result) {
  if (buffer.length < 112 || !buffer.subarray(0, 4).equals(Buffer.from('dex\n'))) {
    result.blockers.push(finding('apk-dex-header-invalid', file, 1, 'BLOCK'));
    return;
  }
  const declaredSize = buffer.readUInt32LE(32);
  const headerSize = buffer.readUInt32LE(36);
  if (declaredSize !== buffer.length) result.blockers.push(finding('apk-dex-size-mismatch', file, 1, 'BLOCK'));
  if (headerSize !== 112) result.blockers.push(finding('apk-dex-header-size-invalid', file, 1, 'BLOCK'));
  const ascii = buffer.toString('latin1');
  const reviewPatterns = [
    ['apk-runtime-exec', /Ljava\/lang\/Runtime;|ProcessBuilder/g],
    ['apk-dynamic-code-loading', /DexClassLoader|PathClassLoader|InMemoryDexClassLoader/g],
    ['apk-native-loading', /System;->loadLibrary|System;->load\(/g],
    ['apk-webview-bridge', /addJavascriptInterface|setJavaScriptEnabled/g],
    ['apk-sms-api', /SmsManager|sendTextMessage/g],
    ['apk-accessibility-api', /AccessibilityService/g],
    ['apk-package-install-api', /REQUEST_INSTALL_PACKAGES|PackageInstaller/g],
  ];
  for (const [rule, regex] of reviewPatterns) {
    const hits = count(ascii, regex);
    if (hits) result.warnings.push(finding(rule, file, hits));
  }
  const urlCount = count(ascii, /https?:\/\//g);
  if (urlCount) result.observations.push({ rule: 'apk-url-string-count', file, count: urlCount });
}

function inspectApk(abs, file) {
  const result = emptyResult('apk', file);
  const validation = validateArchive(abs, REVIEW_CAPS);
  if (!validation.ok) {
    for (const violation of validation.violations) {
      result.blockers.push({ rule: 'apk-archive-invalid', file, count: 1, severity: 'BLOCK', metadata: violation.slice(0, 240) });
    }
    return finalize(result);
  }
  const files = validation.entries.filter((entry) => !entry.name.endsWith('/'));
  const dex = files.filter((entry) => /^classes(?:\d+)?\.dex$/i.test(entry.name));
  const manifests = files.filter((entry) => entry.name === 'AndroidManifest.xml');
  const signatures = files.filter((entry) => /^META-INF\/[^/]+\.(?:RSA|DSA|EC|SF)$/i.test(entry.name));
  const nativeLibraries = files.filter((entry) => /^lib\/[^/]+\/[^/]+\.so$/i.test(entry.name));
  if (manifests.length !== 1) result.blockers.push(finding('apk-manifest-count-invalid', file, manifests.length, 'BLOCK'));
  if (!dex.length) result.blockers.push(finding('apk-dex-missing', file, 1, 'BLOCK'));
  for (const entry of dex) {
    const data = readMemberBuffer(abs, entry, Math.max(entry.uncompressedSize, 112));
    dexMetadata(data, entry.name, result);
  }

  const jar = spawnSync('jarsigner', ['-verify', '-strict', '-certs', abs], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 8 * 1024 * 1024,
  });
  result.observations.push({
    rule: 'apk-jarsigner-exit',
    file,
    count: Number.isInteger(jar.status) ? jar.status : -1,
  });
  if (jar.error) {
    result.warnings.push(finding('apk-jarsigner-unavailable', file, 1));
    if (!signatures.length) result.warnings.push(finding('apk-signature-unverified', file, 1));
  } else if (jar.status !== 0) {
    result.warnings.push(finding('apk-jarsigner-not-strict-valid', file, 1));
  } else {
    result.observations.push({
      rule: signatures.length ? 'apk-v1-signature-verified' : 'apk-modern-signature-verified',
      file,
      count: 1,
    });
  }

  result.observations.push({ rule: 'apk-member-count', file, count: files.length });
  result.observations.push({ rule: 'apk-dex-count', file, count: dex.length });
  result.observations.push({ rule: 'apk-native-library-count', file, count: nativeLibraries.length });
  result.observations.push({ rule: 'apk-visible-signature-entry-count', file, count: signatures.length });
  return finalize(result);
}

function tarEntries(buffer) {
  const out = [];
  const seen = new Set();
  let offset = 0;
  let total = 0;
  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const nameRaw = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/, '');
    const name = prefix ? prefix + '/' + nameRaw : nameRaw;
    const sizeText = header.subarray(124, 136).toString('ascii').replace(/\0.*$/, '').trim();
    const size = Number.parseInt(sizeText || '0', 8);
    const type = String.fromCharCode(header[156] || 48);
    if (!Number.isSafeInteger(size) || size < 0) throw new Error('invalid tar member size');
    const safe = isSafeMemberName(name);
    if (!safe.safe) throw new Error('unsafe tar member name: ' + safe.reason);
    const key = name.toLowerCase();
    if (seen.has(key)) throw new Error('duplicate tar member name');
    seen.add(key);
    if (type === '1' || type === '2') throw new Error('tar link member refused');
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > buffer.length) throw new Error('tar member extends past end of archive');
    out.push({ name, size, type, dataStart, dataEnd });
    total += size;
    if (out.length > 50_000 || total > REVIEW_CAPS.MAX_UNCOMPRESSED) throw new Error('tar expansion cap exceeded');
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  return out;
}

function inspectTarGz(abs, file) {
  const result = emptyResult('tar.gz', file);
  let expanded;
  try {
    expanded = zlib.gunzipSync(fs.readFileSync(abs), { maxOutputLength: REVIEW_CAPS.MAX_UNCOMPRESSED });
  } catch {
    result.blockers.push(finding('gzip-invalid-or-over-cap', file, 1, 'BLOCK'));
    return finalize(result);
  }
  let entries;
  try {
    entries = tarEntries(expanded);
  } catch {
    result.blockers.push(finding('tar-invalid-or-unsafe', file, 1, 'BLOCK'));
    return finalize(result);
  }
  const apks = entries.filter((entry) => /\.apk$/i.test(entry.name) && (entry.type === '0' || entry.type === '\0'));
  if (!apks.length) result.warnings.push(finding('tar-apk-missing', file, 1));
  for (const entry of apks) {
    const temp = path.join(path.dirname(abs), '.scangate-inner-' + process.pid + '.apk');
    try {
      fs.writeFileSync(temp, expanded.subarray(entry.dataStart, entry.dataEnd), { flag: 'wx' });
      const nested = inspectApk(temp, entry.name);
      result.blockers.push(...nested.blockers);
      result.warnings.push(...nested.warnings);
      result.observations.push(...nested.observations);
    } finally {
      fs.rmSync(temp, { force: true });
    }
  }
  result.observations.push({ rule: 'tar-member-count', file, count: entries.length });
  return finalize(result);
}

function inspectTextFile(abs, rel) {
  const ext = path.extname(rel).toLowerCase();
  const text = fs.readFileSync(abs, 'utf8');
  if (ext === '.json') return inspectJsonText(text, rel);
  if (ext === '.svg') return inspectSvgText(text, rel);
  if (ext === '.html' || ext === '.htm') return inspectHtmlText(text, rel);

  const result = emptyResult('text', rel);
  unicodeMetadata(text, rel, result);
  const privateKeys = count(text, /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g);
  const cloudKeys = count(text, /\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|github_pat_[0-9A-Za-z_]{20,}|ghp_[0-9A-Za-z]{20,})\b/g);
  if (privateKeys) result.blockers.push(finding('private-key-material', rel, privateKeys, 'BLOCK'));
  if (cloudKeys) result.blockers.push(finding('credential-shaped-token', rel, cloudKeys, 'BLOCK'));
  if (SCRIPT_EXT.has(ext)) {
    const execution = count(text, /\b(?:child_process|subprocess|os\.system|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Invoke-Expression|Start-Process)\b/g);
    const dynamic = count(text, /\b(?:eval|exec)\s*\(/g);
    const network = count(text, /\b(?:fetch|XMLHttpRequest|requests\.(?:get|post)|urllib|curl\b|wget\b|Invoke-WebRequest)\b/g);
    if (execution) result.warnings.push(finding('script-process-execution', rel, execution));
    if (dynamic) result.warnings.push(finding('script-dynamic-evaluation', rel, dynamic));
    if (network) result.warnings.push(finding('script-network-capability', rel, network));
  }
  return finalize(result);
}

function mergeResult(target, child) {
  target.blockers.push(...child.blockers);
  target.warnings.push(...child.warnings);
  target.observations.push(...child.observations);
  target.governanceCandidates.push(...child.governanceCandidates);
}

export function inspectTree(root) {
  const result = emptyResult('tree', path.basename(root));
  const extensionCounts = {};
  let files = 0;
  let bytes = 0;
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      const rel = path.relative(root, full).split(path.sep).join('/');
      if (entry.isSymbolicLink()) {
        result.blockers.push(finding('tree-symbolic-link', rel, 1, 'BLOCK'));
        continue;
      }
      if (entry.isDirectory()) {
        walk(full);
        continue;
      }
      if (!entry.isFile()) {
        result.blockers.push(finding('tree-nonregular-entry', rel, 1, 'BLOCK'));
        continue;
      }
      files++;
      const stat = fs.statSync(full);
      bytes += stat.size;
      const ext = path.extname(rel).toLowerCase() || '<none>';
      extensionCounts[ext] = (extensionCounts[ext] || 0) + 1;
      if (GOVERNANCE_RE.test('/' + rel)) result.governanceCandidates.push({ path: rel, sha256: sha256File(full), size: stat.size });
      if (TEXT_EXT.has(ext) && stat.size <= MAX_TEXT_BYTES) mergeResult(result, inspectTextFile(full, rel));
      else if (ext === '.docx') mergeResult(result, inspectDocx(full, rel));
      else if (ext === '.pdf') mergeResult(result, inspectPdfBuffer(fs.readFileSync(full), rel));
      else if (ext === '.apk') mergeResult(result, inspectApk(full, rel));
      else if (/\.tar\.gz$/i.test(rel)) mergeResult(result, inspectTarGz(full, rel));
      else if (!PASSIVE_BINARY_EXT.has(ext)) result.warnings.push(finding('format-native-inspector-unhandled', rel));
    }
  };
  walk(root);
  result.observations.push({ rule: 'tree-file-count', file: result.file, count: files });
  result.observations.push({ rule: 'tree-byte-count', file: result.file, count: bytes });
  result.extensionCounts = Object.fromEntries(Object.entries(extensionCounts).sort((a, b) => a[0].localeCompare(b[0])));
  result.governanceCandidates = result.governanceCandidates
    .sort((a, b) => a.path.localeCompare(b.path));
  return finalize(result);
}

export function inspectPayload(payloadDir) {
  if (!fs.existsSync(payloadDir) || !fs.statSync(payloadDir).isDirectory()) {
    throw new Error('payload directory missing or not a directory');
  }
  return inspectTree(payloadDir);
}

function main() {
  const args = process.argv.slice(2);
  const targetArg = args[0];
  const outputIndex = args.indexOf('--output');
  const outputPath = outputIndex >= 0 ? path.resolve(args[outputIndex + 1] || '') : null;
  if (!targetArg || targetArg.startsWith('--')) {
    throw new Error('usage: node scripts/scan-format-review.mjs <quarantine-payload-directory> [--output report.json]');
  }
  const target = path.resolve(targetArg);
  const review = inspectPayload(target);
  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    modelBlind: true,
    contentPrinted: false,
    target,
    targetTreeDigest: treeDigest(target),
    formatReview: review,
  };
  const serialized = JSON.stringify(report, null, 2);
  if (outputPath) {
    fs.writeFileSync(outputPath, serialized + '\n', 'utf8');
    console.log('report=' + outputPath);
  } else {
    console.log(serialized);
  }
}

const invokedDirectly = process.argv[1] && process.argv[1].endsWith('scan-format-review.mjs');
if (invokedDirectly) {
  try {
    main();
  } catch (error) {
    console.error('format review failed closed: ' + error.message);
    process.exit(1);
  }
}
