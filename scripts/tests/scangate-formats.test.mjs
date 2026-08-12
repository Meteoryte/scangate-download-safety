import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  inspectHtmlText,
  inspectJsonText,
  inspectPdfBuffer,
  inspectSvgText,
} from '../scan-format-review.mjs';

test('passive SVG is accepted while active SVG is blocked', () => {
  assert.equal(inspectSvgText('<svg><path d="M0 0"/></svg>').verdict, 'NO_FINDINGS');
  assert.equal(inspectSvgText('<svg onload="run()"><script>run()</script></svg>').verdict, 'BLOCKED');
});

test('JSON parser records Unicode review evidence without leaking content', () => {
  const result = inspectJsonText('{"term":"A\\u200bB"}');
  assert.equal(result.verdict, 'REVIEW');
  assert.equal(result.warnings[0].rule, 'unicode-zero-width');
  assert.equal(Object.hasOwn(result.warnings[0], 'value'), false);
});

test('a leading UTF-8 BOM is recorded and stripped before JSON parsing', () => {
  const result = inspectJsonText('\uFEFF{"ok":true}');
  assert.equal(result.verdict, 'NO_FINDINGS');
  assert.ok(result.observations.some((item) => item.rule === 'json-utf8-bom'));
});

test('passive image data URI is evidence, executable data URI is blocked', () => {
  const passive = inspectHtmlText('<img src="data:image/png;base64,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">');
  assert.equal(passive.verdict, 'NO_FINDINGS');
  const active = inspectHtmlText('<iframe src="data:text/html;base64,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"></iframe>');
  assert.equal(active.verdict, 'BLOCKED');
});

test('HTML network and storage APIs require review but are not silently blocked as malware', () => {
  const result = inspectHtmlText('<script>localStorage.x=1; fetch("/local.json")</script>');
  assert.equal(result.verdict, 'REVIEW');
  assert.ok(result.warnings.some((item) => item.rule === 'html-network-api'));
});

test('PDF JavaScript and open actions block, ordinary page objects do not', () => {
  const ordinary = Buffer.from('%PDF-1.7\n1 0 obj << /Type /Page >> endobj\n%%EOF\n', 'latin1');
  assert.equal(inspectPdfBuffer(ordinary).verdict, 'NO_FINDINGS');
  const active = Buffer.from('%PDF-1.7\n<< /OpenAction 2 0 R /JavaScript /JS (app.launchURL()) >>\n%%EOF\n', 'latin1');
  assert.equal(inspectPdfBuffer(active).verdict, 'BLOCKED');
});

test('a non-script PDF OpenAction is review evidence, not automatically malware', () => {
  const pdf = Buffer.from('%PDF-1.7\n<< /OpenAction [1 0 R /Fit] >>\n%%EOF\n', 'latin1');
  assert.equal(inspectPdfBuffer(pdf).verdict, 'REVIEW');
});

test('PDF JavaScript with no high-risk API is explicit review evidence', () => {
  const pdf = Buffer.from('%PDF-1.7\n<< /JavaScript /JS (this.getField()) >>\n%%EOF\n', 'latin1');
  assert.equal(inspectPdfBuffer(pdf).verdict, 'REVIEW');
});

test('a compressed PDF image stream is passive evidence, not an uninspected stream', () => {
  const pdf = Buffer.from(
    '%PDF-1.7\n<< /Subtype /Image /Filter /DCTDecode >>\nstream\nnot-executed-image-data\nendstream\n%%EOF\n',
    'latin1',
  );
  const result = inspectPdfBuffer(pdf);
  assert.equal(result.verdict, 'NO_FINDINGS');
  assert.ok(result.observations.some((item) => item.rule === 'pdf-passive-image-stream-count' && item.count === 1));
});
