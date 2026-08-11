// The subagent's answer is DATA, not instruction. Anything that does not match the schema
// exactly is treated as BLOCKED -- a compromised or confused reviewer cannot produce a pass
// by returning prose.

const VERDICTS = new Set(['BLOCKED', 'NO_FINDINGS', 'FINDINGS_ACCEPTED']);
const CONFIDENCE = new Set(['confirmed', 'strongly-supported', 'partially-supported', 'inferred']);

const blocked = (reason) => ({
  verdict: 'BLOCKED',
  confidence: 'inferred',
  findings: [{ category: 'verdict-invalid', file: '-', line: 0, evidence: reason, severity: 'HIGH' }],
  rationale: `SCANGATE rejected the review response: ${reason}`,
});

export function validateVerdict(raw) {
  let value = raw;
  if (typeof raw === 'string') {
    try { value = JSON.parse(raw); } catch { return blocked('response was not valid JSON'); }
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return blocked('response was not an object');
  if (!VERDICTS.has(value.verdict)) return blocked(`unknown verdict token: ${String(value.verdict)}`);
  if (!CONFIDENCE.has(value.confidence)) return blocked(`unknown confidence token: ${String(value.confidence)}`);
  if (!Array.isArray(value.findings)) return blocked('findings must be an array');
  if (typeof value.rationale !== 'string') return blocked('rationale must be a string');

  return {
    verdict: value.verdict,
    confidence: value.confidence,
    findings: value.findings.slice(0, 100).map((f) => ({
      category: String(f?.category ?? 'unknown').slice(0, 80),
      file: String(f?.file ?? '-').slice(0, 300),
      line: Number.isInteger(f?.line) ? f.line : 0,
      evidence: String(f?.evidence ?? '').slice(0, 500),
      severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(f?.severity) ? f.severity : 'MEDIUM',
    })),
    rationale: value.rationale.slice(0, 2000),
  };
}
