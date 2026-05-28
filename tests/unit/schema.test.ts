import { describe, expect, it } from 'vitest';
import Ajv2020 from 'ajv/dist/2020';
import addFormats from 'ajv-formats';
import schema from '../../schemas/findings.schema.json';
import type { Finding } from '../../src/findings';

const ajv = new Ajv2020({ allErrors: true });
addFormats(ajv);
const validate = ajv.compile(schema);

function validReport(findings: Finding[]) {
  return {
    targetUrl: 'http://juice-shop:3000',
    generatedAt: '2026-05-28T20:00:00.000Z',
    findingCount: findings.length,
    findings
  };
}

const sampleFinding: Finding = {
  id: 'HDR-001',
  title: 'Content-Security-Policy header is missing',
  severity: 'Medium',
  category: 'Header Hardening',
  status: 'observed',
  description: 'No CSP header was present.',
  impact: 'Reduced defense-in-depth against injection.',
  remediation: 'Deploy a restrictive CSP.',
  evidence: [{ label: 'Missing header', details: 'content-security-policy' }],
  references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/']
};

describe('findings JSON schema', () => {
  it('is itself a compilable schema', () => {
    expect(typeof validate).toBe('function');
  });

  it('accepts a well-formed report', () => {
    expect(validate(validReport([sampleFinding]))).toBe(true);
  });

  it('rejects an invalid severity', () => {
    const bad = validReport([{ ...sampleFinding, severity: 'Catastrophic' as Finding['severity'] }]);
    expect(validate(bad)).toBe(false);
  });

  it('rejects a finding missing required fields', () => {
    const { remediation: _omitted, ...incomplete } = sampleFinding;
    expect(validate(validReport([incomplete as Finding]))).toBe(false);
  });

  it('rejects unknown top-level properties', () => {
    expect(validate({ ...validReport([sampleFinding]), rogue: true })).toBe(false);
  });
});
