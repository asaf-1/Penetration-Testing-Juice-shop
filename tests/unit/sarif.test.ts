import { describe, expect, it } from 'vitest';
import { toSarif } from '../../src/sarif';
import type { Finding } from '../../src/findings';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'HDR-001',
    title: 'CSP missing',
    severity: 'Medium',
    category: 'Header Hardening',
    status: 'observed',
    description: 'No CSP header',
    impact: 'impact',
    remediation: 'add CSP',
    evidence: [],
    ...overrides
  };
}

const TARGET = 'http://juice-shop:3000';

describe('toSarif', () => {
  it('produces a valid SARIF 2.1.0 envelope with one run', () => {
    const sarif = toSarif([makeFinding()], TARGET);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0');
    expect(sarif.runs).toHaveLength(1);
  });

  it('emits one rule per unique finding id', () => {
    const sarif = toSarif(
      [makeFinding({ id: 'HDR-001' }), makeFinding({ id: 'HDR-001' }), makeFinding({ id: 'API-002' })],
      TARGET
    );
    const run = sarif.runs[0] as { tool: { driver: { rules: Array<{ id: string }> } } };
    expect(run.tool.driver.rules.map((rule) => rule.id).sort()).toEqual(['API-002', 'HDR-001']);
  });

  it('maps severity to SARIF level and security-severity score', () => {
    const sarif = toSarif(
      [makeFinding({ id: 'C', severity: 'Critical' }), makeFinding({ id: 'I', severity: 'Info' })],
      TARGET
    );
    const run = sarif.runs[0] as {
      results: Array<{ ruleId: string; level: string }>;
      tool: { driver: { rules: Array<{ id: string; properties: { 'security-severity': string } }> } };
    };

    const critical = run.results.find((result) => result.ruleId === 'C');
    const info = run.results.find((result) => result.ruleId === 'I');
    expect(critical?.level).toBe('error');
    expect(info?.level).toBe('note');

    const criticalRule = run.tool.driver.rules.find((rule) => rule.id === 'C');
    expect(criticalRule?.properties['security-severity']).toBe('9.5');
  });

  it('derives the result location from endpoint evidence', () => {
    const sarif = toSarif(
      [makeFinding({ evidence: [{ label: 'Endpoint', details: `${TARGET}/rest/products/search?q=apple` }] })],
      TARGET
    );
    const run = sarif.runs[0] as {
      results: Array<{ locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }>;
    };
    const uri = run.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri;
    expect(uri).toBe('juice-shop:3000/rest/products/search?q=apple');
  });

  it('falls back to the target host when no endpoint evidence is present', () => {
    const sarif = toSarif([makeFinding({ evidence: [] })], TARGET);
    const run = sarif.runs[0] as {
      results: Array<{ locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }>;
    };
    expect(run.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri).toBe('juice-shop:3000');
  });

  it('returns the raw candidate when the location cannot be parsed as a URL', () => {
    const sarif = toSarif([makeFinding({ evidence: [] })], 'not-a-valid-url');
    const run = sarif.runs[0] as {
      results: Array<{ locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }>;
    };
    expect(run.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri).toBe('not-a-valid-url');
  });

  it('carries a stable partial fingerprint per finding for run-to-run tracking', () => {
    const sarif = toSarif([makeFinding({ id: 'HDR-007' })], TARGET);
    const run = sarif.runs[0] as { results: Array<{ partialFingerprints: { findingId: string } }> };
    expect(run.results[0]!.partialFingerprints.findingId).toBe('HDR-007');
  });
});
