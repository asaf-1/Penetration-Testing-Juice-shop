import { describe, expect, it } from 'vitest';
import {
  cleanFileName,
  countBySeverity,
  deduplicateFindings,
  severityOrder,
  sortFindings,
  type Finding
} from '../../src/findings';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'TEST-001',
    title: 'Example finding',
    severity: 'Low',
    category: 'Header Hardening',
    status: 'observed',
    description: 'description',
    impact: 'impact',
    remediation: 'remediation',
    evidence: [],
    ...overrides
  };
}

describe('sortFindings', () => {
  it('orders by severity (highest first) then by id', () => {
    const sorted = sortFindings([
      makeFinding({ id: 'B', severity: 'Low' }),
      makeFinding({ id: 'A', severity: 'Critical' }),
      makeFinding({ id: 'C', severity: 'Low' }),
      makeFinding({ id: 'A2', severity: 'Medium' })
    ]);

    expect(sorted.map((finding) => finding.id)).toEqual(['A', 'A2', 'B', 'C']);
  });

  it('does not mutate the input array', () => {
    const input = [makeFinding({ id: 'B' }), makeFinding({ id: 'A' })];
    const snapshot = input.map((finding) => finding.id);
    sortFindings(input);
    expect(input.map((finding) => finding.id)).toEqual(snapshot);
  });
});

describe('deduplicateFindings', () => {
  it('collapses findings with the same id and merges new evidence', () => {
    const result = deduplicateFindings([
      makeFinding({ id: 'DUP', evidence: [{ label: 'A', details: '1' }] }),
      makeFinding({ id: 'DUP', evidence: [{ label: 'B', details: '2' }] })
    ]);

    expect(result).toHaveLength(1);
    expect(result[0]!.evidence).toEqual([
      { label: 'A', details: '1' },
      { label: 'B', details: '2' }
    ]);
  });

  it('does not duplicate identical evidence entries', () => {
    const result = deduplicateFindings([
      makeFinding({ id: 'DUP', evidence: [{ label: 'A', details: '1' }] }),
      makeFinding({ id: 'DUP', evidence: [{ label: 'A', details: '1' }] })
    ]);

    expect(result[0]!.evidence).toHaveLength(1);
  });

  it('does not mutate the original findings', () => {
    const original = makeFinding({ id: 'DUP', evidence: [{ label: 'A', details: '1' }] });
    deduplicateFindings([original, makeFinding({ id: 'DUP', evidence: [{ label: 'B', details: '2' }] })]);
    expect(original.evidence).toHaveLength(1);
  });
});

describe('countBySeverity', () => {
  it('counts each severity and zero-fills the rest', () => {
    const counts = countBySeverity([
      makeFinding({ severity: 'High' }),
      makeFinding({ severity: 'High' }),
      makeFinding({ severity: 'Info' })
    ]);

    expect(counts).toEqual({ Critical: 0, High: 2, Medium: 0, Low: 0, Info: 1 });
  });
});

describe('severityOrder', () => {
  it('ranks Critical highest and Info lowest', () => {
    expect(severityOrder.Critical).toBeGreaterThan(severityOrder.High);
    expect(severityOrder.High).toBeGreaterThan(severityOrder.Info);
  });
});

describe('cleanFileName', () => {
  it('lowercases, slugifies, trims dashes, and bounds length', () => {
    expect(cleanFileName('  Hello, World! ')).toBe('hello-world');
    expect(cleanFileName('a'.repeat(200))).toHaveLength(80);
    expect(cleanFileName('***')).toBe('');
  });
});
