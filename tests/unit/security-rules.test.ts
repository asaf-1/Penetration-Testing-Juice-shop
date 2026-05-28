import { describe, expect, it } from 'vitest';
import type { BrowserContext } from '@playwright/test';
import { cookieFindings, corsFinding, headerRules, missingHeaderFinding } from '../../src/security-rules';

type Cookie = Awaited<ReturnType<BrowserContext['cookies']>>[number];

/** Minimal BrowserContext stub exposing only the cookies() method under test. */
function fakeContext(cookies: Partial<Cookie>[]): BrowserContext {
  return {
    cookies: async () => cookies as Cookie[]
  } as unknown as BrowserContext;
}

const cspRule = headerRules.find((rule) => rule.header === 'content-security-policy')!;
const frameRule = headerRules.find((rule) => rule.header === 'x-frame-options')!;
const hstsRule = headerRules.find((rule) => rule.header === 'strict-transport-security')!;

describe('missingHeaderFinding', () => {
  it('returns a finding when the header is absent', () => {
    const finding = missingHeaderFinding({}, cspRule, 'http://localhost:3000');
    expect(finding?.id).toBe('HDR-001');
    expect(finding?.severity).toBe('Medium');
  });

  it('returns null when the header is present', () => {
    const finding = missingHeaderFinding(
      { 'content-security-policy': "default-src 'self'" },
      cspRule,
      'http://localhost:3000'
    );
    expect(finding).toBeNull();
  });

  it('accepts the CSP frame-ancestors alternate for the clickjacking rule', () => {
    const finding = missingHeaderFinding(
      { 'content-security-policy': "frame-ancestors 'none'" },
      frameRule,
      'http://localhost:3000'
    );
    expect(finding).toBeNull();
  });

  it('skips HTTPS-only rules on plain HTTP targets', () => {
    expect(missingHeaderFinding({}, hstsRule, 'http://localhost:3000')).toBeNull();
    expect(missingHeaderFinding({}, hstsRule, 'https://example.test')?.id).toBe('HDR-006');
  });
});

describe('corsFinding', () => {
  it('flags wildcard origin with credentials as High', () => {
    const finding = corsFinding({
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true'
    });
    expect(finding?.severity).toBe('High');
  });

  it('flags a plain wildcard origin as Low / manual-review', () => {
    const finding = corsFinding({ 'access-control-allow-origin': '*' });
    expect(finding?.severity).toBe('Low');
    expect(finding?.status).toBe('manual-review');
  });

  it('returns null for a scoped origin', () => {
    expect(corsFinding({ 'access-control-allow-origin': 'https://trusted.test' })).toBeNull();
  });
});

describe('cookieFindings', () => {
  it('reports an Info finding when no cookies are issued', async () => {
    const findings = await cookieFindings(fakeContext([]), 'http://localhost:3000');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe('Info');
    expect(findings[0]!.status).toBe('not-observed');
  });

  it('flags cookies missing HttpOnly', async () => {
    const findings = await cookieFindings(
      fakeContext([{ name: 'session', httpOnly: false, secure: true, sameSite: 'Lax' }]),
      'http://localhost:3000'
    );
    expect(findings.some((finding) => finding.id === 'CK-001' && finding.title.includes('HttpOnly'))).toBe(
      true
    );
  });

  it('flags Secure only on HTTPS targets', async () => {
    const overHttp = await cookieFindings(
      fakeContext([{ name: 'session', httpOnly: true, secure: false, sameSite: 'Lax' }]),
      'http://localhost:3000'
    );
    expect(overHttp.some((finding) => finding.id === 'CK-002')).toBe(false);

    const overHttps = await cookieFindings(
      fakeContext([{ name: 'session', httpOnly: true, secure: false, sameSite: 'Lax' }]),
      'https://example.test'
    );
    expect(overHttps.some((finding) => finding.id === 'CK-002')).toBe(true);
  });

  it('flags SameSite=None cookies', async () => {
    const findings = await cookieFindings(
      fakeContext([{ name: 'session', httpOnly: true, secure: true, sameSite: 'None' }]),
      'https://example.test'
    );
    expect(findings.some((finding) => finding.id === 'CK-003')).toBe(true);
  });

  it('returns a clean baseline finding when all flags are present', async () => {
    const findings = await cookieFindings(
      fakeContext([{ name: 'session', httpOnly: true, secure: true, sameSite: 'Lax' }]),
      'https://example.test'
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.id).toBe('CK-000');
  });
});
