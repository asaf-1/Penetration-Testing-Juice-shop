import type { BrowserContext } from '@playwright/test';
import type { Finding, Severity } from './audit-report';

export interface HeaderRule {
  id: string;
  header: string;
  alternate?: 'content-security-policy frame-ancestors';
  severity: Severity;
  title: string;
  impact: string;
  remediation: string;
  httpsOnly?: boolean;
}

export interface ApiAuthorizationCheck {
  path: string;
  label: string;
  expectedProtected: boolean;
  sensitivePattern?: RegExp;
}

export const headerRules: HeaderRule[] = [
  {
    id: 'HDR-001',
    header: 'content-security-policy',
    severity: 'Medium',
    title: 'Content-Security-Policy header is missing',
    impact: 'If an injection bug exists, the browser has fewer policy-level controls to reduce script execution impact.',
    remediation: 'Deploy a restrictive Content-Security-Policy and tune it with report-only mode before enforcing it in production.'
  },
  {
    id: 'HDR-002',
    header: 'x-frame-options',
    alternate: 'content-security-policy frame-ancestors',
    severity: 'Low',
    title: 'Clickjacking protection header is missing',
    impact: 'The application may be framed by another site unless frame restrictions are enforced elsewhere.',
    remediation: 'Set CSP frame-ancestors or X-Frame-Options according to the application framing requirements.'
  },
  {
    id: 'HDR-003',
    header: 'referrer-policy',
    severity: 'Low',
    title: 'Referrer-Policy header is missing',
    impact: 'URLs and path data can leak to third-party origins through the Referer header.',
    remediation: 'Set Referrer-Policy to a least-privilege value such as strict-origin-when-cross-origin.'
  },
  {
    id: 'HDR-004',
    header: 'permissions-policy',
    severity: 'Info',
    title: 'Permissions-Policy header is missing',
    impact: 'Browser features such as camera, microphone, and geolocation are not centrally restricted by policy.',
    remediation: 'Set Permissions-Policy to explicitly disable browser features the app does not use.'
  },
  {
    id: 'HDR-006',
    header: 'strict-transport-security',
    severity: 'Medium',
    title: 'HTTP Strict Transport Security header is missing',
    impact: 'Browsers are not instructed to require HTTPS on future visits.',
    remediation: 'Serve the application over HTTPS and set Strict-Transport-Security with an appropriate max-age.',
    httpsOnly: true
  }
];

export const sensitivePathChecks = [
  { path: '/.env', label: 'Environment file', sensitive: true },
  { path: '/config.json', label: 'Configuration file', sensitive: true },
  { path: '/backup.zip', label: 'Backup archive', sensitive: true },
  { path: '/robots.txt', label: 'Robots file', sensitive: false },
  { path: '/security.txt', label: 'Security contact file', sensitive: false },
  { path: '/api-docs', label: 'API documentation', sensitive: true },
  { path: '/swagger.json', label: 'Swagger schema', sensitive: true }
];

export const unauthenticatedRoutes = [
  { route: '/basket', label: 'Basket', expectedProtected: true },
  { route: '/administration', label: 'Administration', expectedProtected: true },
  { route: '/profile', label: 'Profile', expectedProtected: true },
  { route: '/order-history', label: 'Order History', expectedProtected: true }
];

export const unauthenticatedApiChecks: ApiAuthorizationCheck[] = [
  {
    path: '/api/Users',
    label: 'Users API',
    expectedProtected: true,
    sensitivePattern: /email|password|role|token|totp|secret/i
  },
  {
    path: '/api/BasketItems',
    label: 'Basket Items API',
    expectedProtected: true,
    sensitivePattern: /basket|product|quantity|user/i
  },
  {
    path: '/api/Complaints',
    label: 'Complaints API',
    expectedProtected: true,
    sensitivePattern: /complaint|message|email|user/i
  },
  {
    path: '/rest/basket/1',
    label: 'Specific Basket API',
    expectedProtected: true,
    sensitivePattern: /basket|product|quantity|user/i
  },
  {
    path: '/rest/admin/application-configuration',
    label: 'Admin Configuration API',
    expectedProtected: true,
    sensitivePattern: /config|admin|captcha|application|privacy|security/i
  },
  {
    path: '/rest/user/whoami',
    label: 'Current User API',
    expectedProtected: false,
    sensitivePattern: /email|token|password|role/i
  }
];

export function missingHeaderFinding(headers: Record<string, string>, rule: HeaderRule, targetUrl: string): Finding | null {
  if (rule.httpsOnly && new URL(targetUrl).protocol !== 'https:') {
    return null;
  }

  const hasHeader = Boolean(headers[rule.header]);
  const hasAlternate =
    rule.alternate === 'content-security-policy frame-ancestors' &&
    Boolean(headers['content-security-policy']?.toLowerCase().includes('frame-ancestors'));

  if (hasHeader || hasAlternate) {
    return null;
  }

  return {
    id: rule.id,
    title: rule.title,
    severity: rule.severity,
    category: 'Header Hardening',
    status: 'observed',
    description: `The ${rule.header} response header was not present on the initial target response.`,
    impact: rule.impact,
    remediation: rule.remediation,
    evidence: [{ label: 'Missing header', details: rule.header }]
  };
}

export function corsFinding(headers: Record<string, string>): Finding | null {
  const allowOrigin = headers['access-control-allow-origin'];
  const allowCredentials = headers['access-control-allow-credentials'];

  if (allowOrigin === '*' && allowCredentials?.toLowerCase() === 'true') {
    return {
      id: 'HDR-007',
      title: 'CORS allows wildcard origins with credentials',
      severity: 'High',
      category: 'Header Hardening',
      status: 'observed',
      description: 'The response combines a wildcard Access-Control-Allow-Origin value with credentialed requests.',
      impact: 'A hostile origin could read authenticated responses if browsers accepted this policy combination.',
      remediation: 'Use an explicit allowlist of trusted origins and avoid credentialed wildcard CORS policies.',
      evidence: [
        { label: 'Access-Control-Allow-Origin', details: allowOrigin },
        { label: 'Access-Control-Allow-Credentials', details: allowCredentials }
      ],
      references: ['https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny']
    };
  }

  if (allowOrigin === '*') {
    return {
      id: 'HDR-007',
      title: 'CORS wildcard origin is enabled',
      severity: 'Low',
      category: 'Header Hardening',
      status: 'manual-review',
      description: 'The response allows requests from any origin.',
      impact: 'Wildcard CORS can unintentionally expose public APIs to browser-based cross-origin access.',
      remediation: 'Confirm this is intentional for public resources or restrict CORS to trusted origins.',
      evidence: [{ label: 'Access-Control-Allow-Origin', details: allowOrigin }]
    };
  }

  return null;
}

export async function cookieFindings(context: BrowserContext, targetUrl: string): Promise<Finding[]> {
  const cookies = await context.cookies(targetUrl);

  if (cookies.length === 0) {
    return [
      {
        id: 'CK-001',
        title: 'No browser cookies observed',
        severity: 'Info',
        category: 'Session Management',
        status: 'not-observed',
        description: 'No cookies were set during the unauthenticated browser flow.',
        impact: 'No cookie flag issues can be evaluated until a session cookie is issued.',
        remediation: 'When authenticated flows are added, assert HttpOnly, Secure over HTTPS, and SameSite on session cookies.',
        evidence: [{ label: 'Cookie count', details: '0' }]
      }
    ];
  }

  const findings: Finding[] = [];
  const missingHttpOnly = cookies.filter((cookie) => !cookie.httpOnly).map((cookie) => cookie.name);
  const missingSameSite = cookies.filter((cookie) => cookie.sameSite === 'None').map((cookie) => cookie.name);
  const isHttps = new URL(targetUrl).protocol === 'https:';
  const missingSecure = isHttps ? cookies.filter((cookie) => !cookie.secure).map((cookie) => cookie.name) : [];

  if (missingHttpOnly.length > 0) {
    findings.push({
      id: 'CK-001',
      title: 'Cookies missing HttpOnly flag',
      severity: 'Low',
      category: 'Session Management',
      status: 'observed',
      description: 'One or more cookies are readable by client-side JavaScript.',
      impact: 'If an XSS flaw exists, JavaScript-readable cookies are easier to steal.',
      remediation: 'Set HttpOnly on session and sensitive cookies.',
      evidence: [{ label: 'Cookie names', details: missingHttpOnly.join(', ') }]
    });
  }

  if (missingSecure.length > 0) {
    findings.push({
      id: 'CK-002',
      title: 'HTTPS cookies missing Secure flag',
      severity: 'Medium',
      category: 'Session Management',
      status: 'observed',
      description: 'One or more cookies on an HTTPS target are not marked Secure.',
      impact: 'Cookies without Secure can be sent over cleartext HTTP if an HTTP endpoint is reachable.',
      remediation: 'Set Secure on all session and sensitive cookies when served over HTTPS.',
      evidence: [{ label: 'Cookie names', details: missingSecure.join(', ') }]
    });
  }

  if (missingSameSite.length > 0) {
    findings.push({
      id: 'CK-003',
      title: 'Cookies allow cross-site sending',
      severity: 'Low',
      category: 'Session Management',
      status: 'manual-review',
      description: 'One or more cookies use SameSite=None.',
      impact: 'Cross-site cookie sending can increase CSRF exposure if state-changing endpoints lack CSRF controls.',
      remediation: 'Use SameSite=Lax or Strict where possible and require CSRF tokens for state-changing requests.',
      evidence: [{ label: 'Cookie names', details: missingSameSite.join(', ') }]
    });
  }

  return findings.length > 0
    ? findings
    : [
        {
          id: 'CK-000',
          title: 'Observed cookies have baseline flags',
          severity: 'Info',
          category: 'Session Management',
          status: 'not-observed',
          description: 'No missing baseline cookie flags were observed for cookies issued during this run.',
          impact: 'Cookie flags looked acceptable for the unauthenticated browser flow.',
          remediation: 'Continue checking authenticated session cookies in future test coverage.',
          evidence: [{ label: 'Cookie names', details: cookies.map((cookie) => cookie.name).join(', ') }]
        }
      ];
}
