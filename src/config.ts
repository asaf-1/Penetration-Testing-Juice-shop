import path from 'node:path';

export interface AuditConfig {
  targetUrl: string;
  reportsDir: string;
  evidenceDir: string;
}

export function loadAuditConfig(): AuditConfig {
  const reportsDir = path.resolve(process.env.REPORTS_DIR ?? 'reports');

  return {
    targetUrl: process.env.TARGET_URL ?? 'http://localhost:3000',
    reportsDir,
    evidenceDir: path.join(reportsDir, 'evidence')
  };
}
