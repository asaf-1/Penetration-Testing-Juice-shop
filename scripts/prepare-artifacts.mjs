import fs from 'node:fs';

for (const directory of ['reports', 'reports/evidence', 'test-results', 'playwright-report']) {
  fs.mkdirSync(directory, { recursive: true });
}

