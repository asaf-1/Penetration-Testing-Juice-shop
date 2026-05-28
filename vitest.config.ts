import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Vitest owns the fast, pure unit tests. The Playwright end-to-end specs
    // (tests/*.spec.ts) are run separately by `npm run audit`.
    include: ['tests/unit/**/*.test.ts'],
    environment: 'node',
    coverage: {
      provider: 'v8',
      reportsDirectory: 'coverage',
      reporter: ['text', 'html', 'lcov'],
      // Cover the pure, unit-testable modules. The reporter is an HTML/string
      // builder exercised end-to-end by the Playwright audit instead.
      include: [
        'src/findings.ts',
        'src/sarif.ts',
        'src/security-rules.ts',
        'src/juice-shop-helpers.ts',
        'src/config.ts'
      ],
      thresholds: {
        lines: 85,
        functions: 85,
        statements: 85,
        branches: 80
      }
    }
  }
});
