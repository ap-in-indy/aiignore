import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    testTimeout: 10_000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary', 'lcov'],
      include: ['src/**/*.ts'],
      thresholds: {
        branches: 86,
        functions: 99,
        lines: 96,
        statements: 95
      }
    }
  }
});
