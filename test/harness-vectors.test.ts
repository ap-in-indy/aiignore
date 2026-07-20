import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';

interface HarnessVectors {
  revision: string;
  uri: string;
  harness: string;
  cases: Array<{
    id: string;
    resource: string;
    operation: string;
    level: string;
    expectation: string;
  }>;
}

interface Report {
  status: 'provisional' | 'verified' | 'withdrawn';
  vectorsRevision: string;
  vectorsUri: string;
  vectorsSha256: string;
  harness: { name: string };
  results: Array<{ id: string; resource: string; operation: string; level: string }>;
}

const harnessSchema = JSON.parse(
  readFileSync(new URL('../schema/harness-vectors.schema.json', import.meta.url), 'utf8')
) as object;
const validateHarnessVectors = new Ajv2020({ allErrors: true, strict: true }).compile(
  harnessSchema
);
const vectorsDirectory = new URL('../conformance/vectors/', import.meta.url);
const reportDirectory = new URL('../conformance/results/', import.meta.url);

describe('live harness vector provenance', () => {
  it('validates every plan and requires unique case IDs', () => {
    const files = readdirSync(vectorsDirectory).filter((file) => file.endsWith('.json'));
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const value = JSON.parse(readFileSync(new URL(file, vectorsDirectory), 'utf8')) as HarnessVectors;
      expect(validateHarnessVectors(value), `${file}: ${JSON.stringify(validateHarnessVectors.errors)}`).toBe(
        true
      );
      expect(new Set(value.cases.map((testCase) => testCase.id)).size).toBe(value.cases.length);
    }
  });

  it('binds every executable Codex case to the exact published plan', () => {
    const plan = JSON.parse(
      readFileSync(new URL('../conformance/vectors/codex-sandbox-v0.1.json', import.meta.url), 'utf8')
    ) as HarnessVectors;
    const runner = readFileSync(new URL('../testbed/codex/run-live.mjs', import.meta.url), 'utf8');
    for (const testCase of plan.cases) {
      expect(runner).toContain(`id: '${testCase.id}'`);
      expect(runner).toContain(`expectation: '${testCase.expectation}'`);
    }
    expect(runner).toContain("'conformance', 'vectors', 'codex-sandbox-v0.1.json'");
    expect(runner).not.toContain("'test', 'conformance', 'v0.1.json'");
  });

  it('requires every current live report to hash its exact harness plan', () => {
    const plans = readdirSync(vectorsDirectory)
      .filter((file) => file.endsWith('.json'))
      .map((file) => {
        const bytes = readFileSync(new URL(file, vectorsDirectory));
        return {
          document: JSON.parse(bytes.toString('utf8')) as HarnessVectors,
          sha256: createHash('sha256').update(bytes).digest('hex')
        };
      });
    const reports = readdirSync(reportDirectory).filter((file) => file.endsWith('.json'));
    for (const file of reports) {
      const report = JSON.parse(readFileSync(new URL(file, reportDirectory), 'utf8')) as Report;
      if (report.status === 'withdrawn') continue;
      const plan = plans.find(({ sha256 }) => sha256 === report.vectorsSha256);
      expect(plan, `${file}: no harness plan has the reported SHA-256`).toBeDefined();
      expect(report.vectorsRevision).toBe(plan?.document.revision);
      expect(report.vectorsUri).toBe(plan?.document.uri);
      expect(report.harness.name).toBe(plan?.document.harness);
      expect(new Set(report.results.map((result) => result.id)).size).toBe(report.results.length);
      expect(report.results.map((result) => result.id).sort()).toEqual(
        plan?.document.cases.map((testCase) => testCase.id).sort()
      );
      for (const result of report.results) {
        const plannedCase = plan?.document.cases.find((testCase) => testCase.id === result.id);
        expect(result).toMatchObject({
          resource: plannedCase?.resource,
          operation: plannedCase?.operation,
          level: plannedCase?.level
        });
      }
    }
  });
});
