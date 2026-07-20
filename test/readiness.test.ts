import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parsePolicy } from '../src/parser.js';
import { assessReadiness } from '../src/readiness.js';
import { validateReadinessReportSchema } from '../src/schema.js';
import { policy } from './helpers.js';

describe('secret-safe operator readiness assessment', () => {
  it('reports permissive defaults and absent control families without claiming enforcement', () => {
    const report = assessReadiness(policy('aiignore: "0.1"\n'));
    expect(report).toMatchObject({
      formatVersion: '0.1',
      policyValid: true,
      deploymentEnforcement: 'not-established',
      defaults: { files: 'allow', environment: 'allow', network: 'allow', strings: 'allow' },
      ruleCounts: { files: 0, environment: 0, network: 0, strings: 0 },
      controlCounts: {
        fileDeny: 0,
        environmentFilter: 0,
        networkDeny: 0,
        networkAllow: 0,
        stringBoundary: 0
      }
    });
    expect(report.findings.map(({ id }) => id)).toEqual([
      'deployment-not-established',
      'repository-policy-not-administrator-control',
      'network-default-allow',
      'no-file-deny-rules',
      'no-environment-filter-rules',
      'no-string-boundary-rules',
      'codex-compilation-partial'
    ]);
    expect(validateReadinessReportSchema(report)).toEqual([]);
  });

  it('summarizes the complete example without echoing policy match material', () => {
    const bytes = readFileSync(new URL('../examples/complete.aiignore.yaml', import.meta.url));
    const report = assessReadiness(parsePolicy(bytes, '/workspace/.aiignore.yaml'));
    expect(report.defaults.network).toBe('deny');
    expect(report.ruleCounts).toEqual({ files: 2, environment: 2, network: 3, strings: 2 });
    expect(report.controlCounts).toEqual({
      fileDeny: 1,
      environmentFilter: 2,
      networkDeny: 1,
      networkAllow: 2,
      stringBoundary: 2
    });
    expect(report.findings.map(({ id }) => id)).not.toContain('network-default-allow');
    expect(report.adapters.codex.compilationExact).toBe(false);
    expect(report.adapters.gemini.compilationExact).toBe(false);
    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain('AIIGNORE_TEST_SECRET_DO_NOT_USE');
    expect(serialized).not.toContain('secrets/**');
    expect(serialized).not.toContain('/workspace');
  });

  it('does not warn that a default-deny family lacks explicit restrictive rules', () => {
    const report = assessReadiness(
      policy(
        'aiignore: "0.1"\ndefaults: {files: deny, environment: deny, network: deny, strings: deny}\n'
      )
    );
    const ids = report.findings.map(({ id }) => id);
    expect(ids).not.toContain('network-default-allow');
    expect(ids).not.toContain('no-file-deny-rules');
    expect(ids).not.toContain('no-environment-filter-rules');
    expect(ids).not.toContain('no-string-boundary-rules');
  });

  it('never serializes sensitive string patterns or adapter gap detail', () => {
    const secret = 'DO_NOT_EXPOSE_THIS_POLICY_LITERAL';
    const report = assessReadiness(
      policy(`aiignore: "0.1"
rules:
  strings:
    - id: sensitive-pattern
      effect: deny
      patterns: [{type: literal, value: ${secret}}]
`)
    );
    expect(JSON.stringify(report)).not.toContain(secret);
    expect(report.adapters.codex.errorGaps).toBeGreaterThan(0);
    expect(report.findings).toContainEqual(
      expect.objectContaining({ id: 'codex-compilation-partial' })
    );
  });

  it('rejects extension fields and false deployment claims', () => {
    const report = assessReadiness(policy('aiignore: "0.1"\n'));
    expect(validateReadinessReportSchema({ ...report, vendor: 'claim' })).not.toEqual([]);
    expect(
      validateReadinessReportSchema({ ...report, deploymentEnforcement: 'established' })
    ).not.toEqual([]);
    expect(
      validateReadinessReportSchema({
        ...report,
        findings: report.findings.map((finding, index) =>
          index === 0 ? { ...finding, severity: 'info', message: 'ready' } : finding
        )
      })
    ).not.toEqual([]);
  });

  it('fails closed if an invalid loaded-policy object reaches report assembly', () => {
    const loaded = policy('aiignore: "0.1"\n');
    expect(() => assessReadiness({ ...loaded, digest: 'invalid' })).toThrow(
      expect.objectContaining({ code: 'readiness_schema_validation' })
    );
  });
});
