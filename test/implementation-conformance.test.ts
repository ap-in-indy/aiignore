import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  assertImplementationConformanceReport,
  createReferenceConformanceReport,
  verifyImplementationConformanceBundle
} from '../src/implementation-conformance.js';
import {
  IMPLEMENTATION_CONFORMANCE_REPORT_MEDIA_TYPE,
  signConformanceReport,
  verifyConformanceReport
} from '../src/report-signature.js';
import { validateImplementationConformanceReportSchema } from '../src/schema.js';
import type { ImplementationConformanceReport } from '../src/types.js';
import { createMinimalConformanceBundle } from './helpers.js';

let baseReport: ImplementationConformanceReport;
let minimalManifestPath = '';

describe('implementation conformance reports', () => {
  beforeAll(() => {
    minimalManifestPath = createMinimalConformanceBundle(
      mkdtempSync(path.join(tmpdir(), 'aiignore-minimal-conformance-'))
    );
    baseReport = generateReferenceReport();
  });

  it('runs every parser and decision suite bound by the canonical manifest', () => {
    const report = structuredClone(baseReport);
    expect(report).toMatchObject({
      reportVersion: '0.1',
      reportType: 'implementation',
      status: 'provisional',
      specification: '0.1',
      implementation: { classification: 'reference', sourceTreeDirty: false },
      summary: { total: 2, passed: 2, failed: 0, conformant: true }
    });
    expect(report.suites).toHaveLength(2);
    expect(report.suites.filter(({ kind }) => kind === 'parser')).toHaveLength(1);
    expect(report.suites.filter(({ kind }) => kind === 'decision')).toHaveLength(1);
    expect(validateImplementationConformanceReportSchema(report)).toEqual([]);
    expect(
      validateImplementationConformanceReportSchema({ ...report, limitations: [] })
    ).not.toEqual([]);
    expect(
      validateImplementationConformanceReportSchema({
        ...report,
        runner: { ...report.runner, name: 'independent-runner' }
      })
    ).toEqual([]);
    expect(report.limitations.join(' ')).toContain('does not establish harness');
  });

  it('verifies exact manifest binding and complete suite membership offline', () => {
    const bytes = reportBytes(baseReport);
    expect(verifyImplementationConformanceBundle(bytes, minimalManifestPath)).toMatchObject({
      valid: true,
      reportSha256: createHash('sha256').update(bytes).digest('hex'),
      status: 'provisional',
      conformant: true,
      suites: 2
    });

    const root = mkdtempSync(path.join(tmpdir(), 'aiignore-incomplete-report-'));
    const manifestPath = createMinimalConformanceBundle(root, 2);
    const complete = generateReferenceReport({ manifestPath });
    const incomplete: ImplementationConformanceReport = {
      ...complete,
      suites: complete.suites.slice(0, -1),
      summary: { total: 2, passed: 2, failed: 0, conformant: true }
    };
    assertImplementationConformanceReport(incomplete);
    expect(() =>
      verifyImplementationConformanceBundle(reportBytes(incomplete), manifestPath)
    ).toThrow(/does not contain every manifest-selected vector suite/u);

    const wrongIdentity: ImplementationConformanceReport = {
      ...structuredClone(baseReport),
      suites: baseReport.suites.map((suite, index) =>
        index === 0 ? { ...suite, vectorsSha256: 'f'.repeat(64) } : suite
      )
    };
    expect(() =>
      verifyImplementationConformanceBundle(reportBytes(wrongIdentity), minimalManifestPath)
    ).toThrow(/suite identity does not match/u);

    const wrongCaseCount: ImplementationConformanceReport = {
      ...structuredClone(baseReport),
      suites: baseReport.suites.map((suite, index) =>
        index === 0 ? { ...suite, total: 0, passed: 0 } : suite
      ),
      summary: { total: 1, passed: 1, failed: 0, conformant: true }
    };
    assertImplementationConformanceReport(wrongCaseCount);
    expect(() =>
      verifyImplementationConformanceBundle(reportBytes(wrongCaseCount), minimalManifestPath)
    ).toThrow(/case inventory does not match/u);
  });

  it('rejects malformed, oversized, and differently bound implementation reports', () => {
    for (const bytes of [Buffer.from('{'), Buffer.from([0xff])]) {
      expect(() => verifyImplementationConformanceBundle(bytes, minimalManifestPath)).toThrow();
    }
    expect(() =>
      verifyImplementationConformanceBundle(Buffer.alloc(4 * 1024 * 1024 + 1), minimalManifestPath)
    ).toThrow(/exceeds/u);
    const mismatched: ImplementationConformanceReport = {
      ...structuredClone(baseReport),
      conformanceBundle: { ...baseReport.conformanceBundle, sha256: '0'.repeat(64) }
    };
    expect(() =>
      verifyImplementationConformanceBundle(reportBytes(mismatched), minimalManifestPath)
    ).toThrow(/does not bind the supplied conformance manifest/u);
  });

  it('rejects invalid dates, extension fields, inconsistent totals, and duplicate suites', () => {
    expect(() => referenceReport({ date: 'not-a-date' })).toThrow(/YYYY-MM-DD/u);
    expect(() => referenceReport({ date: '2026-02-30' })).toThrow(/calendar date/u);
    const report = structuredClone(baseReport);
    expect(
      validateImplementationConformanceReportSchema({ ...report, certified: true })
    ).not.toEqual([]);
    expect(() =>
      assertImplementationConformanceReport({
        ...report,
        suites: report.suites.map((suite, index) =>
          index === 0 ? { ...suite, conformant: false } : suite
        )
      })
    ).toThrow(/suite totals are inconsistent/u);
    expect(() =>
      assertImplementationConformanceReport({
        ...report,
        summary: { ...report.summary, passed: report.summary.passed - 1 }
      })
    ).toThrow(/summary is inconsistent/u);
    expect(() =>
      assertImplementationConformanceReport({
        ...report,
        suites: [...report.suites, report.suites[1]!]
      })
    ).toThrow(/repeats a vector suite URI/u);
    expect(() =>
      assertImplementationConformanceReport({ ...report, vendor: true } as unknown as ImplementationConformanceReport)
    ).toThrow(/implementation conformance report:/u);
  });

  it('fails before execution when manifest-bound vector bytes drift', () => {
    const root = mkdtempSync(path.join(tmpdir(), 'aiignore-implementation-report-'));
    const copiedManifest = createMinimalConformanceBundle(root);
    const original = readManifest(copiedManifest);
    const decision = original.artifacts.find(({ role }) => role === 'decision-vectors');
    if (!decision) throw new Error('fixture manifest must include decision vectors');
    decision.sha256 = '0'.repeat(64);
    writeFileSync(copiedManifest, JSON.stringify(original));
    expect(() => referenceReport({ manifestPath: copiedManifest })).toThrow(
      /digest does not match/u
    );
  });

  it('rejects malformed manifests, incomplete inventories, duplicates, and identity drift', () => {
    for (const bytes of ['{', Buffer.from([0xff]), '{}']) {
      const root = mkdtempSync(path.join(tmpdir(), 'aiignore-invalid-manifest-'));
      const manifest = createMinimalConformanceBundle(root);
      writeFileSync(manifest, bytes);
      expect(() => referenceReport({ manifestPath: manifest })).toThrow();
    }

    const missingRoot = mkdtempSync(path.join(tmpdir(), 'aiignore-missing-vectors-'));
    const missingManifest = createMinimalConformanceBundle(missingRoot);
    const missing = readManifest(missingManifest);
    missing.artifacts = missing.artifacts.filter(({ role }) => role !== 'parser-vectors');
    writeFileSync(missingManifest, JSON.stringify(missing));
    expect(() => referenceReport({ manifestPath: missingManifest })).toThrow(
      /exactly one parser vector pack/u
    );

    const duplicateRoot = mkdtempSync(path.join(tmpdir(), 'aiignore-duplicate-vectors-'));
    const duplicateManifest = createMinimalConformanceBundle(duplicateRoot);
    const duplicate = readManifest(duplicateManifest);
    duplicate.artifacts[1]!.uri = duplicate.artifacts[0]!.uri;
    writeFileSync(duplicateManifest, JSON.stringify(duplicate));
    expect(() => referenceReport({ manifestPath: duplicateManifest })).toThrow(
      /repeats artifact uri/u
    );

    const identityRoot = mkdtempSync(path.join(tmpdir(), 'aiignore-vector-identity-'));
    const identityManifest = createMinimalConformanceBundle(identityRoot);
    const identity = readManifest(identityManifest);
    identity.artifacts[1]!.uri = 'https://example.invalid/vectors/changed.json';
    writeFileSync(identityManifest, JSON.stringify(identity));
    expect(() => referenceReport({ manifestPath: identityManifest })).toThrow(
      /executed vector identity/u
    );
  });

  it('retains failed parser and decision case IDs without failure detail', () => {
    const root = mkdtempSync(path.join(tmpdir(), 'aiignore-failing-vectors-'));
    const manifestPath = createMinimalConformanceBundle(root);
    const manifest = readManifest(manifestPath);
    for (const artifact of manifest.artifacts) {
      const artifactPath = path.join(root, artifact.path);
      const vectors = JSON.parse(readFileSync(artifactPath, 'utf8')) as {
        cases: Array<Record<string, unknown>>;
      };
      if (artifact.role === 'parser-vectors') {
        vectors.cases[0]!['valid'] = false;
        vectors.cases[0]!['errorCode'] = 'invalid_yaml';
      } else {
        vectors.cases[0]!['effect'] = 'deny';
      }
      const bytes = `${JSON.stringify(vectors)}\n`;
      writeFileSync(artifactPath, bytes);
      artifact.sha256 = createHash('sha256').update(bytes).digest('hex');
    }
    writeFileSync(manifestPath, JSON.stringify(manifest));
    const report = referenceReport({ manifestPath });
    expect(report.summary).toEqual({ total: 2, passed: 0, failed: 2, conformant: false });
    expect(report.suites.map(({ failedCaseIds }) => failedCaseIds)).toEqual([
      ['valid-minimal'],
      ['default-file-allow']
    ]);
    expect(JSON.stringify(report)).not.toContain('invalid_yaml');
  });

  it('signs implementation evidence with a distinct payload type and trust pins', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const provisional = {
      ...structuredClone(baseReport),
      evidence: [
        {
          type: 'artifact' as const,
          uri: 'https://example.invalid/evidence/implementation-run.json',
          sha256: '3'.repeat(64)
        }
      ]
    };
    const signed = signConformanceReport(
      Buffer.from(`${JSON.stringify(provisional)}\n`),
      privateKey.export({ type: 'pkcs8', format: 'pem' }),
      {
        identity: 'https://example.invalid/implementer',
        envelopeUri: 'https://example.invalid/implementation.signature.json'
      }
    );
    expect(signed.payloadType).toBe(IMPLEMENTATION_CONFORMANCE_REPORT_MEDIA_TYPE);
    expect(
      verifyConformanceReport(signed.reportBytes, signed.envelopeBytes, {
        expectedIdentity: 'https://example.invalid/implementer',
        expectedPublicKeySha256: signed.publicKeySha256
      })
    ).toMatchObject({
      verified: true,
      payloadType: IMPLEMENTATION_CONFORMANCE_REPORT_MEDIA_TYPE
    });

    expect(() =>
      signConformanceReport(
        Buffer.from(
          JSON.stringify({
            ...provisional,
            implementation: { ...provisional.implementation, sourceTreeDirty: true }
          })
        ),
        privateKey.export({ type: 'pkcs8', format: 'pem' }),
        {
          identity: 'https://example.invalid/implementer',
          envelopeUri: 'https://example.invalid/implementation.signature.json'
        }
      )
    ).toThrow(/dirty source tree/u);
  });
});

function generateReferenceReport(
  overrides: Partial<Parameters<typeof createReferenceConformanceReport>[0]> = {}
): ImplementationConformanceReport {
  return createReferenceConformanceReport({
    manifestPath: minimalManifestPath,
    date: '2026-07-16',
    sourceUri: 'https://example.invalid/aiignore-source.tgz',
    sourceRevision: '7162933f520e89ea024467ddb0807c2208a4d2b8',
    sourceSha256: '1'.repeat(64),
    sourceTreeDirty: false,
    runnerVersion: '0.1.0-alpha.1',
    runnerSha256: '2'.repeat(64),
    ...overrides
  });
}

function referenceReport(
  overrides: Partial<Parameters<typeof createReferenceConformanceReport>[0]> = {}
): ImplementationConformanceReport {
  return Object.keys(overrides).length === 0
    ? structuredClone(baseReport)
    : generateReferenceReport(overrides);
}

function readManifest(filename: string): {
  artifacts: Array<{ id: string; role: string; path: string; uri: string; sha256: string }>;
  [key: string]: unknown;
} {
  return JSON.parse(readFileSync(filename, 'utf8')) as {
    artifacts: Array<{ id: string; role: string; path: string; uri: string; sha256: string }>;
    [key: string]: unknown;
  };
}

function reportBytes(report: ImplementationConformanceReport): Buffer {
  return Buffer.from(`${JSON.stringify(report)}\n`);
}
