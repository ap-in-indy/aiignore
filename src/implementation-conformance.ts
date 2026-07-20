import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { Ajv2020, type ErrorObject } from 'ajv/dist/2020.js';
import { CONFORMANCE_VECTORS_SCHEMA, runConformanceFile } from './conformance.js';
import { SPEC_VERSION } from './constants.js';
import { PolicyError } from './errors.js';
import { PARSER_VECTORS_SCHEMA, runParserConformanceFile } from './parser-conformance.js';
import { readBoundedRegularFile } from './safe-file.js';
import { validateImplementationConformanceReportSchema } from './schema.js';
import type {
  ImplementationConformanceReport,
  ImplementationConformanceSuite
} from './types.js';

const manifestSchema = JSON.parse(
  readFileSync(new URL('../schema/conformance-manifest.schema.json', import.meta.url), 'utf8')
) as object;
const validateManifest = new Ajv2020({
  allErrors: true,
  strict: true,
  validateFormats: false
}).compile<ConformanceManifest>(manifestSchema);
const vectorAjv = new Ajv2020({ allErrors: true, strict: true, validateFormats: false });
const validateDecisionVectors = vectorAjv.compile(CONFORMANCE_VECTORS_SCHEMA);
const validateParserVectors = vectorAjv.compile(PARSER_VECTORS_SCHEMA);

const MAX_MANIFEST_BYTES = 1024 * 1024;
export const MAX_IMPLEMENTATION_REPORT_BYTES = 4 * 1024 * 1024;
const LIMITATION =
  'This report covers restricted-YAML parsing and portable decision semantics only; it does not establish harness, tool, or sandbox enforcement.';
const CLASSIFICATION_LIMITATION =
  'The implementation classification is asserted by the report producer and requires source and provenance review.';

interface ManifestArtifact {
  id: string;
  role:
    | 'specification'
    | 'schema'
    | 'decision-vectors'
    | 'parser-vectors'
    | 'harness-vectors'
    | 'requirements';
  mediaType: string;
  path: string;
  uri: string;
  sha256: string;
}

interface ConformanceManifest {
  formatVersion: '0.1';
  specification: '0.1';
  release: string;
  status: 'experimental';
  uri: string;
  artifacts: ManifestArtifact[];
}

interface LoadedManifest {
  bytes: Uint8Array;
  manifest: ConformanceManifest;
  packageRoot: string;
  vectorArtifacts: ManifestArtifact[];
}

export interface CreateReferenceConformanceReportOptions {
  readonly manifestPath: string;
  readonly date: string;
  readonly sourceUri: string;
  readonly sourceRevision: string;
  readonly sourceSha256: string;
  readonly sourceTreeDirty: boolean;
  readonly runnerVersion: string;
  readonly runnerSha256: string;
  readonly limitations?: readonly string[];
}

export interface VerifiedImplementationConformanceBundle {
  readonly valid: true;
  readonly reportSha256: string;
  readonly manifestSha256: string;
  readonly status: ImplementationConformanceReport['status'];
  readonly conformant: boolean;
  readonly suites: number;
}

export function createReferenceConformanceReport(
  options: CreateReferenceConformanceReportOptions
): ImplementationConformanceReport {
  assertCalendarDate(options.date);
  const { bytes: manifestBytes, manifest, packageRoot, vectorArtifacts } =
    loadConformanceManifest(options.manifestPath);

  const suites: ImplementationConformanceSuite[] = vectorArtifacts.map((artifact) => {
    const artifactPath = resolveArtifactPath(packageRoot, artifact.path);
    const artifactBytes = readBoundedRegularFile(artifactPath, {
      maximumBytes: 4 * 1024 * 1024,
      label: 'conformance artifact',
      unreadableCode: 'artifact_unreadable',
      notFileCode: 'not_a_file',
      tooLargeCode: 'artifact_too_large',
      changedCode: 'artifact_changed_during_load'
    });
    if (sha256(artifactBytes) !== artifact.sha256) {
      throw new PolicyError(
        'manifest_artifact_digest_mismatch',
        `conformance artifact digest does not match manifest entry ${artifact.id}`
      );
    }
    if (artifact.role === 'parser-vectors') {
      const run = runParserConformanceFile(artifactPath);
      assertRunIdentity(artifact, run.vectorsUri, run.vectorsSha256);
      return {
        kind: 'parser',
        revision: run.revision,
        vectorsUri: run.vectorsUri,
        vectorsSha256: run.vectorsSha256,
        total: run.total,
        passed: run.passed,
        failedCaseIds: run.failed.map(({ id }) => id),
        conformant: run.conformant
      };
    }
    const run = runConformanceFile(artifactPath);
    assertRunIdentity(artifact, run.vectorsUri, run.vectorsSha256);
    return {
      kind: 'decision',
      revision: run.revision,
      vectorsUri: run.vectorsUri,
      vectorsSha256: run.vectorsSha256,
      policySha256: run.policyDigest,
      total: run.total,
      passed: run.passed,
      failedCaseIds: run.failed.map(({ id }) => id),
      conformant: run.conformant
    };
  });
  const total = suites.reduce((sum, suite) => sum + suite.total, 0);
  const passed = suites.reduce((sum, suite) => sum + suite.passed, 0);
  const report: ImplementationConformanceReport = {
    reportVersion: '0.1',
    reportType: 'implementation',
    status: 'provisional',
    date: options.date,
    specification: SPEC_VERSION,
    conformanceBundle: {
      formatVersion: manifest.formatVersion,
      release: manifest.release,
      uri: manifest.uri,
      sha256: sha256(manifestBytes)
    },
    implementation: {
      name: 'aiignore',
      version: options.runnerVersion,
      language: 'TypeScript',
      classification: 'reference',
      sourceUri: options.sourceUri,
      sourceRevision: options.sourceRevision,
      sourceSha256: options.sourceSha256,
      sourceTreeDirty: options.sourceTreeDirty
    },
    runner: {
      name: 'aiignore',
      version: options.runnerVersion,
      sha256: options.runnerSha256
    },
    suites,
    summary: {
      total,
      passed,
      failed: total - passed,
      conformant: suites.every(({ conformant }) => conformant)
    },
    limitations: [...new Set([LIMITATION, CLASSIFICATION_LIMITATION, ...(options.limitations ?? [])])]
  };
  assertImplementationConformanceReport(report);
  return report;
}

export function verifyImplementationConformanceBundle(
  reportBytes: Uint8Array,
  manifestPath: string
): VerifiedImplementationConformanceBundle {
  const report = parseImplementationReport(reportBytes);
  const { bytes: manifestBytes, manifest, packageRoot, vectorArtifacts } =
    loadConformanceManifest(manifestPath);
  const manifestSha256 = sha256(manifestBytes);
  if (
    report.conformanceBundle.formatVersion !== manifest.formatVersion ||
    report.conformanceBundle.release !== manifest.release ||
    report.conformanceBundle.uri !== manifest.uri ||
    report.conformanceBundle.sha256 !== manifestSha256
  ) {
    throw new PolicyError(
      'implementation_report_bundle_mismatch',
      'implementation report does not bind the supplied conformance manifest'
    );
  }
  if (report.suites.length !== vectorArtifacts.length) {
    throw new PolicyError(
      'implementation_report_suite_inventory',
      'implementation report does not contain every manifest-selected vector suite'
    );
  }
  const suites = new Map(report.suites.map((suite) => [suite.vectorsUri, suite]));
  for (const artifact of vectorArtifacts) {
    const suite = suites.get(artifact.uri);
    const expectedKind = artifact.role === 'parser-vectors' ? 'parser' : 'decision';
    if (!suite || suite.kind !== expectedKind || suite.vectorsSha256 !== artifact.sha256) {
      throw new PolicyError(
        'implementation_report_suite_identity',
        `implementation report suite identity does not match manifest entry ${artifact.id}`
      );
    }
    const artifactPath = resolveArtifactPath(packageRoot, artifact.path);
    const artifactBytes = readBoundedRegularFile(artifactPath, {
      maximumBytes: 4 * 1024 * 1024,
      label: 'conformance artifact',
      unreadableCode: 'artifact_unreadable',
      notFileCode: 'not_a_file',
      tooLargeCode: 'artifact_too_large',
      changedCode: 'artifact_changed_during_load'
    });
    if (sha256(artifactBytes) !== artifact.sha256) {
      throw new PolicyError(
        'manifest_artifact_digest_mismatch',
        `conformance artifact digest does not match manifest entry ${artifact.id}`
      );
    }
    const identity = parseVectorIdentity(artifactBytes, expectedKind);
    if (
      suite.revision !== identity.revision ||
      suite.vectorsUri !== identity.uri ||
      (expectedKind === 'decision' && suite.policySha256 !== identity.policySha256)
    ) {
      throw new PolicyError(
        'implementation_report_suite_identity',
        `implementation report suite content does not match manifest entry ${artifact.id}`
      );
    }
    const caseIds = new Set(identity.caseIds);
    if (
      suite.total !== identity.caseIds.length ||
      suite.failedCaseIds.some((caseId) => !caseIds.has(caseId))
    ) {
      throw new PolicyError(
        'implementation_report_case_inventory',
        `implementation report case inventory does not match manifest entry ${artifact.id}`
      );
    }
  }
  return {
    valid: true,
    reportSha256: sha256(reportBytes),
    manifestSha256,
    status: report.status,
    conformant: report.summary.conformant,
    suites: report.suites.length
  };
}

export function assertImplementationConformanceReport(
  report: ImplementationConformanceReport
): void {
  const errors = validateImplementationConformanceReportSchema(report);
  if (errors.length > 0) {
    throw schemaError(
      'implementation_report_schema_validation',
      'implementation conformance report',
      errors
    );
  }
  assertCalendarDate(report.date);
  const uris = new Set<string>();
  let total = 0;
  let passed = 0;
  for (const suite of report.suites) {
    if (uris.has(suite.vectorsUri)) {
      throw new PolicyError(
        'implementation_report_duplicate_suite',
        'implementation conformance report repeats a vector suite URI'
      );
    }
    uris.add(suite.vectorsUri);
    if (
      suite.passed > suite.total ||
      suite.failedCaseIds.length !== suite.total - suite.passed ||
      suite.conformant !== (suite.passed === suite.total)
    ) {
      throw new PolicyError(
        'implementation_report_inconsistent',
        'implementation conformance suite totals are inconsistent'
      );
    }
    total += suite.total;
    passed += suite.passed;
  }
  if (
    report.summary.total !== total ||
    report.summary.passed !== passed ||
    report.summary.failed !== total - passed ||
    report.summary.conformant !== report.suites.every(({ conformant }) => conformant)
  ) {
    throw new PolicyError(
      'implementation_report_inconsistent',
      'implementation conformance report summary is inconsistent'
    );
  }
}

function parseManifest(bytes: Uint8Array): ConformanceManifest {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new PolicyError('invalid_manifest_encoding', 'conformance manifest is not valid UTF-8');
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new PolicyError('invalid_manifest_json', 'conformance manifest is not valid JSON');
  }
  if (!validateManifest(value)) {
    throw schemaError('manifest_schema_validation', 'conformance manifest', validateManifest.errors ?? []);
  }
  return value;
}

function loadConformanceManifest(manifestPath: string): LoadedManifest {
  const absolutePath = path.resolve(manifestPath);
  const bytes = readBoundedRegularFile(absolutePath, {
    maximumBytes: MAX_MANIFEST_BYTES,
    label: 'conformance manifest',
    unreadableCode: 'manifest_unreadable',
    notFileCode: 'not_a_file',
    tooLargeCode: 'manifest_too_large',
    changedCode: 'manifest_changed_during_load'
  });
  const manifest = parseManifest(bytes);
  assertUniqueManifestArtifacts(manifest.artifacts);
  const vectorArtifacts = manifest.artifacts.filter(
    (artifact) => artifact.role === 'parser-vectors' || artifact.role === 'decision-vectors'
  );
  if (
    vectorArtifacts.filter((artifact) => artifact.role === 'parser-vectors').length !== 1 ||
    vectorArtifacts.every((artifact) => artifact.role !== 'decision-vectors')
  ) {
    throw new PolicyError(
      'manifest_vector_inventory',
      'implementation conformance requires exactly one parser vector pack and at least one decision vector pack'
    );
  }
  return {
    bytes,
    manifest,
    packageRoot: path.resolve(path.dirname(absolutePath), '..'),
    vectorArtifacts
  };
}

function parseImplementationReport(bytes: Uint8Array): ImplementationConformanceReport {
  if (bytes.byteLength > MAX_IMPLEMENTATION_REPORT_BYTES) {
    throw new PolicyError(
      'implementation_report_too_large',
      `implementation report exceeds ${MAX_IMPLEMENTATION_REPORT_BYTES} bytes`
    );
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new PolicyError(
      'invalid_implementation_report_encoding',
      'implementation report is not valid UTF-8'
    );
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new PolicyError(
      'invalid_implementation_report_json',
      'implementation report is not valid JSON'
    );
  }
  assertImplementationConformanceReport(value as ImplementationConformanceReport);
  return value as ImplementationConformanceReport;
}

function parseVectorIdentity(
  bytes: Uint8Array,
  kind: 'parser' | 'decision'
): { revision: string; uri: string; policySha256?: string; caseIds: string[] } {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
  } catch {
    throw new PolicyError('invalid_vectors_json', 'manifest-selected vectors are not valid JSON');
  }
  const validator = kind === 'decision' ? validateDecisionVectors : validateParserVectors;
  if (!validator(value)) {
    throw schemaError(
      'vectors_schema_validation',
      `manifest-selected ${kind} vectors`,
      validator.errors ?? []
    );
  }
  if (
    typeof value !== 'object' ||
    value === null ||
    !('revision' in value) ||
    typeof value.revision !== 'string' ||
    !('uri' in value) ||
    typeof value.uri !== 'string'
  ) {
    throw new PolicyError('invalid_vectors_identity', 'manifest-selected vectors lack an identity');
  }
  const cases = (value as unknown as { cases: Array<{ id: string }> }).cases;
  const caseIds = cases.map(({ id }) => id);
  if (new Set(caseIds).size !== caseIds.length) {
    throw new PolicyError('duplicate_vector_id', 'manifest-selected vectors repeat a case ID');
  }
  if (kind === 'decision') {
    if (!('policy' in value) || typeof value.policy !== 'string') {
      throw new PolicyError(
        'invalid_vectors_identity',
        'manifest-selected decision vectors lack policy bytes'
      );
    }
    return {
      revision: value.revision,
      uri: value.uri,
      policySha256: sha256(Buffer.from(value.policy, 'utf8')),
      caseIds
    };
  }
  return { revision: value.revision, uri: value.uri, caseIds };
}

function assertUniqueManifestArtifacts(artifacts: readonly ManifestArtifact[]): void {
  for (const key of ['id', 'path', 'uri'] as const) {
    const values = new Set<string>();
    for (const artifact of artifacts) {
      if (values.has(artifact[key])) {
        throw new PolicyError(
          'manifest_duplicate_artifact',
          `conformance manifest repeats artifact ${key}`
        );
      }
      values.add(artifact[key]);
    }
  }
}

function resolveArtifactPath(root: string, relativePath: string): string {
  const absolute = path.resolve(root, relativePath);
  const relative = path.relative(root, absolute);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new PolicyError('manifest_artifact_path_escape', 'manifest artifact escapes package root');
  }
  return absolute;
}

function assertRunIdentity(
  artifact: ManifestArtifact,
  vectorsUri: string,
  vectorsSha256: string
): void {
  if (artifact.uri !== vectorsUri || artifact.sha256 !== vectorsSha256) {
    throw new PolicyError(
      'manifest_artifact_identity_mismatch',
      `executed vector identity does not match manifest entry ${artifact.id}`
    );
  }
}

function assertCalendarDate(value: string): void {
  if (!/^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$/u.test(value)) {
    throw new PolicyError('invalid_report_date', 'report date must use YYYY-MM-DD');
  }
  const parsed = new Date(`${value}T00:00:00.000Z`);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString().slice(0, 10) !== value) {
    throw new PolicyError('invalid_report_date', 'report date is not a calendar date');
  }
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function schemaError(code: string, label: string, errors: ErrorObject[]): PolicyError {
  const message = errors
    .slice(0, 20)
    .map((error) => `${error.instancePath || '/'} ${error.message ?? 'is invalid'}`)
    .join('; ');
  const suffix = errors.length > 20 ? `; and ${errors.length - 20} more errors` : '';
  return new PolicyError(code, `${label}: ${message}${suffix}`);
}
