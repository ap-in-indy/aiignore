import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { Ajv2020, type ErrorObject } from 'ajv/dist/2020.js';
import { PolicyEngine } from './engine.js';
import { PolicyError } from './errors.js';
import { parsePolicy } from './parser.js';
import { readBoundedRegularFile } from './safe-file.js';
import { validateDecisionSchema } from './schema.js';
import type { DecisionEffect, FileOperation, Resource, StringScope } from './types.js';

const schemaUrl = new URL('../schema/conformance-vectors.schema.json', import.meta.url);
export const CONFORMANCE_VECTORS_SCHEMA = JSON.parse(readFileSync(schemaUrl, 'utf8')) as object;
export const MAX_VECTOR_BYTES = 4 * 1024 * 1024;
export const MAX_GENERATED_CANDIDATE_BYTES = 8 * 1024 * 1024;

interface ExpectedDecision {
  resource: Resource;
  effect?: DecisionEffect;
  ruleId?: string | null;
  matched?: string | null;
  output?: string;
  appliedRuleIds?: string[];
  errorCode?: string;
}

interface BaseCase extends ExpectedDecision {
  id: string;
  candidate?: string;
  candidateRepeat?: { prefix?: string; text: string; count: number; suffix?: string };
}

type VectorCase =
  | (BaseCase & { resource: 'file'; operation: FileOperation; caseInsensitive?: boolean })
  | (BaseCase & { resource: 'environment'; caseInsensitive?: boolean })
  | (BaseCase & { resource: 'network' })
  | (BaseCase & { resource: 'string'; scope: StringScope });

interface VectorDocument {
  revision: string;
  uri: string;
  policy: string;
  cases: VectorCase[];
}

export interface ConformanceFailure {
  id: string;
  expected: ExpectedDecision;
  actual: ExpectedDecision | null;
  error?: string;
}

export interface ConformanceRun {
  revision: string;
  vectorsUri: string;
  vectorsSha256: string;
  policyDigest: string;
  total: number;
  passed: number;
  failed: ConformanceFailure[];
  conformant: boolean;
}

const ajv = new Ajv2020({ allErrors: true, strict: true, validateFormats: false });
const validateVectors = ajv.compile<VectorDocument>(CONFORMANCE_VECTORS_SCHEMA);

export function runConformanceFile(vectorPath: string): ConformanceRun {
  const absolutePath = path.resolve(vectorPath);
  const bytes = readBoundedRegularFile(absolutePath, {
    maximumBytes: MAX_VECTOR_BYTES,
    label: 'conformance vectors',
    unreadableCode: 'vectors_unreadable',
    notFileCode: 'not_a_file',
    tooLargeCode: 'vectors_too_large',
    changedCode: 'vectors_changed_during_load'
  });
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new PolicyError('invalid_vectors_encoding', 'conformance vectors are not valid UTF-8');
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new PolicyError('invalid_vectors_json', 'conformance vectors are not valid JSON');
  }
  if (!validateVectors(value)) throw vectorSchemaError(validateVectors.errors ?? []);
  const vectors = value;
  const ids = new Set<string>();
  for (const testCase of vectors.cases) {
    if (ids.has(testCase.id)) {
      throw new PolicyError('duplicate_vector_id', `duplicate conformance case id: ${testCase.id}`);
    }
    ids.add(testCase.id);
  }

  const policy = parsePolicy(vectors.policy, path.join(path.dirname(absolutePath), '.aiignore.yaml'));
  const engine = new PolicyEngine(policy);
  const failed: ConformanceFailure[] = [];
  for (const testCase of vectors.cases) {
    const expected: ExpectedDecision =
      testCase.errorCode === undefined
        ? {
            resource: testCase.resource,
            effect: testCase.effect as DecisionEffect,
            ruleId: testCase.ruleId as string | null,
            ...('matched' in testCase ? { matched: testCase.matched } : {}),
            ...('output' in testCase && testCase.output !== undefined
              ? { output: testCase.output }
              : {}),
            ...('appliedRuleIds' in testCase
              ? { appliedRuleIds: testCase.appliedRuleIds }
              : {})
          }
        : { resource: testCase.resource, errorCode: testCase.errorCode };
    try {
      const candidate = materializeCandidate(testCase);
      const decision =
        testCase.resource === 'file'
          ? engine.decideFile(
              candidate,
              testCase.operation,
              policy.root,
              testCase.caseInsensitive ?? false
            )
          : testCase.resource === 'environment'
            ? engine.decideEnvironment(candidate, testCase.caseInsensitive ?? false)
            : testCase.resource === 'network'
              ? engine.decideNetwork(candidate)
              : engine.decideString(candidate, testCase.scope);
      const decisionErrors = validateDecisionSchema(decision);
      if (decisionErrors.length > 0) {
        throw new PolicyError(
          'decision_schema_validation',
          'implementation returned a decision outside the portable draft 0.1 contract'
        );
      }
      const actual: ExpectedDecision = {
        resource: decision.resource,
        effect: decision.effect,
        ruleId: decision.ruleId,
        ...(expected.matched !== undefined ? { matched: decision.matched } : {}),
        ...(expected.output !== undefined ? { output: decision.output ?? '' } : {}),
        ...(expected.appliedRuleIds !== undefined
          ? { appliedRuleIds: decision.appliedRuleIds ?? [] }
          : {})
      };
      if (
        testCase.errorCode !== undefined ||
        decision.policyDigest !== policy.digest ||
        decision.reason.length === 0 ||
        JSON.stringify(actual) !== JSON.stringify(expected)
      ) {
        failed.push({ id: testCase.id, expected, actual });
      }
    } catch (error) {
      const errorCode = error instanceof PolicyError ? error.code : 'unexpected_error';
      if (testCase.errorCode !== errorCode) {
        failed.push({ id: testCase.id, expected, actual: null, error: errorCode });
      }
    }
  }
  return {
    revision: vectors.revision,
    vectorsUri: vectors.uri,
    vectorsSha256: createHash('sha256').update(bytes).digest('hex'),
    policyDigest: policy.digest,
    total: vectors.cases.length,
    passed: vectors.cases.length - failed.length,
    failed,
    conformant: failed.length === 0
  };
}

function materializeCandidate(testCase: BaseCase): string {
  if (testCase.candidate !== undefined) return testCase.candidate;
  if (!testCase.candidateRepeat) return '';
  const generatedBytes =
    Buffer.byteLength(testCase.candidateRepeat.prefix ?? '') +
    Buffer.byteLength(testCase.candidateRepeat.text) * testCase.candidateRepeat.count +
    Buffer.byteLength(testCase.candidateRepeat.suffix ?? '');
  if (generatedBytes > MAX_GENERATED_CANDIDATE_BYTES) {
    throw new PolicyError(
      'generated_candidate_too_large',
      `generated candidate exceeds ${MAX_GENERATED_CANDIDATE_BYTES} bytes`
    );
  }
  return `${testCase.candidateRepeat.prefix ?? ''}${testCase.candidateRepeat.text.repeat(testCase.candidateRepeat.count)}${testCase.candidateRepeat.suffix ?? ''}`;
}

function vectorSchemaError(errors: ErrorObject[]): PolicyError {
  const message = errors
    .slice(0, 20)
    .map((error) => `${error.instancePath || '/'} ${error.message ?? 'is invalid'}`)
    .join('; ');
  const suffix = errors.length > 20 ? `; and ${errors.length - 20} more errors` : '';
  return new PolicyError('vectors_schema_validation', `${message}${suffix}`);
}
