import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { Ajv2020, type ErrorObject } from 'ajv/dist/2020.js';
import { PolicyError } from './errors.js';
import { parsePolicy } from './parser.js';
import { readBoundedRegularFile } from './safe-file.js';

const schemaUrl = new URL('../schema/parser-vectors.schema.json', import.meta.url);
export const PARSER_VECTORS_SCHEMA = JSON.parse(readFileSync(schemaUrl, 'utf8')) as object;
export const MAX_PARSER_VECTOR_BYTES = 4 * 1024 * 1024;
export const MAX_GENERATED_PARSER_INPUT_BYTES = 2 * 1024 * 1024;

interface ParserVectorCase {
  id: string;
  text?: string;
  bytesBase64?: string;
  repeat?: { text: string; count: number };
  valid: boolean;
  errorCode?: string;
}

interface ParserVectorDocument {
  revision: string;
  uri: string;
  cases: ParserVectorCase[];
}

export interface ParserConformanceFailure {
  id: string;
  expected: { valid: boolean; errorCode?: string };
  actual: { valid: boolean; errorCode?: string };
}

export interface ParserConformanceRun {
  revision: string;
  vectorsUri: string;
  vectorsSha256: string;
  total: number;
  passed: number;
  failed: ParserConformanceFailure[];
  conformant: boolean;
}

const ajv = new Ajv2020({ allErrors: true, strict: true, validateFormats: false });
const validateVectors = ajv.compile<ParserVectorDocument>(PARSER_VECTORS_SCHEMA);

export function runParserConformanceFile(vectorPath: string): ParserConformanceRun {
  const absolutePath = path.resolve(vectorPath);
  const bytes = readBoundedRegularFile(absolutePath, {
    maximumBytes: MAX_PARSER_VECTOR_BYTES,
    label: 'parser conformance vectors',
    unreadableCode: 'vectors_unreadable',
    notFileCode: 'not_a_file',
    tooLargeCode: 'vectors_too_large',
    changedCode: 'vectors_changed_during_load'
  });
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new PolicyError(
      'invalid_vectors_encoding',
      'parser conformance vectors are not valid UTF-8'
    );
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new PolicyError('invalid_vectors_json', 'parser conformance vectors are not valid JSON');
  }
  if (!validateVectors(value)) throw vectorSchemaError(validateVectors.errors ?? []);

  const ids = new Set<string>();
  const failed: ParserConformanceFailure[] = [];
  for (const testCase of value.cases) {
    if (ids.has(testCase.id)) {
      throw new PolicyError('duplicate_vector_id', `duplicate parser conformance case id: ${testCase.id}`);
    }
    ids.add(testCase.id);
    const expected = {
      valid: testCase.valid,
      ...(testCase.errorCode === undefined ? {} : { errorCode: testCase.errorCode })
    };
    let actual: ParserConformanceFailure['actual'];
    const input = materializeInput(testCase);
    try {
      parsePolicy(input, '<parser-vector>');
      actual = { valid: true };
    } catch (error) {
      actual = {
        valid: false,
        errorCode: error instanceof PolicyError ? error.code : 'unexpected_error'
      };
    }
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      failed.push({ id: testCase.id, expected, actual });
    }
  }

  return {
    revision: value.revision,
    vectorsUri: value.uri,
    vectorsSha256: createHash('sha256').update(bytes).digest('hex'),
    total: value.cases.length,
    passed: value.cases.length - failed.length,
    failed,
    conformant: failed.length === 0
  };
}

function materializeInput(testCase: ParserVectorCase): string | Buffer {
  if (testCase.text !== undefined) return testCase.text;
  if (testCase.bytesBase64 !== undefined) return Buffer.from(testCase.bytesBase64, 'base64');
  if (!testCase.repeat) return '';
  const generatedBytes = Buffer.byteLength(testCase.repeat.text) * testCase.repeat.count;
  if (generatedBytes > MAX_GENERATED_PARSER_INPUT_BYTES) {
    throw new PolicyError(
      'generated_input_too_large',
      `generated parser input exceeds ${MAX_GENERATED_PARSER_INPUT_BYTES} bytes`
    );
  }
  return testCase.repeat.text.repeat(testCase.repeat.count);
}

function vectorSchemaError(errors: ErrorObject[]): PolicyError {
  const message = errors
    .slice(0, 20)
    .map((error) => `${error.instancePath || '/'} ${error.message ?? 'is invalid'}`)
    .join('; ');
  const suffix = errors.length > 20 ? `; and ${errors.length - 20} more errors` : '';
  return new PolicyError('parser_vectors_schema_validation', `${message}${suffix}`);
}
