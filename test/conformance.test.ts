import { createHash } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  MAX_GENERATED_CANDIDATE_BYTES,
  MAX_VECTOR_BYTES,
  runConformanceFile
} from '../src/conformance.js';
import { PolicyEngine } from '../src/engine.js';
import { parsePolicy } from '../src/parser.js';
import type { FileOperation, StringScope } from '../src/types.js';

interface VectorFile {
  revision: string;
  uri: string;
  policy: string;
  cases: Array<{
    id: string;
    resource: 'file' | 'environment' | 'network' | 'string';
    candidate: string;
    operation?: FileOperation;
    scope?: StringScope;
    effect: string;
    ruleId: string | null;
    output?: string;
  }>;
}

const vectors = JSON.parse(
  readFileSync(new URL('conformance/v0.1.json', import.meta.url), 'utf8')
) as VectorFile;

describe(`language-neutral conformance vectors ${vectors.revision}`, () => {
  const engine = new PolicyEngine(parsePolicy(vectors.policy, '/workspace/.aiignore.yaml'));
  for (const vector of vectors.cases) {
    it(vector.id, () => {
      const decision =
        vector.resource === 'file'
          ? engine.decideFile(vector.candidate, vector.operation ?? 'read')
          : vector.resource === 'environment'
            ? engine.decideEnvironment(vector.candidate, false)
            : vector.resource === 'network'
              ? engine.decideNetwork(vector.candidate)
              : engine.decideString(vector.candidate, vector.scope ?? 'tool_output');
      expect({
        effect: decision.effect,
        ruleId: decision.ruleId,
        ...(vector.output !== undefined ? { output: decision.output } : {})
      }).toEqual({
        effect: vector.effect,
        ruleId: vector.ruleId,
        ...(vector.output !== undefined ? { output: vector.output } : {})
      });
    });
  }

  it('runs the published vector document through the reusable runner', () => {
    const vectorPath = fileURLToPath(new URL('conformance/v0.1.json', import.meta.url));
    const result = runConformanceFile(vectorPath);
    expect(result).toMatchObject({ conformant: true, total: vectors.cases.length, failed: [] });
    expect(result.vectorsUri).toBe(vectors.uri);
    expect(result.vectorsSha256).toBe(
      createHash('sha256').update(readFileSync(vectorPath)).digest('hex')
    );
  });

  it('passes every published language-neutral vector pack', () => {
    const directory = fileURLToPath(new URL('conformance/', import.meta.url));
    const files = readdirSync(directory).filter((file) => file.endsWith('.json'));
    expect(files.length).toBeGreaterThan(1);
    for (const file of files) {
      expect(runConformanceFile(path.join(directory, file)).conformant, file).toBe(true);
    }
  }, 15_000);

  it('reports decision mismatches and rejects duplicate case ids', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-vectors-'));
    const mismatchPath = path.join(directory, 'mismatch.json');
    const mismatch = structuredClone(vectors);
    const first = mismatch.cases[0];
    if (!first) throw new Error('test vector fixture must not be empty');
    first.effect = 'allow';
    writeFileSync(mismatchPath, JSON.stringify(mismatch));
    const result = runConformanceFile(mismatchPath);
    expect(result.conformant).toBe(false);
    expect(result.failed[0]?.id).toBe(first.id);

    const duplicatePath = path.join(directory, 'duplicate.json');
    const duplicate = structuredClone(vectors);
    const second = duplicate.cases[1];
    if (!second) throw new Error('test vector fixture needs two cases');
    second.id = duplicate.cases[0]?.id ?? second.id;
    writeFileSync(duplicatePath, JSON.stringify(duplicate));
    expect(() => runConformanceFile(duplicatePath)).toThrow(/duplicate conformance case id/u);
  });

  it('fails closed on invalid vector containers and records candidate errors', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-vectors-invalid-'));
    expect(() => runConformanceFile(directory)).toThrow(/not a regular file/u);

    const invalidJson = path.join(directory, 'invalid.json');
    writeFileSync(invalidJson, '{');
    expect(() => runConformanceFile(invalidJson)).toThrow(/not valid JSON/u);

    const invalidEncoding = path.join(directory, 'invalid-encoding.json');
    writeFileSync(invalidEncoding, Buffer.from([0xff]));
    expect(() => runConformanceFile(invalidEncoding)).toThrow(/not valid UTF-8/u);

    const invalidSchema = path.join(directory, 'schema.json');
    writeFileSync(invalidSchema, '{}');
    expect(() => runConformanceFile(invalidSchema)).toThrow(/required property/u);

    for (const invalidCase of [
      {
        id: 'invalid-success-operation',
        resource: 'file',
        candidate: 'private.txt',
        operation: 'reed',
        effect: 'allow',
        ruleId: null
      },
      {
        id: 'invalid-success-scope',
        resource: 'string',
        candidate: 'value',
        scope: 'logs',
        effect: 'allow',
        ruleId: null
      }
    ]) {
      const invalidEnum = path.join(directory, `${invalidCase.id}.json`);
      writeFileSync(
        invalidEnum,
        JSON.stringify({
          revision: 'test',
          uri: 'https://example.invalid/invalid-enum.json',
          policy: 'aiignore: "0.1"\n',
          cases: [invalidCase]
        })
      );
      expect(() => runConformanceFile(invalidEnum)).toThrow(/allowed values|match "then" schema/u);
    }

    const tooLarge = path.join(directory, 'large.json');
    writeFileSync(tooLarge, ' '.repeat(MAX_VECTOR_BYTES + 1));
    expect(() => runConformanceFile(tooLarge)).toThrow(/vectors exceed/u);

    const candidateError = path.join(directory, 'candidate-error.json');
    writeFileSync(
      candidateError,
      JSON.stringify({
        revision: 'test',
        uri: 'https://example.invalid/vectors.json',
        policy: 'aiignore: "0.1"\n',
        cases: [
          {
            id: 'invalid-url',
            resource: 'network',
            candidate: 'not-a-url',
            effect: 'deny',
            ruleId: null
          }
        ]
      })
    );
    expect(runConformanceFile(candidateError).failed[0]).toMatchObject({
      id: 'invalid-url',
      actual: null,
      error: 'invalid_url'
    });

    const generatedError = path.join(directory, 'generated-error.json');
    writeFileSync(
      generatedError,
      JSON.stringify({
        revision: 'test',
        uri: 'https://example.invalid/generated-vectors.json',
        policy: 'aiignore: "0.1"\n',
        cases: [
          {
            id: 'generated-too-large',
            resource: 'string',
            candidateRepeat: { text: 'xx', count: MAX_GENERATED_CANDIDATE_BYTES },
            scope: 'log',
            errorCode: 'generated_candidate_too_large'
          }
        ]
      })
    );
    expect(runConformanceFile(generatedError)).toMatchObject({ conformant: true, failed: [] });
  });
});
