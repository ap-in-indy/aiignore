import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  MAX_GENERATED_PARSER_INPUT_BYTES,
  MAX_PARSER_VECTOR_BYTES,
  runParserConformanceFile
} from '../src/parser-conformance.js';

const publishedPath = fileURLToPath(new URL('parser-conformance/v0.1.json', import.meta.url));

describe('language-neutral parser conformance vectors', () => {
  it('passes the published valid and invalid policy cases', () => {
    const result = runParserConformanceFile(publishedPath);
    expect(result).toMatchObject({ conformant: true, failed: [] });
    expect(result.total).toBeGreaterThanOrEqual(30);
    expect(result.vectorsUri).toBe(
      'https://ap-in-indy.github.io/aiignore/vectors/0.1/parser.json'
    );
    expect(result.vectorsSha256).toBe(
      createHash('sha256').update(readFileSync(publishedPath)).digest('hex')
    );
  });

  it('reports mismatches and rejects malformed vector containers', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-parser-vectors-'));
    const mismatch = path.join(directory, 'mismatch.json');
    writeFileSync(
      mismatch,
      JSON.stringify({
        revision: 'test',
        uri: 'https://example.invalid/parser-vectors.json',
        cases: [{ id: 'wrong-expectation', text: 'aiignore: "0.1"\n', valid: false, errorCode: 'invalid_yaml' }]
      })
    );
    expect(runParserConformanceFile(mismatch)).toMatchObject({
      conformant: false,
      failed: [{ id: 'wrong-expectation', actual: { valid: true } }]
    });

    const invalidJson = path.join(directory, 'invalid.json');
    writeFileSync(invalidJson, '{');
    expect(() => runParserConformanceFile(invalidJson)).toThrow(/not valid JSON/u);

    const invalidEncoding = path.join(directory, 'invalid-encoding.json');
    writeFileSync(invalidEncoding, Buffer.from([0xff]));
    expect(() => runParserConformanceFile(invalidEncoding)).toThrow(/not valid UTF-8/u);

    const invalidSchema = path.join(directory, 'invalid-schema.json');
    writeFileSync(invalidSchema, JSON.stringify({ revision: 'test', cases: [] }));
    expect(() => runParserConformanceFile(invalidSchema)).toThrow(/must NOT have fewer/u);

    const duplicate = path.join(directory, 'duplicate.json');
    writeFileSync(
      duplicate,
      JSON.stringify({
        revision: 'test',
        uri: 'https://example.invalid/parser-vectors.json',
        cases: [
          { id: 'same', text: 'aiignore: "0.1"\n', valid: true },
          { id: 'same', text: 'aiignore: "0.1"\n', valid: true }
        ]
      })
    );
    expect(() => runParserConformanceFile(duplicate)).toThrow(/duplicate parser conformance/u);
  });

  it('rejects non-files and oversized vector containers', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-parser-vector-size-'));
    expect(() => runParserConformanceFile(directory)).toThrow(/not a regular file/u);
    const tooLarge = path.join(directory, 'large.json');
    writeFileSync(tooLarge, ' '.repeat(MAX_PARSER_VECTOR_BYTES + 1));
    expect(() => runParserConformanceFile(tooLarge)).toThrow(/vectors exceed/u);

    const generatedTooLarge = path.join(directory, 'generated-large.json');
    writeFileSync(
      generatedTooLarge,
      JSON.stringify({
        revision: 'test',
        uri: 'https://example.invalid/parser-vectors.json',
        cases: [
          {
            id: 'generated-large',
            repeat: { text: 'xx', count: MAX_GENERATED_PARSER_INPUT_BYTES },
            valid: false,
            errorCode: 'policy_too_large'
          }
        ]
      })
    );
    expect(() => runParserConformanceFile(generatedTooLarge)).toThrow(/generated parser input/u);
  });
});
