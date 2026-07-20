import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { SPEC_VERSION } from '../src/constants.js';
import {
  DEFAULT_EFFECTS,
  DECISION_EFFECTS,
  ENVIRONMENT_EFFECTS,
  FILE_EFFECTS,
  FILE_OPERATIONS,
  NETWORK_EFFECTS,
  RESOURCES,
  STRING_EFFECTS,
  STRING_PATTERN_TYPES,
  STRING_SCOPES
} from '../src/types.js';

type LooseCase = Record<string, unknown>;
type EnumDefinition = { enum: readonly string[] };
interface PolicySchemaShape {
  properties: { aiignore: { const: string } };
  $defs: {
    defaultEffect: EnumDefinition;
    fileRule: { properties: { effect: EnumDefinition; operations: { items: EnumDefinition } } };
    environmentRule: { properties: { effect: EnumDefinition } };
    networkRule: { properties: { effect: EnumDefinition } };
    stringRule: { properties: { effect: EnumDefinition } };
    stringScope: EnumDefinition;
    stringPattern: { properties: { type: EnumDefinition } };
  };
}

const policySchema = JSON.parse(
  readFileSync(new URL('../schema/aiignore.schema.json', import.meta.url), 'utf8')
) as unknown as PolicySchemaShape;
const decisionSchema = JSON.parse(
  readFileSync(new URL('../schema/decision.schema.json', import.meta.url), 'utf8')
) as unknown as {
  properties: { resource: EnumDefinition; effect: EnumDefinition };
};
const auditEventSchema = JSON.parse(
  readFileSync(new URL('../schema/audit-event.schema.json', import.meta.url), 'utf8')
) as unknown as {
  properties: { resource: EnumDefinition; formatVersion: { const: string } };
};
const vectorFiles = [
  'v0.1.json',
  'security-v0.1.json',
  'options-v0.1.json',
  'limits-v0.1.json'
].map((filename) =>
  JSON.parse(
    readFileSync(new URL(`conformance/${filename}`, import.meta.url), 'utf8')
  ) as unknown as { cases: LooseCase[] }
);
const parserVectors = JSON.parse(
  readFileSync(new URL('parser-conformance/v0.1.json', import.meta.url), 'utf8')
) as unknown as { cases: LooseCase[] };

describe('normative coverage contract', () => {
  it('keeps runtime constants synchronized with the policy schema', () => {
    const definitions = policySchema.$defs;
    expect(policySchema.properties.aiignore.const).toBe(SPEC_VERSION);
    expect(definitions.defaultEffect.enum).toEqual(DEFAULT_EFFECTS);
    expect(definitions.fileRule.properties.effect.enum).toEqual(FILE_EFFECTS);
    expect(definitions.fileRule.properties.operations.items.enum).toEqual(FILE_OPERATIONS);
    expect(definitions.environmentRule.properties.effect.enum).toEqual(ENVIRONMENT_EFFECTS);
    expect(definitions.networkRule.properties.effect.enum).toEqual(NETWORK_EFFECTS);
    expect(definitions.stringRule.properties.effect.enum).toEqual(STRING_EFFECTS);
    expect(definitions.stringScope.enum).toEqual(STRING_SCOPES);
    expect(definitions.stringPattern.properties.type.enum).toEqual(STRING_PATTERN_TYPES);
    expect(decisionSchema.properties.resource.enum).toEqual(RESOURCES);
    expect(decisionSchema.properties.effect.enum).toEqual(DECISION_EFFECTS);
    expect(auditEventSchema.properties.resource.enum).toEqual(RESOURCES);
    expect(auditEventSchema.properties.formatVersion.const).toBe(SPEC_VERSION);
  });

  it('has portable decision evidence for every operation, scope, and observable effect', () => {
    const cases = vectorFiles.flatMap((vectors) => vectors.cases);
    const values = (resource: string, field: string, successfulOnly = false): Set<unknown> =>
      new Set(
        cases
          .filter(
            (testCase) =>
              testCase.resource === resource && (!successfulOnly || testCase.errorCode === undefined)
          )
          .map((testCase) => testCase[field])
      );

    expect(values('file', 'operation', true)).toEqual(new Set(FILE_OPERATIONS));
    expect(values('file', 'effect')).toEqual(new Set(['allow', 'deny', 'audit', undefined]));
    expect(values('environment', 'effect')).toEqual(
      new Set([...ENVIRONMENT_EFFECTS, undefined])
    );
    expect(values('network', 'effect')).toEqual(new Set([...NETWORK_EFFECTS, undefined]));
    expect(values('string', 'effect')).toEqual(new Set([...STRING_EFFECTS, undefined]));
    expect(values('string', 'scope', true)).toEqual(new Set(STRING_SCOPES));
  });

  it('has portable negative evidence for every normative parser and candidate diagnostic', () => {
    const parserCodes = new Set(
      parserVectors.cases.map((testCase) => testCase.errorCode).filter(Boolean)
    );
    for (const code of [
      'invalid_encoding',
      'policy_too_large',
      'invalid_yaml',
      'unsafe_yaml',
      'schema_validation',
      'duplicate_rule_id',
      'invalid_pattern',
      'invalid_network_pattern',
      'invalid_string_pattern'
    ]) {
      expect(parserCodes).toContain(code);
    }

    const runtimeCodes = new Set(
      vectorFiles.flatMap((vectors) => vectors.cases).map((testCase) => testCase.errorCode).filter(Boolean)
    );
    expect(runtimeCodes).toEqual(
      new Set([
        'invalid_path',
        'path_escape',
        'invalid_file_operation',
        'invalid_environment_name',
        'invalid_url',
        'invalid_string_scope',
        'candidate_too_large',
        'resource_work_limit',
        'string_output_too_large',
        'string_replacement_limit',
        'string_work_limit'
      ])
    );
  });

  it('freezes exported language enums at runtime', () => {
    for (const values of [FILE_OPERATIONS, STRING_SCOPES, RESOURCES, DECISION_EFFECTS]) {
      expect(Object.isFrozen(values)).toBe(true);
      expect(() => (values as unknown as string[]).splice(0)).toThrow(TypeError);
    }
  });
});
