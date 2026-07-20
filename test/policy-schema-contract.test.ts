import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { PolicyError } from '../src/errors.js';
import { parsePolicy } from '../src/parser.js';

type JsonObject = Record<string, unknown>;
type Witness = () => void;

const schema = JSON.parse(
  readFileSync(new URL('../schema/aiignore.schema.json', import.meta.url), 'utf8')
) as JsonObject;
const assertionKeywords = new Set([
  'additionalProperties',
  'const',
  'dependentRequired',
  'enum',
  'exclusiveMaximum',
  'exclusiveMinimum',
  'format',
  'maxItems',
  'maxLength',
  'maxContains',
  'maxProperties',
  'maximum',
  'minItems',
  'minLength',
  'minContains',
  'minProperties',
  'minimum',
  'multipleOf',
  'pattern',
  'required',
  'type',
  'uniqueItems'
]);
const schemaKeywords = new Set([
  '$anchor',
  '$comment',
  '$defs',
  '$dynamicAnchor',
  '$dynamicRef',
  '$id',
  '$ref',
  '$schema',
  '$vocabulary',
  'additionalProperties',
  'allOf',
  'anyOf',
  'const',
  'contains',
  'contentEncoding',
  'contentMediaType',
  'contentSchema',
  'default',
  'dependentRequired',
  'dependentSchemas',
  'deprecated',
  'description',
  'else',
  'enum',
  'examples',
  'exclusiveMaximum',
  'exclusiveMinimum',
  'format',
  'if',
  'items',
  'maxContains',
  'maxItems',
  'maxLength',
  'maxProperties',
  'maximum',
  'minContains',
  'minItems',
  'minLength',
  'minProperties',
  'minimum',
  'multipleOf',
  'not',
  'oneOf',
  'pattern',
  'patternProperties',
  'prefixItems',
  'properties',
  'propertyNames',
  'readOnly',
  'required',
  'then',
  'title',
  'type',
  'unevaluatedItems',
  'unevaluatedProperties',
  'uniqueItems',
  'writeOnly'
]);

describe('policy schema executable contract', () => {
  it(
    'binds every declared schema assertion to an executable boundary witness',
    () => {
      expect([...witnesses.keys()].sort()).toEqual(collectAssertions(schema));
      for (const [pointer, witness] of witnesses) {
        try {
          witness();
        } catch (error) {
          throw new Error(`schema witness failed for ${pointer}`, { cause: error });
        }
      }
    },
    120_000
  );
});

const witnesses = new Map<string, Witness>([
  ['/type', () => expectSchemaInvalid([])],
  ['/additionalProperties', () => expectSchemaInvalid({ ...base(), surprise: true })],
  ['/required', () => expectSchemaInvalid({})],
  ['/properties/aiignore/const', () => expectSchemaInvalid({ aiignore: '0.2' })],
  ['/$defs/id/type', () => expectSchemaInvalid(withRules('files', [{ ...fileRule('valid'), id: 1 }]))],
  ['/$defs/id/pattern', witnessIdPattern],
  ['/$defs/priority/type', witnessPriorityType],
  ['/$defs/priority/minimum', () => witnessPriority(-1000, -1001)],
  ['/$defs/priority/maximum', () => witnessPriority(1000, 1001)],
  ['/$defs/nonEmptyString/type', () => expectSchemaInvalid(withRules('files', [{ ...fileRule('valid'), paths: [1] }]))],
  ['/$defs/nonEmptyString/minLength', witnessNonEmptyStringMinimum],
  ['/$defs/nonEmptyString/maxLength', witnessNonEmptyStringMaximum],
  ['/$defs/nonEmptyStringArray/type', () => expectSchemaInvalid(withRules('files', [{ ...fileRule('valid'), paths: 'x' }]))],
  ['/$defs/nonEmptyStringArray/minItems', witnessNonEmptyArrayMinimum],
  ['/$defs/nonEmptyStringArray/maxItems', witnessNonEmptyArrayMaximum],
  ['/$defs/metadata/type', () => expectSchemaInvalid({ ...base(), metadata: 'metadata' })],
  ['/$defs/metadata/additionalProperties', () => expectSchemaInvalid({ ...base(), metadata: { surprise: true } })],
  ['/$defs/metadata/properties/name/type', () => expectSchemaInvalid({ ...base(), metadata: { name: 1 } })],
  ['/$defs/metadata/properties/name/minLength', () => expectSchemaInvalid({ ...base(), metadata: { name: '' } })],
  ['/$defs/metadata/properties/name/maxLength', () => witnessStringBoundary('name', 128)],
  ['/$defs/metadata/properties/description/type', () => expectSchemaInvalid({ ...base(), metadata: { description: 1 } })],
  ['/$defs/metadata/properties/description/maxLength', () => witnessStringBoundary('description', 2048)],
  ['/$defs/defaults/type', () => expectSchemaInvalid({ ...base(), defaults: 'allow' })],
  ['/$defs/defaults/additionalProperties', () => expectSchemaInvalid({ ...base(), defaults: { surprise: 'allow' } })],
  ['/$defs/defaultEffect/type', () => expectSchemaInvalid({ ...base(), defaults: { files: 1 } })],
  ['/$defs/defaultEffect/enum', witnessDefaultEffects],
  ['/$defs/rules/type', () => expectSchemaInvalid({ ...base(), rules: 'rules' })],
  ['/$defs/rules/additionalProperties', () => expectSchemaInvalid({ ...base(), rules: { surprise: [] } })],
  ['/$defs/rules/properties/files/type', () => expectSchemaInvalid(withRules('files', {}))],
  ['/$defs/rules/properties/files/maxItems', () => witnessRuleArrayMaximum('files', fileRule)],
  ['/$defs/rules/properties/environment/type', () => expectSchemaInvalid(withRules('environment', {}))],
  ['/$defs/rules/properties/environment/maxItems', () => witnessRuleArrayMaximum('environment', environmentRule)],
  ['/$defs/rules/properties/network/type', () => expectSchemaInvalid(withRules('network', {}))],
  ['/$defs/rules/properties/network/maxItems', () => witnessRuleArrayMaximum('network', networkRule)],
  ['/$defs/rules/properties/strings/type', () => expectSchemaInvalid(withRules('strings', {}))],
  ['/$defs/rules/properties/strings/maxItems', () => witnessRuleArrayMaximum('strings', stringRule)],
  ['/$defs/fileRule/type', () => expectSchemaInvalid(withRules('files', [null]))],
  ['/$defs/fileRule/additionalProperties', () => witnessAdditionalRuleProperty('files', fileRule('file'))],
  ['/$defs/fileRule/required', witnessFileRequired],
  ['/$defs/fileRule/properties/effect/type', () => expectSchemaInvalid(withRules('files', [{ ...fileRule('file'), effect: 1 }]))],
  ['/$defs/fileRule/properties/effect/enum', witnessFileEffects],
  ['/$defs/fileRule/properties/operations/type', () => expectSchemaInvalid(withRules('files', [{ ...fileRule('file'), operations: 'read' }]))],
  ['/$defs/fileRule/properties/operations/minItems', () => witnessFileOperations([])],
  ['/$defs/fileRule/properties/operations/uniqueItems', () => witnessFileOperations(['read', 'read'])],
  ['/$defs/fileRule/properties/operations/items/type', () => expectSchemaInvalid(withRules('files', [{ ...fileRule('file'), operations: [1] }]))],
  ['/$defs/fileRule/properties/operations/items/enum', witnessFileOperationsEnum],
  ['/$defs/environmentRule/type', () => expectSchemaInvalid(withRules('environment', [null]))],
  ['/$defs/environmentRule/additionalProperties', () => witnessAdditionalRuleProperty('environment', environmentRule('environment'))],
  ['/$defs/environmentRule/required', witnessEnvironmentRequired],
  ['/$defs/environmentRule/properties/effect/type', () => expectSchemaInvalid(withRules('environment', [{ ...environmentRule('environment'), effect: 1 }]))],
  ['/$defs/environmentRule/properties/effect/enum', witnessEnvironmentEffects],
  ['/$defs/environmentRule/properties/replacement/type', () => expectSchemaInvalid(withRules('environment', [{ ...environmentRule('environment'), replacement: 1 }]))],
  ['/$defs/environmentRule/properties/replacement/maxLength', () => witnessReplacementMaximum('environment')],
  ['/$defs/environmentRule/allOf/0/if/properties/effect/const', witnessEnvironmentReplacementCondition],
  ['/$defs/environmentRule/allOf/0/else/not/required', witnessEnvironmentReplacementCondition],
  ['/$defs/networkRule/type', () => expectSchemaInvalid(withRules('network', [null]))],
  ['/$defs/networkRule/additionalProperties', () => witnessAdditionalRuleProperty('network', networkRule('network'))],
  ['/$defs/networkRule/required', witnessNetworkRequired],
  ['/$defs/networkRule/properties/effect/type', () => expectSchemaInvalid(withRules('network', [{ ...networkRule('network'), effect: 1 }]))],
  ['/$defs/networkRule/properties/effect/enum', witnessNetworkEffects],
  ['/$defs/stringRule/type', () => expectSchemaInvalid(withRules('strings', [null]))],
  ['/$defs/stringRule/additionalProperties', () => witnessAdditionalRuleProperty('strings', stringRule('string'))],
  ['/$defs/stringRule/required', witnessStringRequired],
  ['/$defs/stringRule/properties/effect/type', () => expectSchemaInvalid(withRules('strings', [{ ...stringRule('string'), effect: 1 }]))],
  ['/$defs/stringRule/properties/effect/enum', witnessStringEffects],
  ['/$defs/stringRule/properties/scopes/type', () => expectSchemaInvalid(withRules('strings', [{ ...stringRule('string'), scopes: 'log' }]))],
  ['/$defs/stringRule/properties/scopes/minItems', () => witnessStringScopes([])],
  ['/$defs/stringRule/properties/scopes/uniqueItems', () => witnessStringScopes(['log', 'log'])],
  ['/$defs/stringRule/properties/patterns/type', () => expectSchemaInvalid(withRules('strings', [{ ...stringRule('string'), patterns: literal('x') }]))],
  ['/$defs/stringRule/properties/patterns/minItems', () => witnessPatternArray('patterns', 0)],
  ['/$defs/stringRule/properties/patterns/maxItems', () => witnessPatternArray('patterns', 1025)],
  ['/$defs/stringRule/properties/except/type', () => expectSchemaInvalid(withRules('strings', [{ ...stringRule('string'), except: literal('x') }]))],
  ['/$defs/stringRule/properties/except/minItems', () => witnessPatternArray('except', 0)],
  ['/$defs/stringRule/properties/except/maxItems', () => witnessPatternArray('except', 1025)],
  ['/$defs/stringRule/properties/replacement/type', () => expectSchemaInvalid(withRules('strings', [{ ...stringRule('string'), replacement: 1 }]))],
  ['/$defs/stringRule/properties/replacement/maxLength', () => witnessReplacementMaximum('strings')],
  ['/$defs/stringRule/allOf/0/if/properties/effect/const', witnessStringReplacementCondition],
  ['/$defs/stringRule/allOf/0/else/not/required', witnessStringReplacementCondition],
  ['/$defs/stringScope/type', () => expectSchemaInvalid(withRules('strings', [{ ...stringRule('string'), scopes: [1] }]))],
  ['/$defs/stringScope/enum', witnessStringScopesEnum],
  ['/$defs/stringPattern/type', () => expectSchemaInvalid(withRules('strings', [{ ...stringRule('string'), patterns: ['x'] }]))],
  ['/$defs/stringPattern/additionalProperties', witnessStringPatternAdditionalProperty],
  ['/$defs/stringPattern/required', witnessStringPatternRequired],
  ['/$defs/stringPattern/properties/type/type', () => expectSchemaInvalid(withRules('strings', [{ ...stringRule('string'), patterns: [{ type: 1, value: 'x' }] }]))],
  ['/$defs/stringPattern/properties/type/enum', witnessStringPatternTypes],
  ['/$defs/stringPattern/properties/caseSensitive/type', () => expectSchemaInvalid(withRules('strings', [{ ...stringRule('string'), patterns: [{ ...literal('x'), caseSensitive: 'true' }] }]))]
]);

function witnessIdPattern() {
  expectValid(withRules('files', [{ ...fileRule(`a${'b'.repeat(63)}`) }]));
  for (const id of ['Uppercase', '1leading', `a${'b'.repeat(64)}`]) {
    expectSchemaInvalid(withRules('files', [{ ...fileRule('valid'), id }]));
  }
}

function witnessPriority(valid: number, invalid: number) {
  expectValid(withRules('files', [{ ...fileRule('valid'), priority: valid }]));
  expectSchemaInvalid(withRules('files', [{ ...fileRule('invalid'), priority: invalid }]));
}

function witnessPriorityType() {
  expectSchemaInvalid(withRules('files', [{ ...fileRule('string'), priority: '1' }]));
  expectSchemaInvalid(withRules('files', [{ ...fileRule('fraction'), priority: 0.5 }]));
}

function witnessNonEmptyStringMinimum() {
  expectValid(withRules('files', [{ ...fileRule('valid'), paths: ['x'] }]));
  expectSchemaInvalid(withRules('files', [{ ...fileRule('invalid'), paths: [''] }]));
}

function witnessNonEmptyStringMaximum() {
  expectValid(withRules('strings', [{ ...stringRule('valid'), patterns: [literal('x'.repeat(4096))] }]));
  expectSchemaInvalid(withRules('strings', [{ ...stringRule('invalid'), patterns: [literal('x'.repeat(4097))] }]));
}

function witnessNonEmptyArrayMinimum() {
  expectValid(withRules('files', [{ ...fileRule('valid'), paths: ['x'] }]));
  expectSchemaInvalid(withRules('files', [{ ...fileRule('invalid'), paths: [] }]));
}

function witnessNonEmptyArrayMaximum() {
  expectValid(withRules('files', [{ ...fileRule('valid'), paths: Array.from({ length: 1024 }, (_, index) => `p${index}`) }]));
  expectSchemaInvalid(withRules('files', [{ ...fileRule('invalid'), paths: Array.from({ length: 1025 }, (_, index) => `p${index}`) }]));
}

function witnessStringBoundary(field: 'name' | 'description', maximum: number) {
  expectValid({ ...base(), metadata: { [field]: 'x'.repeat(maximum) } });
  expectSchemaInvalid({ ...base(), metadata: { [field]: 'x'.repeat(maximum + 1) } });
}

function witnessDefaultEffects() {
  for (const effect of ['allow', 'deny']) expectValid({ ...base(), defaults: { files: effect } });
  expectSchemaInvalid({ ...base(), defaults: { files: 'audit' } });
}

function witnessRuleArrayMaximum(
  family: 'files' | 'environment' | 'network' | 'strings',
  factory: (id: string) => JsonObject
) {
  expectValid(withRules(family, Array.from({ length: 4096 }, (_, index) => factory(`r${index}`))));
  expectSchemaInvalid(withRules(family, Array.from({ length: 4097 }, (_, index) => factory(`r${index}`))));
}

function witnessAdditionalRuleProperty(family: RuleFamily, rule: JsonObject) {
  expectSchemaInvalid(withRules(family, [{ ...rule, surprise: true }]));
}

function witnessFileRequired() {
  witnessRequired('files', fileRule('file'), ['id', 'effect', 'paths']);
}

function witnessEnvironmentRequired() {
  witnessRequired('environment', environmentRule('environment'), ['id', 'effect', 'names']);
}

function witnessNetworkRequired() {
  witnessRequired('network', networkRule('network'), ['id', 'effect', 'urls']);
}

function witnessStringRequired() {
  witnessRequired('strings', stringRule('string'), ['id', 'effect', 'patterns']);
}

function witnessRequired(family: RuleFamily, rule: JsonObject, fields: string[]) {
  for (const field of fields) {
    const invalid = { ...rule };
    delete invalid[field];
    expectSchemaInvalid(withRules(family, [invalid]));
  }
}

function witnessFileEffects() {
  for (const effect of ['allow', 'deny', 'audit', 'read-only']) {
    expectValid(withRules('files', [{ ...fileRule(effect), effect }]));
  }
  expectSchemaInvalid(withRules('files', [{ ...fileRule('invalid'), effect: 'drop' }]));
}

function witnessFileOperations(operations: string[]) {
  expectSchemaInvalid(withRules('files', [{ ...fileRule('file'), operations }]));
}

function witnessFileOperationsEnum() {
  for (const operation of ['discover', 'index', 'read', 'write', 'execute']) {
    expectValid(withRules('files', [{ ...fileRule(operation), operations: [operation] }]));
  }
  expectSchemaInvalid(withRules('files', [{ ...fileRule('invalid'), operations: ['delete'] }]));
}

function witnessEnvironmentEffects() {
  for (const effect of ['allow', 'drop', 'redact', 'deny', 'audit']) {
    const rule: JsonObject = { ...environmentRule(effect), effect };
    if (effect !== 'redact') delete rule.replacement;
    expectValid(withRules('environment', [rule]));
  }
  expectSchemaInvalid(withRules('environment', [{ ...environmentRule('invalid'), effect: 'read-only' }]));
}

function witnessNetworkEffects() {
  for (const effect of ['allow', 'deny', 'audit']) {
    expectValid(withRules('network', [{ ...networkRule(effect), effect }]));
  }
  expectSchemaInvalid(withRules('network', [{ ...networkRule('invalid'), effect: 'drop' }]));
}

function witnessStringEffects() {
  for (const effect of ['allow', 'deny', 'redact', 'audit']) {
    const rule: JsonObject = { ...stringRule(effect), effect };
    if (effect !== 'redact') delete rule.replacement;
    expectValid(withRules('strings', [rule]));
  }
  expectSchemaInvalid(withRules('strings', [{ ...stringRule('invalid'), effect: 'drop' }]));
}

function witnessReplacementMaximum(family: 'environment' | 'strings') {
  const factory = family === 'environment' ? environmentRule : stringRule;
  expectValid(withRules(family, [{ ...factory('valid'), replacement: 'x'.repeat(1024) }]));
  expectSchemaInvalid(withRules(family, [{ ...factory('invalid'), replacement: 'x'.repeat(1025) }]));
}

function witnessEnvironmentReplacementCondition() {
  expectValid(withRules('environment', [{ ...environmentRule('redacted'), effect: 'redact', replacement: 'x' }]));
  expectSchemaInvalid(withRules('environment', [{ ...environmentRule('allowed'), effect: 'allow', replacement: 'x' }]));
}

function witnessStringReplacementCondition() {
  expectValid(withRules('strings', [{ ...stringRule('redacted'), effect: 'redact', replacement: 'x' }]));
  expectSchemaInvalid(withRules('strings', [{ ...stringRule('allowed'), effect: 'allow', replacement: 'x' }]));
}

function witnessStringScopes(scopes: string[]) {
  expectSchemaInvalid(withRules('strings', [{ ...stringRule('string'), scopes }]));
}

function witnessStringScopesEnum() {
  for (const scope of [
    'user_prompt',
    'model_input',
    'model_output',
    'tool_input',
    'tool_output',
    'file_read',
    'file_write',
    'environment_value',
    'network_request',
    'network_response',
    'log'
  ]) {
    expectValid(withRules('strings', [{ ...stringRule(scope), scopes: [scope] }]));
  }
  expectSchemaInvalid(withRules('strings', [{ ...stringRule('invalid'), scopes: ['transcript'] }]));
}

function witnessPatternArray(field: 'patterns' | 'except', length: number) {
  const validLength = length === 0 ? 1 : 1024;
  expectValid(withRules('strings', [{ ...stringRule('valid'), [field]: Array.from({ length: validLength }, (_, index) => literal(`x${index}`)) }]));
  expectSchemaInvalid(withRules('strings', [{ ...stringRule('string'), [field]: Array.from({ length }, () => literal('x')) }]));
}

function witnessStringPatternAdditionalProperty() {
  expectSchemaInvalid(withRules('strings', [{ ...stringRule('string'), patterns: [{ ...literal('x'), surprise: true }] }]));
}

function witnessStringPatternRequired() {
  for (const field of ['type', 'value']) {
    const pattern = literal('x');
    delete pattern[field];
    expectSchemaInvalid(withRules('strings', [{ ...stringRule(field), patterns: [pattern] }]));
  }
}

function witnessStringPatternTypes() {
  const patterns: Array<[string, string]> = [['literal', 'x'], ['glob', 'x*'], ['regex', 'x+']];
  for (const [type, value] of patterns) {
    expectValid(withRules('strings', [{ ...stringRule(type), patterns: [{ type, value }] }]));
  }
  expectSchemaInvalid(withRules('strings', [{ ...stringRule('invalid'), patterns: [{ type: 'pcre', value: 'x' }] }]));
}

function base(): JsonObject {
  return { aiignore: '0.1' };
}

type RuleFamily = 'files' | 'environment' | 'network' | 'strings';

function withRules(family: RuleFamily, rules: unknown): JsonObject {
  return { ...base(), rules: { [family]: rules } };
}

function fileRule(id: string): JsonObject {
  return { id, effect: 'deny', paths: ['x'] };
}

function environmentRule(id: string): JsonObject {
  return { id, effect: 'redact', names: ['SECRET'], replacement: 'x' };
}

function networkRule(id: string): JsonObject {
  return { id, effect: 'deny', urls: ['https://example.com/**'] };
}

function stringRule(id: string): JsonObject {
  return { id, effect: 'redact', patterns: [literal('x')], replacement: 'x' };
}

function literal(value: string): JsonObject {
  return { type: 'literal', value };
}

function expectValid(document: JsonObject) {
  expect(() => parsePolicy(JSON.stringify(document))).not.toThrow();
}

function expectSchemaInvalid(document: unknown) {
  const serialized = JSON.stringify(document);
  if (!serialized) throw new Error('schema witness is not JSON serializable');
  try {
    parsePolicy(serialized);
  } catch (error) {
    expect(error).toBeInstanceOf(PolicyError);
    expect((error as PolicyError).code).toBe('schema_validation');
    return;
  }
  throw new Error('expected policy schema validation to fail');
}

function collectAssertions(value: unknown, pointer = ''): string[] {
  if (typeof value === 'boolean') return [];
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`invalid JSON Schema object at ${pointer || '/'}`);
  }
  const assertions: string[] = [];
  for (const [key, child] of Object.entries(value)) {
    const childPointer = `${pointer}/${escapePointer(key)}`;
    if (!schemaKeywords.has(key)) throw new Error(`unsupported JSON Schema keyword ${childPointer}`);
    if (assertionKeywords.has(key)) assertions.push(childPointer);
    if (['$defs', 'properties', 'patternProperties', 'dependentSchemas'].includes(key)) {
      if (typeof child !== 'object' || child === null || Array.isArray(child)) {
        throw new Error(`invalid schema map at ${childPointer}`);
      }
      const schemaMap = child as Record<string, unknown>;
      for (const [name, nested] of Object.entries(schemaMap)) {
        assertions.push(
          ...collectAssertions(nested, `${childPointer}/${escapePointer(name)}`)
        );
      }
    } else if (['allOf', 'anyOf', 'oneOf', 'prefixItems'].includes(key)) {
      if (!Array.isArray(child)) throw new Error(`invalid schema array at ${childPointer}`);
      child.forEach((nested, index) => {
        assertions.push(...collectAssertions(nested, `${childPointer}/${index}`));
      });
    } else if (
      [
        'additionalProperties',
        'contains',
        'contentSchema',
        'else',
        'if',
        'items',
        'not',
        'propertyNames',
        'then',
        'unevaluatedItems',
        'unevaluatedProperties'
      ].includes(key) &&
      (typeof child === 'boolean' || (typeof child === 'object' && child !== null))
    ) {
      assertions.push(...collectAssertions(child, childPointer));
    }
  }
  return assertions.sort();
}

function escapePointer(value: string): string {
  return value.replaceAll('~', '~0').replaceAll('/', '~1');
}
