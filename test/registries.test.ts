import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  CONFORMANCE_REPORT_MEDIA_TYPE,
  IMPLEMENTATION_CONFORMANCE_REPORT_MEDIA_TYPE
} from '../src/report-signature.js';
import {
  DEFAULT_EFFECTS,
  ENVIRONMENT_EFFECTS,
  FILE_EFFECTS,
  FILE_OPERATIONS,
  NETWORK_EFFECTS,
  RESOURCES,
  STRING_EFFECTS,
  STRING_PATTERN_TYPES,
  STRING_SCOPES
} from '../src/types.js';

const registry = readFileSync(new URL('../spec/registries.md', import.meta.url), 'utf8');

describe('closed draft 0.1 registries', () => {
  it('enumerates the exact runtime resource, operation, scope, and pattern tokens', () => {
    expect(firstColumn('Resources')).toEqual(RESOURCES);
    expect(firstColumn('File operations')).toEqual(FILE_OPERATIONS);
    expect(firstColumn('String scopes')).toEqual(STRING_SCOPES);
    expect(firstColumn('String pattern types')).toEqual(STRING_PATTERN_TYPES);
  });

  it('enumerates every resource-specific rule effect without adding aliases', () => {
    expect(effectRows()).toEqual({
      defaults: DEFAULT_EFFECTS,
      file: FILE_EFFECTS,
      environment: ENVIRONMENT_EFFECTS,
      network: NETWORK_EFFECTS,
      string: STRING_EFFECTS,
      'portable decision': ['allow', 'deny', 'drop', 'redact', 'audit']
    });
  });

  it('binds assurance and signed-report identifiers without a private extension range', () => {
    expect(firstColumn('Assurance levels')).toEqual(['context', 'tool', 'sandbox']);
    expect(registry).toContain(IMPLEMENTATION_CONFORMANCE_REPORT_MEDIA_TYPE);
    expect(registry).toContain(CONFORMANCE_REPORT_MEDIA_TYPE);
    expect(registry).toContain('`aiignore-ed25519-v0.1`');
    expect(registry).toContain('Draft 0.1 defines no private-use token range');
  });

  it('enumerates the complete portable diagnostic code registry', () => {
    expect(firstColumn('Portable diagnostic codes')).toEqual([
      'invalid_encoding',
      'policy_too_large',
      'invalid_yaml',
      'unsafe_yaml',
      'schema_validation',
      'duplicate_rule_id',
      'invalid_pattern',
      'invalid_network_pattern',
      'invalid_string_pattern',
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
    ]);
  });
});

function section(name: string): string {
  const startMarker = `## ${name}\n`;
  const start = registry.indexOf(startMarker);
  if (start < 0) throw new Error(`missing registry section ${name}`);
  const contentStart = start + startMarker.length;
  const next = registry.indexOf('\n## ', contentStart);
  return registry.slice(contentStart, next < 0 ? registry.length : next);
}

function firstColumn(name: string): string[] {
  return section(name)
    .split('\n')
    .map((line) => /^\| `([^`]+)` \|/u.exec(line)?.[1])
    .filter((value): value is string => value !== undefined);
}

function effectRows(): Record<string, readonly string[]> {
  return Object.fromEntries(
    section('Rule effects')
      .split('\n')
      .map((line) => /^\| ([^|`]+) \| (.+) \|$/u.exec(line))
      .filter(
        (match): match is RegExpExecArray => match !== null && match[2]!.includes('`')
      )
      .map((match) => [
        match[1]!.trim(),
        [...match[2]!.matchAll(/`([^`]+)`/gu)].map((token) => token[1]!)
      ])
  );
}
