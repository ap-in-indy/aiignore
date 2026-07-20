import { describe, expect, it } from 'vitest';
import { PolicyEngine } from '../src/engine.js';
import { policy } from './helpers.js';

const engine = new PolicyEngine(
  policy(`aiignore: "0.1"
rules:
  environment:
    - id: credentials
      effect: drop
      names: ["*_TOKEN", "AWS_*"]
      except: ["PUBLIC_*", "*_TOKEN_TTL"]
    - id: internal-url
      effect: redact
      names: ["INTERNAL_URL"]
      replacement: "hidden"
    - id: forbidden-runtime
      effect: deny
      names: ["FORBIDDEN_RUNTIME"]
  strings:
    - id: marker
      effect: deny
      scopes: [environment_value]
      patterns: [{type: literal, value: "AIIGNORE_TEST_SECRET_DO_NOT_USE"}]
`)
);

describe('environment decisions', () => {
  it('drops secret names and honors exceptions', () => {
    expect(engine.decideEnvironment('GITHUB_TOKEN').effect).toBe('drop');
    expect(engine.decideEnvironment('PUBLIC_TOKEN').effect).toBe('allow');
    expect(engine.decideEnvironment('ACCESS_TOKEN_TTL').effect).toBe('allow');
  });

  it('supports explicit platform case folding', () => {
    expect(engine.decideEnvironment('github_token', false).effect).toBe('allow');
    expect(engine.decideEnvironment('github_token', true).effect).toBe('drop');
  });

  it('filters values without returning denied values in decisions', () => {
    const result = engine.filterEnvironment({
      SAFE: 'ok',
      GITHUB_TOKEN: 'not-a-real-token',
      INTERNAL_URL: 'https://internal.example',
      OTHER: 'AIIGNORE_TEST_SECRET_DO_NOT_USE'
    });
    expect(result.environment).toEqual({ SAFE: 'ok', INTERNAL_URL: 'hidden' });
    expect(result.denied).toEqual(['OTHER']);
    expect(result.decisions.OTHER).toMatchObject({ resource: 'environment', effect: 'allow' });
    expect(result.valueDecisions.OTHER).toMatchObject({ resource: 'string', effect: 'deny' });
    expect(result.valueDecisions.SAFE).toMatchObject({ resource: 'string', effect: 'allow' });
    expect(JSON.stringify(result.decisions)).not.toContain('not-a-real-token');
    expect(JSON.stringify(result.decisions)).not.toContain('https://internal.example');
    expect(JSON.stringify(result.valueDecisions)).not.toContain('AIIGNORE_TEST_SECRET_DO_NOT_USE');
  });

  it('refuses environment names with a deny effect', () => {
    const result = engine.filterEnvironment({ FORBIDDEN_RUNTIME: 'present' });
    expect(result.denied).toEqual(['FORBIDDEN_RUNTIME']);
    expect(result.environment).toEqual({});
  });

  it('rejects names that cannot exist in a process environment', () => {
    expect(() => engine.decideEnvironment('')).toThrow(/non-empty/u);
    expect(() => engine.decideEnvironment('BAD=NAME')).toThrow(/neither NUL nor =/u);
    expect(() => engine.decideEnvironment('BAD\0NAME')).toThrow(/neither NUL nor =/u);
  });

  it('preserves JavaScript object-prototype names as ordinary environment entries', () => {
    const input = Object.create(null) as Record<string, string>;
    input['__proto__'] = 'prototype-value';
    input['constructor'] = 'constructor-value';
    const result = engine.filterEnvironment(input);
    expect(Object.getPrototypeOf(result.environment)).toBeNull();
    expect(Object.getPrototypeOf(result.decisions)).toBeNull();
    expect(Object.prototype.hasOwnProperty.call(result.environment, '__proto__')).toBe(true);
    expect(result.environment['__proto__']).toBe('prototype-value');
    expect(result.environment['constructor']).toBe('constructor-value');
    expect(result.decisions['__proto__']?.resource).toBe('environment');
    const serialized = JSON.parse(JSON.stringify(result.environment)) as Record<string, string>;
    expect(serialized['__proto__']).toBe('prototype-value');
    expect(serialized['constructor']).toBe('constructor-value');
  });
});
