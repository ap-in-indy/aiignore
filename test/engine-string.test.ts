import { describe, expect, it } from 'vitest';
import { PolicyEngine } from '../src/engine.js';
import { PolicyError } from '../src/errors.js';
import { policy } from './helpers.js';

const engine = new PolicyEngine(
  policy(`aiignore: "0.1"
rules:
  strings:
    - id: marker
      effect: redact
      scopes: [tool_output]
      patterns:
        - {type: literal, value: "TOP-SECRET", caseSensitive: false}
        - {type: regex, value: "KEY-[0-9]+"}
      except:
        - {type: literal, value: "SAFE-FIXTURE"}
      replacement: "[MASKED]"
    - id: network-deny
      effect: deny
      priority: 10
      scopes: [network_request]
      patterns: [{type: glob, value: "*PRIVATE*"}]
`)
);

describe('string decisions', () => {
  it('uses linear-time regex and case-insensitive literal redaction', () => {
    const decision = engine.decideString('top-secret and KEY-123', 'tool_output');
    expect(decision.effect).toBe('redact');
    expect(decision.output).toBe('[MASKED] and [MASKED]');
    expect(decision.appliedRuleIds).toEqual(['marker']);
    expect(decision.matched).toBe('literal');
    expect(JSON.stringify(decision)).not.toContain('TOP-SECRET');
  });

  it('applies scopes and whole-rule exceptions', () => {
    expect(engine.decideString('TOP-SECRET', 'model_output').effect).toBe('allow');
    expect(engine.decideString('SAFE-FIXTURE TOP-SECRET', 'tool_output').effect).toBe('allow');
  });

  it('rejects unknown scopes instead of falling through to allow', () => {
    expect(() => engine.decideString('TOP-SECRET', 'logs' as never)).toThrowError(PolicyError);
    expect(() => engine.decideString('TOP-SECRET', 'logs' as never)).toThrow(
      /scope is not supported/u
    );
  });

  it('supports unanchored portable globs', () => {
    expect(engine.decideString('body=PRIVATE-MARKER', 'network_request').effect).toBe('deny');
  });

  it('composes all matching redact rules when redact wins', () => {
    const composed = new PolicyEngine(
      policy(`aiignore: "0.1"
rules:
  strings:
    - id: first
      effect: redact
      patterns: [{type: literal, value: FIRST}]
    - id: second
      effect: redact
      patterns: [{type: literal, value: SECOND}]
`)
    ).decideString('FIRST and SECOND', 'tool_output');
    expect(composed.output).toBe('[REDACTED:first] and [REDACTED:second]');
    expect(composed.appliedRuleIds).toEqual(['second', 'first']);
  });

  it('freezes the redaction set against the original input and orders overlapping patterns', () => {
    const composed = new PolicyEngine(
      policy(`aiignore: "0.1"
rules:
  strings:
    - id: lower
      effect: redact
      priority: 1
      patterns: [{type: literal, value: SECRET}]
      replacement: lower
    - id: higher
      effect: redact
      priority: 2
      patterns:
        - {type: literal, value: SECRET-LONG}
        - {type: literal, value: SECRET}
      replacement: higher
    - id: replacement-only
      effect: redact
      priority: 3
      patterns: [{type: literal, value: higher}]
      replacement: unexpected
`)
    ).decideString('SECRET-LONG', 'tool_output');
    expect(composed.output).toBe('higher');
    expect(composed.appliedRuleIds).toEqual(['higher', 'lower']);
  });

  it('treats replacement metacharacters literally for every matcher type', () => {
    const replacement = '$1/$&/\\';
    for (const pattern of [
      '{type: literal, value: SECRET}',
      '{type: glob, value: "*SECRET*"}',
      '{type: regex, value: "(SECRET)"}'
    ]) {
      const decision = new PolicyEngine(
        policy(`aiignore: "0.1"
rules:
  strings:
    - id: literal-replacement
      effect: redact
      patterns: [${pattern}]
      replacement: "${replacement.replace(/\\/gu, '\\\\')}"
`)
      ).decideString('SECRET', 'tool_output');
      expect(decision.output).toBe(replacement);
      expect(decision.output).not.toBe('SECRET');
    }
  });
});
