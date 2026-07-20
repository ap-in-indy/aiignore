import { describe, expect, it } from 'vitest';
import { createAuditEvent } from '../src/audit.js';
import { evaluateCodexPreToolUse } from '../src/adapters/codex-hook.js';
import { evaluateGeminiBeforeTool } from '../src/adapters/gemini-hook.js';
import { PolicyEngine } from '../src/engine.js';
import {
  validateAuditEventSchema,
  validateDecisionSchema
} from '../src/schema.js';
import type { Decision } from '../src/types.js';
import { policy } from './helpers.js';

const engine = new PolicyEngine(
  policy(`aiignore: "0.1"
rules:
  files:
    - {id: file-audit, effect: audit, paths: ["audit/**"]}
  environment:
    - {id: env-redact, effect: redact, names: [SECRET_*], replacement: hidden}
  network:
    - {id: network-deny, effect: deny, urls: ["https://blocked.test/**"]}
  strings:
    - {id: string-redact, effect: redact, patterns: [{type: literal, value: TOKEN}], replacement: "[X]"}
`)
);

describe('portable decision and audit protocol schemas', () => {
  it('accepts exact decisions for every resource family and defaults', () => {
    const decisions = [
      engine.decideFile('audit/item', 'read'),
      engine.decideFile('ordinary/item', 'read'),
      engine.decideEnvironment('SECRET_VALUE'),
      engine.decideNetwork('https://blocked.test/item'),
      engine.decideString('TOKEN', 'tool_output')
    ];
    for (const decision of decisions) {
      expect(validateDecisionSchema(decision)).toEqual([]);
    }
  });

  it('requires output fields only for the corresponding redaction shape', () => {
    const environment = engine.decideEnvironment('SECRET_VALUE');
    const string = engine.decideString('TOKEN', 'tool_output');
    expect(environment).toMatchObject({ effect: 'redact', output: 'hidden' });
    expect(string).toMatchObject({
      effect: 'redact',
      output: '[X]',
      appliedRuleIds: ['string-redact']
    });
    expect(validateDecisionSchema({ ...environment, appliedRuleIds: ['env-redact'] })).not.toEqual(
      []
    );
    const missingApplied = { ...string };
    delete missingApplied.appliedRuleIds;
    expect(validateDecisionSchema(missingApplied)).not.toEqual([]);
  });

  it('rejects extension fields and mismatched default identities', () => {
    const defaultDecision = engine.decideFile('ordinary/item', 'read');
    expect(validateDecisionSchema({ ...defaultDecision, vendorData: true })).not.toEqual([]);
    expect(
      validateDecisionSchema({ ...defaultDecision, ruleId: 'fabricated', matched: null })
    ).not.toEqual([]);
  });

  it('restricts resource-specific effects and safe string match identities', () => {
    const file = engine.decideFile('audit/item', 'read');
    expect(validateDecisionSchema({ ...file, effect: 'redact', output: 'x' })).not.toEqual([]);
    const string = engine.decideString('TOKEN', 'tool_output');
    expect(validateDecisionSchema({ ...string, matched: 'TOKEN' })).not.toEqual([]);
  });

  it('creates the exact secret-safe versioned audit event', () => {
    const decision = engine.decideFile('audit/private-name.txt', 'read');
    const event = createAuditEvent(decision);
    expect(event).toEqual({
      event: 'aiignore.audit',
      formatVersion: '0.1',
      resource: 'file',
      ruleId: 'file-audit',
      policyDigest: decision.policyDigest
    });
    expect(validateAuditEventSchema(event)).toEqual([]);
    expect(JSON.stringify(event)).not.toContain('private-name.txt');
  });

  it('refuses to turn a non-audit or default decision into an audit record', () => {
    expect(() => createAuditEvent(engine.decideFile('ordinary/item', 'read'))).toThrow(
      'requires an audit decision selected by a rule'
    );
    const malformed = {
      ...engine.decideFile('audit/item', 'read'),
      ruleId: null
    } as Decision;
    expect(() => createAuditEvent(malformed)).toThrow('requires an audit decision');
    expect(() =>
      createAuditEvent({
        ...engine.decideFile('audit/item', 'read'),
        policyDigest: 'not-a-digest'
      })
    ).toThrow('metadata is not portable');
  });

  it('keeps fail-closed adapter errors separate from portable decisions', () => {
    for (const evaluate of [evaluateCodexPreToolUse, evaluateGeminiBeforeTool]) {
      const result = evaluate(engine.policy, {
        cwd: '/workspace',
        tool_name: 'fetch_file',
        tool_input: { path: '../outside', url: 'not a URL' }
      });
      expect(result.denied).toBe(true);
      expect(result.errors).toEqual([
        expect.objectContaining({ resource: 'file', error: 'path_escape' }),
        expect.objectContaining({ resource: 'network', error: 'invalid_url' })
      ]);
      for (const decision of result.decisions) {
        expect(validateDecisionSchema(decision)).toEqual([]);
      }
    }
  });
});
