import { describe, expect, it } from 'vitest';
import { PolicyEngine } from '../src/engine.js';
import { loadPolicy } from '../src/parser.js';

const engine = new PolicyEngine(loadPolicy('profiles/recommended.aiignore.yaml'));

describe('recommended secret baseline', () => {
  it('protects common credential files while allowing templates', () => {
    expect(engine.decideFile('/workspace/app/.env.production', 'read', '/workspace').effect).toBe('deny');
    expect(engine.decideFile('/workspace/app/.env.example', 'read', '/workspace').effect).toBe('allow');
    expect(engine.decideFile('/workspace/.ssh/id_ed25519', 'read', '/workspace').effect).toBe('deny');
  });

  it('drops ambient credential variables and keeps metadata exceptions', () => {
    expect(engine.decideEnvironment('SERVICE_API_KEY').effect).toBe('drop');
    expect(engine.decideEnvironment('GITHUB_TOKEN').effect).toBe('drop');
    expect(engine.decideEnvironment('ACCESS_TOKEN_TTL').effect).toBe('allow');
  });

  it('redacts synthetic provider and private-key canaries', () => {
    // Assemble the deliberately invalid canary so secret scanners do not
    // mistake a source-code fixture for a live provider credential.
    const providerCanary = ['AKIA', '0'.repeat(16)].join('');
    const provider = engine.decideString(`key=${providerCanary}`, 'tool_output');
    expect(provider.effect).toBe('redact');
    expect(provider.output).not.toContain(providerCanary);

    const pem = engine.decideString('-----BEGIN PRIVATE KEY-----', 'model_input');
    expect(pem.effect).toBe('redact');
    expect(pem.output).toBe('[REDACTED:pem-private-key]');
  });

  it('redacts bearer, URL, and assignment forms without logging source values', () => {
    const input = [
      'Authorization: Bearer synthetic-token-value-0000',
      'https://user:synthetic-password@example.test/path',
      'client_secret=synthetic-value-0000'
    ].join('\n');
    const decision = engine.decideString(input, 'network_request');
    expect(decision.effect).toBe('redact');
    expect(decision.matched).toMatch(/^(regex|literal|glob)$/u);
    expect(decision.appliedRuleIds).toEqual(
      expect.arrayContaining(['generic-secret-assignment', 'credential-in-url', 'bearer-credential'])
    );
    const output = decision.output ?? input;
    expect(output).not.toContain('synthetic-password');
    expect(output).not.toContain('synthetic-value-0000');
    expect(output).not.toContain('synthetic-token-value-0000');
  });
});
