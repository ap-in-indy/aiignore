import { describe, expect, it } from 'vitest';
import { compileGeminiConfiguration, GEMINI_IGNORE_FILE } from '../src/adapters/gemini.js';
import { evaluateGeminiBeforeTool } from '../src/adapters/gemini-hook.js';
import { policy } from './helpers.js';

describe('Gemini CLI adapter', () => {
  it('lowers context-only file decisions in policy-precedence order', () => {
    const loaded = policy(`aiignore: "0.1"
rules:
  files:
    - id: allow-public
      effect: allow
      priority: 10
      operations: [discover, index]
      paths: ["private/public/**"]
    - id: private
      effect: deny
      operations: [discover, index]
      paths: ["private/**"]
`);
    const result = compileGeminiConfiguration(loaded);
    expect(result.exact).toBe(false);
    expect(result.ignoreFile.indexOf('/private/**')).toBeLessThan(
      result.ignoreFile.indexOf('!/private/public/**')
    );
    expect(result.settings.context.fileFiltering.customIgnoreFilePaths).toEqual([
      GEMINI_IGNORE_FILE
    ]);
    expect(result.ignoreFile).toContain(loaded.digest);
    expect(result.gaps.some((gap) => gap.message.includes('re-include'))).toBe(true);
  });

  it('exactly exports a context-only deny rule', () => {
    const result = compileGeminiConfiguration(
      policy(`aiignore: "0.1"
rules:
  files:
    - {id: private, effect: deny, operations: [discover, index], paths: ["private/**"]}
`)
    );
    expect(result.exact).toBe(true);
    expect(result.ignoreFile).toContain('/private/**');
  });

  it('reports direct-file, environment-glob, network, and string gaps', () => {
    const result = compileGeminiConfiguration(
      policy(`aiignore: "0.1"
defaults: {network: deny}
rules:
  files:
    - {id: secrets, effect: deny, paths: ["secrets/**"], except: ["secrets/example.txt"]}
  environment:
    - {id: tokens, effect: drop, names: ["*_TOKEN", "GITHUB_TOKEN"]}
  network:
    - {id: docs, effect: allow, urls: ["https://docs.example/**"]}
  strings:
    - id: marker
      effect: redact
      patterns: [{type: literal, value: secret}]
`)
    );
    expect(result.exact).toBe(false);
    expect(result.settings.security.environmentVariableRedaction.blocked).toContain('GITHUB_TOKEN');
    expect(result.gaps.map((gap) => gap.resource)).toEqual(
      expect.arrayContaining(['file', 'environment', 'network', 'string'])
    );
    expect(result.gaps.some((gap) => /rule-local/iu.test(gap.message))).toBe(true);
  });

  it('returns Gemini structured denials without echoing string secrets', () => {
    const loaded = policy(`aiignore: "0.1"
rules:
  files:
    - {id: private, effect: deny, paths: ["private/**"]}
  environment:
    - {id: tokens, effect: drop, names: ["*_TOKEN"]}
  network:
    - {id: blocked, effect: deny, urls: ["https://blocked.test/**"]}
  strings:
    - id: query-secret
      effect: deny
      scopes: [network_request]
      patterns: [{type: literal, value: "do-not-echo"}]
`);
    const fileResult = evaluateGeminiBeforeTool(loaded, {
      cwd: '/workspace',
      tool_name: 'read_file',
      tool_input: { file_path: '/workspace/private/key.txt' }
    });
    expect(fileResult.denied).toBe(true);
    expect(fileResult.response).toMatchObject({ decision: 'deny' });

    const bulkFileResult = evaluateGeminiBeforeTool(loaded, {
      cwd: '/workspace',
      tool_name: 'read_many_files',
      tool_input: { paths: ['/workspace/public.txt', '/workspace/private/key.txt'] }
    });
    expect(bulkFileResult.denied).toBe(true);
    expect(bulkFileResult.decisions).toContainEqual(
      expect.objectContaining({ resource: 'file', ruleId: 'private' })
    );

    const bulkNetworkResult = evaluateGeminiBeforeTool(loaded, {
      tool_name: 'web_fetch_many',
      tool_input: { urls: ['https://example.test/', 'https://blocked.test/private'] }
    });
    expect(bulkNetworkResult.denied).toBe(true);

    const networkResult = evaluateGeminiBeforeTool(loaded, {
      cwd: '/workspace',
      tool_name: 'web_fetch',
      tool_input: { http_url: 'https://example.test/?q=do-not-echo' }
    });
    expect(networkResult.denied).toBe(true);
    expect(JSON.stringify(networkResult.response)).not.toContain('do-not-echo');

    const envResult = evaluateGeminiBeforeTool(loaded, {
      cwd: '/workspace',
      tool_name: 'run_shell_command',
      tool_input: { command: 'printf %s "$GITHUB_TOKEN"' }
    });
    expect(envResult.denied).toBe(true);
  });

  it('resolves relative tool paths from the event cwd and matches them from the policy root', () => {
    const loaded = policy(`aiignore: "0.1"
rules:
  files:
    - {id: nested-private, effect: deny, paths: ["subdir/private/**"]}
`);
    const result = evaluateGeminiBeforeTool(loaded, {
      cwd: '/workspace/subdir',
      policyRoot: '/workspace',
      tool_name: 'read_file',
      tool_input: { file_path: 'private/key.txt' }
    });
    expect(result.denied).toBe(true);
    expect(result.decisions).toContainEqual(expect.objectContaining({ ruleId: 'nested-private' }));
  });

  it('fails closed on malformed direct inputs and allows an unrelated call', () => {
    const loaded = policy('aiignore: "0.1"\n');
    const malformed = evaluateGeminiBeforeTool(loaded, {
      cwd: '/workspace',
      tool_name: 'read_file',
      tool_input: [{ path: '../outside' }, { uri: 'not a url' }]
    });
    expect(malformed.denied).toBe(true);
    expect(malformed.errors).toEqual([
      expect.objectContaining({ resource: 'file', error: 'path_escape' }),
      expect.objectContaining({ resource: 'network', error: 'invalid_url' })
    ]);
    expect(malformed.decisions.every((decision) => decision.effect !== 'deny')).toBe(true);

    const allowed = evaluateGeminiBeforeTool(loaded, {
      cwd: '/workspace',
      tool_name: 'read_file',
      tool_input: { file_path: 'README.md' }
    });
    expect(allowed.response).toEqual({ decision: 'allow' });
  });

  it('reports default-deny, single-operation, audit, and exact environment variants', () => {
    const result = compileGeminiConfiguration(
      policy(`aiignore: "0.1"
defaults: {files: deny, environment: deny, strings: deny}
rules:
  files:
    - {id: one-context-op, effect: deny, operations: [discover], paths: ["single/"]}
    - {id: context-audit, effect: audit, operations: [discover, index], paths: ["audit/**"]}
  environment:
    - {id: exact-allow, effect: allow, names: [PUBLIC_VALUE]}
    - {id: exact-deny, effect: deny, names: [BLOCKED_VALUE]}
    - {id: env-audit, effect: audit, names: [AUDIT_VALUE], except: [AUDIT_SAFE]}
`)
    );
    expect(result.ignoreFile).toContain('/**');
    expect(result.ignoreFile).toContain('/single/**');
    expect(result.settings.security.environmentVariableRedaction).toMatchObject({
      enabled: true,
      allowed: ['AUDIT_VALUE', 'PUBLIC_VALUE'],
      blocked: ['BLOCKED_VALUE']
    });
    expect(result.gaps.some((gap) => gap.message.includes('default-deny environment'))).toBe(true);
    expect(result.gaps.some((gap) => gap.message.includes('cannot distinguish discover'))).toBe(true);
    expect(result.gaps.some((gap) => gap.message.includes('Audit-only context'))).toBe(true);
    expect(result.gaps.some((gap) => gap.message.includes('Audit-only environment'))).toBe(true);
    expect(result.gaps.some((gap) => gap.message.includes('default-deny string'))).toBe(true);
  });

  it('maps Gemini tool-name operation variants and nested command aliases', () => {
    const loaded = policy(`aiignore: "0.1"
rules:
  files:
    - {id: private, effect: deny, operations: [discover, write, execute], paths: ["private/**"]}
  environment:
    - {id: blocked, effect: drop, names: [BLOCKED_VALUE]}
`);
    for (const toolName of ['replace_file', 'delete_file', 'run_shell_command', 'glob_search']) {
      const result = evaluateGeminiBeforeTool(loaded, {
        cwd: '/workspace',
        tool_name: toolName,
        tool_input: [null, 'ignored', { nested: { file_path: '/workspace/private/key' } }]
      });
      expect(result.denied, toolName).toBe(true);
    }
    expect(
      evaluateGeminiBeforeTool(loaded, {
        tool_name: 'custom',
        tool_input: { cmd: 'echo $BLOCKED_VALUE' }
      }).denied
    ).toBe(true);
  });

  it('fails closed when hook environment references exceed their aggregate limit', () => {
    const loaded = policy('aiignore: "0.1"\n');
    const command = Array.from({ length: 129 }, (_, index) => `$VALUE_${index}`).join(' ');
    expect(() => evaluateGeminiBeforeTool(loaded, { tool_input: { command } })).toThrow(
      /environment-reference limit/u
    );
  });
});
