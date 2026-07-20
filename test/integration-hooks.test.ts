import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('../', import.meta.url));
const wrappers = {
  codex: path.join(root, 'integrations/codex/aiignore-codex/scripts/pre_tool_use.mjs'),
  gemini: path.join(root, 'integrations/gemini/aiignore-gemini/scripts/before_tool.mjs')
} as const;

describe('packaged hook wrappers', () => {
  it('accepts only status-consistent structured child responses', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-hook-wrapper-'));
    const fakeCli = path.join(directory, 'fake-cli.mjs');
    const policy = path.join(directory, '.aiignore.yaml');
    writeFileSync(policy, 'aiignore: "0.1"\n');
    writeFileSync(
      fakeCli,
      `const mode = process.env.FAKE_MODE;
const target = process.argv[3];
if (mode === 'empty3') process.exit(3);
if (mode === 'malformed3') { process.stdout.write('{'); process.exit(3); }
if (mode === 'conflicting3') { process.stdout.write(target === 'codex' ? '{}' : '{"decision":"allow"}'); process.exit(3); }
if (mode === 'valid3') {
  process.stdout.write(target === 'codex'
    ? JSON.stringify({hookSpecificOutput:{hookEventName:'PreToolUse',permissionDecision:'deny',permissionDecisionReason:'verified deny'}})
    : JSON.stringify({decision:'deny',reason:'verified deny'}));
  process.exit(3);
}
if (mode === 'allow0') {
  if (target === 'gemini') process.stdout.write('{"decision":"allow"}');
  process.exit(0);
}
process.exit(9);
`
    );

    for (const target of ['codex', 'gemini'] as const) {
      for (const mode of ['empty3', 'malformed3', 'conflicting3']) {
        const response = invoke(wrappers[target], fakeCli, policy, mode);
        expect(response.status).toBe(0);
        expect(decision(response.stdout, target)).toBe('deny');
        expect(response.stdout).toContain('failed closed');
      }
      const denied = invoke(wrappers[target], fakeCli, policy, 'valid3');
      expect(decision(denied.stdout, target)).toBe('deny');
      expect(denied.stdout).toContain('verified deny');

      const allowed = invoke(wrappers[target], fakeCli, policy, 'allow0');
      expect(allowed.status).toBe(0);
      if (target === 'codex') expect(allowed.stdout).toBe('');
      else expect(decision(allowed.stdout, target)).toBe('allow');

      const invalidEncoding = invoke(
        wrappers[target],
        fakeCli,
        policy,
        'allow0',
        Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d])
      );
      expect(invalidEncoding.status).toBe(0);
      expect(decision(invalidEncoding.stdout, target)).toBe('deny');
      expect(invalidEncoding.stdout).toContain('not valid UTF-8');
    }
  }, 30_000);
});

function invoke(wrapper: string, cli: string, policy: string, mode: string, input?: string | Buffer) {
  return spawnSync(process.execPath, [wrapper], {
    input: input ?? JSON.stringify({ cwd: path.dirname(policy), tool_input: {} }),
    encoding: 'utf8',
    env: {
      ...process.env,
      AIIGNORE_CLI_JS: cli,
      AIIGNORE_POLICY_PATH: policy,
      FAKE_MODE: mode
    }
  });
}

function decision(stdout: string, target: 'codex' | 'gemini'): unknown {
  const value = JSON.parse(stdout) as Record<string, unknown>;
  return target === 'codex'
    ? (value['hookSpecificOutput'] as Record<string, unknown>)['permissionDecision']
    : value['decision'];
}
