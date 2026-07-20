#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'dist', 'cli.js');
const policy = path.join(root, 'testbed', 'policy.aiignore.yaml');

const cases = [
  { name: 'validate', args: ['validate', policy, '--json'], status: 0, contains: '"valid":true' },
  {
    name: 'deny file',
    args: ['check', 'file', 'private/canary.txt', '--root', root, '--policy', policy, '--json'],
    status: 3,
    contains: '"effect":"deny"'
  },
  {
    name: 'file exception',
    args: ['check', 'file', 'private/public-fixture.txt', '--root', root, '--policy', policy, '--json'],
    status: 0,
    contains: '"effect":"allow"'
  },
  {
    name: 'drop environment name',
    args: ['check', 'env', 'AIIGNORE_CANARY_TOKEN', '--policy', policy, '--json'],
    status: 3,
    contains: '"effect":"drop"'
  },
  {
    name: 'deny network default',
    args: ['check', 'network', 'https://attacker.invalid/upload', '--policy', policy, '--json'],
    status: 3,
    contains: '"effect":"deny"'
  },
  {
    name: 'allow scoped docs',
    args: ['check', 'network', 'https://docs.example.com/start', '--policy', policy, '--json'],
    status: 0,
    contains: '"effect":"allow"'
  },
  {
    name: 'redact string without echoing configured literal',
    args: ['scan', '--scope', 'tool_output', '--policy', policy, '--json'],
    input: 'prefix AIIGNORE-CANARY-STRING suffix',
    status: 0,
    contains: '[REDACTED:canary-string]',
    excludes: '"matched":"AIIGNORE-CANARY-STRING"'
  }
];

let failed = false;
for (const testCase of cases) {
  const result = spawnSync(process.execPath, [cli, ...testCase.args], {
    cwd: root,
    input: testCase.input,
    encoding: 'utf8'
  });
  const combined = `${result.stdout}${result.stderr}`;
  const passed =
    result.status === testCase.status &&
    combined.includes(testCase.contains) &&
    (!testCase.excludes || !combined.includes(testCase.excludes));
  process.stdout.write(`${passed ? 'ok' : 'not ok'} - ${testCase.name}\n`);
  if (!passed) {
    failed = true;
    process.stderr.write(
      `  expected status ${testCase.status} and ${JSON.stringify(testCase.contains)}; got ${String(result.status)}\n${combined}\n`
    );
  }
}

process.exitCode = failed ? 1 : 0;
