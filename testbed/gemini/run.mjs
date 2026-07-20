#!/usr/bin/env node
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cli = path.join(root, 'dist', 'cli.js');
const hook = path.join(root, 'integrations/gemini/aiignore-gemini/scripts/before_tool.mjs');
const workspace = mkdtempSync(path.join(tmpdir(), 'aiignore-gemini-'));

try {
  writeFileSync(
    path.join(workspace, '.aiignore.yaml'),
    `aiignore: "0.1"
defaults: {network: deny}
rules:
  files:
    - {id: private, effect: deny, paths: ["private/**"]}
  environment:
    - {id: tokens, effect: drop, names: ["*_TOKEN"]}
  network:
    - {id: docs, effect: allow, urls: ["https://docs.example.com/**"]}
`
  );

  const cases = [
    {
      name: 'deny direct file',
      event: { cwd: workspace, tool_name: 'read_file', tool_input: { file_path: 'private/key.txt' } },
      decision: 'deny'
    },
    {
      name: 'deny referenced environment',
      event: { cwd: workspace, tool_name: 'run_shell_command', tool_input: { command: 'echo $GITHUB_TOKEN' } },
      decision: 'deny'
    },
    {
      name: 'deny network default',
      event: { cwd: workspace, tool_name: 'web_fetch', tool_input: { url: 'https://attacker.invalid/' } },
      decision: 'deny'
    },
    {
      name: 'allow scoped docs',
      event: { cwd: workspace, tool_name: 'web_fetch', tool_input: { url: 'https://docs.example.com/start' } },
      decision: 'allow'
    }
  ];

  let failed = false;
  for (const testCase of cases) {
    const result = spawnSync(process.execPath, [hook], {
      cwd: workspace,
      env: { ...process.env, AIIGNORE_CLI_JS: cli },
      input: JSON.stringify(testCase.event),
      encoding: 'utf8'
    });
    let output;
    try {
      output = JSON.parse(result.stdout);
    } catch {
      output = null;
    }
    const passed = result.status === 0 && output?.decision === testCase.decision;
    process.stdout.write(`${passed ? 'ok' : 'not ok'} - Gemini hook ${testCase.name}\n`);
    if (!passed) {
      failed = true;
      process.stderr.write(`${result.stdout}${result.stderr}\n`);
    }
  }
  process.exitCode = failed ? 1 : 0;
} finally {
  rmSync(workspace, { force: true, recursive: true });
}
