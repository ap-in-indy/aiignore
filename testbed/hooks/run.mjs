#!/usr/bin/env node
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const cases = [
  {
    name: 'Codex malformed input fails closed',
    script: 'integrations/codex/aiignore-codex/scripts/pre_tool_use.mjs',
    input: 'not-json',
    accepts: (value) => value?.hookSpecificOutput?.permissionDecision === 'deny'
  },
  {
    name: 'Gemini malformed input fails closed',
    script: 'integrations/gemini/aiignore-gemini/scripts/before_tool.mjs',
    input: 'not-json',
    accepts: (value) => value?.decision === 'deny'
  },
  {
    name: 'Codex non-object input fails closed',
    script: 'integrations/codex/aiignore-codex/scripts/pre_tool_use.mjs',
    input: '[]',
    accepts: (value) => value?.hookSpecificOutput?.permissionDecision === 'deny'
  },
  {
    name: 'Gemini invalid cwd type fails closed',
    script: 'integrations/gemini/aiignore-gemini/scripts/before_tool.mjs',
    input: '{"cwd":42}',
    accepts: (value) => value?.decision === 'deny'
  },
  {
    name: 'Gemini oversized input fails closed',
    script: 'integrations/gemini/aiignore-gemini/scripts/before_tool.mjs',
    input: 'x'.repeat(8 * 1024 * 1024 + 1),
    accepts: (value) => value?.decision === 'deny' && /exceeds/u.test(value.reason ?? '')
  },
  {
    name: 'Codex hook honors pinned external policy and workspace root',
    script: 'integrations/codex/aiignore-codex/scripts/pre_tool_use.mjs',
    input: JSON.stringify({
      cwd: root,
      tool_name: 'read_file',
      tool_input: { file_path: 'private/key.txt' }
    }),
    environment: {
      AIIGNORE_CLI_JS: path.join(root, 'dist', 'cli.js'),
      AIIGNORE_POLICY_PATH: path.join(root, 'testbed', 'policy.aiignore.yaml'),
      AIIGNORE_POLICY_ROOT: root
    },
    accepts: (value) => value?.hookSpecificOutput?.permissionDecision === 'deny'
  },
  {
    name: 'Gemini hook fails closed when pinned policy disappears',
    script: 'integrations/gemini/aiignore-gemini/scripts/before_tool.mjs',
    input: JSON.stringify({ cwd: root, tool_name: 'read_file', tool_input: { file_path: 'x' } }),
    environment: {
      AIIGNORE_CLI_JS: path.join(root, 'dist', 'cli.js'),
      AIIGNORE_POLICY_PATH: path.join(root, 'test-results', 'missing.aiignore.yaml'),
      AIIGNORE_POLICY_ROOT: root
    },
    accepts: (value) => value?.decision === 'deny' && /status 2/u.test(value.reason ?? '')
  }
];

let failed = false;
for (const testCase of cases) {
  const result = spawnSync(process.execPath, [path.join(root, testCase.script)], {
    cwd: root,
    input: testCase.input,
    encoding: 'utf8',
    maxBuffer: 2 * 1024 * 1024,
    env: { ...process.env, ...testCase.environment }
  });
  let output;
  try {
    output = JSON.parse(result.stdout);
  } catch {
    output = null;
  }
  const passed = result.status === 0 && testCase.accepts(output);
  process.stdout.write(`${passed ? 'ok' : 'not ok'} - ${testCase.name}\n`);
  if (!passed) {
    failed = true;
    process.stderr.write(`${result.stdout}${result.stderr}\n`);
  }
}

process.exitCode = failed ? 1 : 0;
