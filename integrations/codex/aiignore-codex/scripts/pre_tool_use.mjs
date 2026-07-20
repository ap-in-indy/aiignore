#!/usr/bin/env node
import { existsSync, readSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const input = readLimitedStdin();
let event;
try {
  event = JSON.parse(decodeUtf8(input));
} catch {
  deny('.aiignore enforcement failed closed: invalid hook input');
}
if (!event || typeof event !== 'object' || Array.isArray(event)) {
  deny('.aiignore enforcement failed closed: hook input must be an object');
}
if (event.cwd !== undefined && typeof event.cwd !== 'string') {
  deny('.aiignore enforcement failed closed: hook cwd must be a string');
}
const policy = findPolicy(event.cwd ?? process.cwd());
if (!policy) process.exit(0);

const cli = trustedCliPath();
const command = process.execPath;
const args = [cli, 'hook', 'codex', '--policy', policy];
if (process.env.AIIGNORE_POLICY_ROOT) args.push('--root', process.env.AIIGNORE_POLICY_ROOT);
const result = spawnSync(command, args, {
  input,
  encoding: 'utf8',
  maxBuffer: 2 * 1024 * 1024
});

if (result.error) deny(`.aiignore enforcement failed closed: ${result.error.message}`);
if (result.stderr) process.stderr.write(result.stderr);

if (result.status === 0 && result.stdout.trim() === '') process.exit(0);
if (result.status === 3) {
  const response = parseDeniedResponse(result.stdout);
  if (response) {
    process.stdout.write(`${JSON.stringify(response)}\n`);
    process.exit(0);
  }
  deny('.aiignore enforcement failed closed: invalid Codex denial response');
}
deny(`.aiignore enforcement failed closed with status ${String(result.status)}`);

function trustedCliPath() {
  const configured = process.env.AIIGNORE_CLI_JS;
  if (configured) {
    if (!path.isAbsolute(configured)) deny('.aiignore enforcement failed closed: AIIGNORE_CLI_JS must be absolute');
    return configured;
  }
  return fileURLToPath(new URL('../../../../dist/cli.js', import.meta.url));
}

function parseDeniedResponse(stdout) {
  let value;
  try {
    value = JSON.parse(stdout);
  } catch {
    return null;
  }
  const output = value?.hookSpecificOutput;
  if (
    !output ||
    output.hookEventName !== 'PreToolUse' ||
    output.permissionDecision !== 'deny' ||
    typeof output.permissionDecisionReason !== 'string' ||
    output.permissionDecisionReason.length === 0
  ) return null;
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: output.permissionDecisionReason
    }
  };
}

function findPolicy(start) {
  if (process.env.AIIGNORE_POLICY_PATH) return path.resolve(process.env.AIIGNORE_POLICY_PATH);
  let current = path.resolve(start);
  while (true) {
    const candidate = path.join(current, '.aiignore.yaml');
    if (existsSync(candidate)) return candidate;
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

function readLimitedStdin(maxBytes = 8 * 1024 * 1024) {
  const chunks = [];
  let total = 0;
  while (true) {
    const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, maxBytes + 1 - total));
    const bytes = readSync(0, buffer, 0, buffer.length, null);
    if (bytes === 0) return Buffer.concat(chunks, total);
    total += bytes;
    if (total > maxBytes) deny(`.aiignore enforcement failed closed: hook input exceeds ${maxBytes} bytes`);
    chunks.push(buffer.subarray(0, bytes));
  }
}

function decodeUtf8(input) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(input);
  } catch {
    deny('.aiignore enforcement failed closed: hook input is not valid UTF-8');
  }
}

function deny(reason) {
  process.stdout.write(
    `${JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: reason
      }
    })}\n`
  );
  process.exit(0);
}
