#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

const root = path.resolve('integrations/gemini/aiignore-gemini');
const manifest = JSON.parse(readFileSync(path.join(root, 'gemini-extension.json'), 'utf8'));
const hooks = JSON.parse(readFileSync(path.join(root, 'hooks', 'hooks.json'), 'utf8'));
const failures = [];

if (manifest.name !== 'aiignore-gemini') failures.push('manifest name must equal extension directory');
if (!/^\d+\.\d+\.\d+$/u.test(manifest.version ?? '')) failures.push('manifest version must be semver');
if (!Array.isArray(hooks.hooks?.BeforeTool)) failures.push('BeforeTool hooks are missing');
const hook = hooks.hooks?.BeforeTool?.[0]?.hooks?.[0];
if (hook?.type !== 'command' || typeof hook.command !== 'string') {
  failures.push('BeforeTool command hook is invalid');
}
if (!existsSync(path.join(root, 'scripts', 'before_tool.mjs'))) failures.push('hook script is missing');

if (failures.length > 0) {
  failures.forEach((failure) => process.stderr.write(`not ok - ${failure}\n`));
  process.exit(1);
}
process.stdout.write('ok - Gemini CLI extension structure\n');
