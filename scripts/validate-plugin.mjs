#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

const root = path.resolve('integrations/codex/aiignore-codex');
const manifestPath = path.join(root, '.codex-plugin', 'plugin.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const failures = [];

if (manifest.name !== 'aiignore-codex') failures.push('manifest name must equal plugin directory');
if (!/^\d+\.\d+\.\d+$/u.test(manifest.version ?? '')) failures.push('manifest version must be semver');
if (!existsSync(path.join(root, 'hooks', 'hooks.json'))) failures.push('hooks/hooks.json is missing');
if (!existsSync(path.join(root, 'scripts', 'pre_tool_use.mjs'))) failures.push('hook script is missing');
if (!existsSync(path.join(root, 'skills', 'aiignore-enforcement', 'SKILL.md'))) {
  failures.push('aiignore enforcement skill is missing');
}

if (failures.length > 0) {
  failures.forEach((failure) => process.stderr.write(`not ok - ${failure}\n`));
  process.exit(1);
}
process.stdout.write('ok - Codex plugin structure\n');
