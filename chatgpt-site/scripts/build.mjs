import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const project = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const root = path.resolve(project, '..');
const output = path.join(project, 'dist');

execFileSync(process.execPath, [path.join(root, 'scripts', 'build-site.mjs')], {
  cwd: root,
  stdio: 'inherit'
});

rmSync(output, { force: true, recursive: true });
mkdirSync(path.join(output, 'server'), { recursive: true });
cpSync(path.join(root, 'site-dist'), path.join(output, 'client'), { recursive: true });
cpSync(path.join(project, 'worker', 'index.js'), path.join(output, 'server', 'index.js'));
