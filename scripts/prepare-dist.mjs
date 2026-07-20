import { chmodSync, readFileSync } from 'node:fs';

const cli = new URL('../dist/cli.js', import.meta.url);
const firstLine = readFileSync(cli, 'utf8').split('\n', 1)[0];
if (firstLine !== '#!/usr/bin/env node') {
  throw new Error('dist/cli.js is missing the Node.js executable shebang');
}
chmodSync(cli, 0o755);
