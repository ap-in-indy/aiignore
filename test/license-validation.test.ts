import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

const script = fileURLToPath(new URL('../scripts/validate-licenses.mjs', import.meta.url));

describe('production dependency license validation', () => {
  it('rejects contributor-edited lockfile license metadata', () => {
    const root = mkdtempSync(path.join(tmpdir(), 'aiignore-licenses-'));
    const installed = path.join(root, 'node_modules/example');
    mkdirSync(installed, { recursive: true });
    writeFileSync(
      path.join(root, 'package.json'),
      JSON.stringify({ name: 'fixture', license: 'MIT', dependencies: { example: '1.0.0' } })
    );
    writeFileSync(
      path.join(root, 'package-lock.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { example: '1.0.0' } },
          'node_modules/example': { version: '1.0.0', license: 'MIT' }
        }
      })
    );
    writeFileSync(
      path.join(installed, 'package.json'),
      JSON.stringify({ name: 'example', version: '1.0.0', license: 'GPL-3.0-only' })
    );
    const result = spawnSync(process.execPath, [script, '--root', root], { encoding: 'utf8' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('lock license does not match installed package');
    expect(result.stderr).toContain('GPL-3.0-only is not approved');
  });
});
