import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('../', import.meta.url));
const script = path.join(root, 'scripts/validate-conformance-manifest.mjs');
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe('versioned conformance manifest', () => {
  it('accepts the exact bundle and rejects byte or membership drift', () => {
    const directory = createBundleFixture();
    expect(invoke(directory)).toMatchObject({ status: 0, stderr: '' });

    const specification = path.join(directory, 'spec/aiignore.md');
    const originalSpecification = readFileSync(specification);
    writeFileSync(specification, Buffer.concat([originalSpecification, Buffer.from('\ntampered\n')]));
    const tampered = invoke(directory);
    expect(tampered).toMatchObject({ status: 1 });
    expect(tampered.stderr).toContain('artifact digest drifted: spec/aiignore.md');
    writeFileSync(specification, originalSpecification);

    const manifestPath = path.join(directory, 'conformance/manifest-v0.1.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
      artifacts: unknown[];
    };
    manifest.artifacts.pop();
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const incomplete = invoke(directory);
    expect(incomplete).toMatchObject({ status: 1 });
    expect(incomplete.stderr).toContain('conformance manifest must contain exactly 22 artifacts');

    writeFileSync(manifestPath, Buffer.from([0xff]));
    const invalidEncoding = invoke(directory);
    expect(invalidEncoding).toMatchObject({ status: 1 });
    expect(invalidEncoding.stderr).toContain('conformance manifest is not valid UTF-8');
  }, 15_000);
});

function createBundleFixture(): string {
  const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-manifest-'));
  temporaryDirectories.push(directory);
  const manifestPath = 'conformance/manifest-v0.1.json';
  const manifest = JSON.parse(readFileSync(path.join(root, manifestPath), 'utf8')) as {
    artifacts: Array<{ path: string }>;
  };
  for (const relativePath of [
    'package.json',
    manifestPath,
    'schema/conformance-manifest.schema.json',
    ...manifest.artifacts.map((artifact) => artifact.path)
  ]) {
    const destination = path.join(directory, relativePath);
    mkdirSync(path.dirname(destination), { recursive: true });
    copyFileSync(path.join(root, relativePath), destination);
  }
  return directory;
}

function invoke(directory: string): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, [script, '--root', directory], {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024
  });
}
