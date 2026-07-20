import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

const root = process.cwd();
const validator = path.join(root, 'scripts/validate-requirements-traceability.mjs');
const catalogPath = 'conformance/requirements-v0.1.json';

describe('normative requirements traceability', () => {
  it('inventories every normative keyword and maps each section to reviewed evidence', () => {
    expect(validate(createFixture())).toMatchObject({ status: 0, stderr: '' });
  });

  it('rejects unreviewed normative language and missing evidence', () => {
    const changedSpec = createFixture();
    const specPath = path.join(changedSpec, 'spec/aiignore.md');
    writeFileSync(specPath, `${readFileSync(specPath, 'utf8')}\nImplementations MUST reject drift.\n`);
    expect(validate(changedSpec).stderr).toContain('traceability metadata drifted');

    const missingEvidence = createFixture();
    rmSync(path.join(missingEvidence, 'schema/aiignore.schema.json'));
    expect(validate(missingEvidence).stderr).toContain('missing traceability evidence');
  });

  it('rejects self-upgraded assurance and erased external limitations', () => {
    const fixture = createFixture();
    mutateCatalog(fixture, (catalog) => {
      catalog.sections[4]!.assurance = 'implemented';
      catalog.sections[4]!.limitations = [];
    });
    expect(validate(fixture).stderr).toContain('claims differ from the reviewed catalog');
  });

  it('rejects substituted evidence and weakened limitation claims', () => {
    const substitutedEvidence = createFixture();
    mutateCatalog(substitutedEvidence, (catalog) => {
      catalog.sections[1]!.evidence[0] = 'README.md';
    });
    copyEvidence(substitutedEvidence, 'README.md');
    expect(validate(substitutedEvidence).stderr).toContain('claims differ from the reviewed catalog');

    const weakenedLimitation = createFixture();
    mutateCatalog(weakenedLimitation, (catalog) => {
      catalog.sections[4]!.limitations = ['Some external work may remain.'];
    });
    expect(validate(weakenedLimitation).stderr).toContain('claims differ from the reviewed catalog');
  });
});

function createFixture(): string {
  const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-requirements-'));
  const catalog = readCatalog(root);
  for (const filename of [
    catalogPath,
    'schema/requirements-traceability.schema.json',
    'spec/aiignore.md',
    ...catalog.sections.flatMap(({ evidence }) => evidence.map((item) => item.split('#', 1)[0]!))
  ]) {
    const destination = path.join(directory, filename);
    mkdirSync(path.dirname(destination), { recursive: true });
    cpSync(path.join(root, filename), destination);
  }
  return directory;
}

function mutateCatalog(directory: string, mutate: (catalog: Catalog) => void) {
  const filename = path.join(directory, catalogPath);
  const catalog = readCatalog(directory);
  mutate(catalog);
  writeFileSync(filename, `${JSON.stringify(catalog, null, 2)}\n`);
}

function copyEvidence(directory: string, filename: string) {
  const destination = path.join(directory, filename);
  mkdirSync(path.dirname(destination), { recursive: true });
  cpSync(path.join(root, filename), destination);
}

function readCatalog(directory: string): Catalog {
  return JSON.parse(readFileSync(path.join(directory, catalogPath), 'utf8')) as Catalog;
}

function validate(directory: string): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, [validator, '--root', directory], {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024
  });
}

interface Catalog {
  sections: Array<{
    assurance: string;
    evidence: string[];
    limitations: string[];
  }>;
}
