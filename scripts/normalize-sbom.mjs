#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export function normalizeSbom(document, packageIdentity) {
  if (
    !document ||
    typeof document !== 'object' ||
    Array.isArray(document) ||
    document.bomFormat !== 'CycloneDX' ||
    typeof document.metadata !== 'object' ||
    !Array.isArray(document.components)
  ) {
    throw new Error('npm SBOM is not a supported CycloneDX document');
  }
  const normalized = structuredClone(document);
  delete normalized.serialNumber;
  delete normalized.metadata.timestamp;
  if (packageIdentity) {
    if (
      typeof packageIdentity.name !== 'string' ||
      typeof packageIdentity.version !== 'string' ||
      !normalized.metadata.component ||
      typeof normalized.metadata.component !== 'object'
    ) {
      throw new Error('package identity or SBOM root component is invalid');
    }
    const expectedReference = `${packageIdentity.name}@${packageIdentity.version}`;
    const purlName = packageIdentity.name.replace(/^@/u, '%40');
    const expectedPurl = `pkg:npm/${purlName}@${packageIdentity.version}`;
    if (
      normalized.metadata.component['bom-ref'] !== expectedReference ||
      normalized.metadata.component.version !== packageIdentity.version ||
      normalized.metadata.component.purl !== expectedPurl ||
      !Array.isArray(normalized.dependencies) ||
      !normalized.dependencies.some(
        (dependency) => dependency && dependency.ref === expectedReference
      )
    ) {
      throw new Error('SBOM root references do not match the package identity');
    }
    normalized.metadata.component.name = packageIdentity.name;
    normalized.metadata.component.version = packageIdentity.version;
  }
  return `${JSON.stringify(sortKeys(normalized), null, 2)}\n`;
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, sortKeys(value[key])])
  );
}

function main() {
  const [input, output] = process.argv.slice(2);
  if (!input || !output) throw new Error('usage: normalize-sbom.mjs input.json output.json');
  const document = JSON.parse(readFileSync(input, 'utf8'));
  const packageIdentity = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  writeFileSync(output, normalizeSbom(document, packageIdentity));
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
