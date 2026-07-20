import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

const root = parseRoot(process.argv.slice(2));
const manifest = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
const lock = JSON.parse(readFileSync(path.join(root, 'package-lock.json'), 'utf8'));

const allowedProductionLicenses = new Set([
  '0BSD',
  'Apache-2.0',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'BlueOak-1.0.0',
  'ISC',
  'MIT'
]);

const failures = [];
const inventory = new Map();
if (manifest.license !== 'MIT') {
  failures.push(`project license is ${String(manifest.license)}; expected MIT`);
}

for (const [packagePath, installed] of collectProductionPackages(root, manifest, failures)) {
  const metadata = lock.packages?.[packagePath];
  const name = typeof installed.name === 'string' ? installed.name : packagePath;
  if (!metadata) {
    failures.push(`${name}: installed production dependency is missing from package-lock.json`);
    continue;
  }
  const installedPath = path.resolve(root, packagePath);
  if (!installedPath.startsWith(`${path.join(root, 'node_modules')}${path.sep}`)) {
    failures.push(`${packagePath}: unsafe production dependency path`);
    continue;
  }
  const license = installed.license;
  if (metadata.version !== installed.version) {
    failures.push(`${name}: lock version does not match installed package`);
  }
  if (metadata.license !== license) {
    failures.push(`${name}: lock license does not match installed package`);
  }
  if (typeof license !== 'string' || license.length === 0) {
    failures.push(`${name}: installed production dependency has no declared license`);
    continue;
  }
  if (!allowedProductionLicenses.has(license)) {
    failures.push(`${name}: production dependency license ${license} is not approved`);
  }
  const packages = inventory.get(license) ?? [];
  packages.push(name);
  inventory.set(license, packages);
}

if (failures.length > 0) {
  failures.forEach((failure) => process.stderr.write(`not ok - ${failure}\n`));
  process.exit(1);
}

const summary = [...inventory]
  .sort(([left], [right]) => left.localeCompare(right))
  .map(([license, packages]) => `${license}:${packages.length}`)
  .join(', ');
process.stdout.write(`ok - production dependency licenses (${summary})\n`);

function parseRoot(args) {
  if (args.length === 0) return path.resolve('.');
  if (args.length === 2 && args[0] === '--root' && args[1]) return path.resolve(args[1]);
  throw new Error('usage: validate-licenses.mjs [--root directory]');
}

function collectProductionPackages(root, rootManifest, failures) {
  const packages = new Map();
  const queue = Object.keys(rootManifest.dependencies ?? {}).map((name) => ({
    name,
    from: root,
    optional: false
  }));
  while (queue.length > 0) {
    const request = queue.shift();
    const installedPath = resolveInstalledPackage(root, request.from, request.name);
    if (!installedPath) {
      if (!request.optional) failures.push(`${request.name}: production dependency is not installed`);
      continue;
    }
    const packagePath = path.relative(root, installedPath).split(path.sep).join('/');
    if (packages.has(packagePath)) continue;
    const installed = JSON.parse(readFileSync(path.join(installedPath, 'package.json'), 'utf8'));
    packages.set(packagePath, installed);
    for (const name of Object.keys(installed.dependencies ?? {})) {
      queue.push({ name, from: installedPath, optional: false });
    }
    for (const name of Object.keys(installed.optionalDependencies ?? {})) {
      queue.push({ name, from: installedPath, optional: true });
    }
  }
  return packages;
}

function resolveInstalledPackage(root, from, name) {
  let current = from;
  while (current === root || current.startsWith(`${root}${path.sep}`)) {
    const candidate = path.resolve(current, 'node_modules', name);
    if (
      candidate.startsWith(`${path.join(root, 'node_modules')}${path.sep}`) &&
      existsSync(path.join(candidate, 'package.json'))
    ) return candidate;
    if (current === root) break;
    current = path.dirname(current);
  }
  return null;
}
