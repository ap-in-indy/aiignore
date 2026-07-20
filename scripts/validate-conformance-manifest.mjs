import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv2020 } from 'ajv/dist/2020.js';

const scriptRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const root = parseRoot(process.argv.slice(2));
const manifestPath = path.join(root, 'conformance/manifest-v0.1.json');
const manifestBytes = readFileSync(manifestPath);
if (manifestBytes.byteLength > 64 * 1024) throw new Error('conformance manifest exceeds 64 KiB');
const manifest = JSON.parse(decodeUtf8(manifestBytes, 'conformance manifest'));
const schema = JSON.parse(
  readFileSync(path.join(root, 'schema/conformance-manifest.schema.json'), 'utf8')
);
const validate = new Ajv2020({ allErrors: true, strict: true, validateFormats: false }).compile(schema);
if (!validate(manifest)) {
  throw new Error(`invalid conformance manifest: ${JSON.stringify(validate.errors)}`);
}

const expected = [
  ['specification', 'specification', 'text/markdown; charset=utf-8', 'spec/aiignore.md', 'spec/0.1/aiignore.md'],
  ['specification-registries', 'specification', 'text/markdown; charset=utf-8', 'spec/registries.md', 'spec/0.1/registries.md'],
  ['specification-errata', 'specification', 'text/markdown; charset=utf-8', 'spec/errata.md', 'spec/0.1/errata.md'],
  ['schema-policy', 'schema', 'application/schema+json', 'schema/aiignore.schema.json', 'schema/0.1/aiignore.schema.json'],
  ['schema-decision', 'schema', 'application/schema+json', 'schema/decision.schema.json', 'schema/0.1/decision.schema.json'],
  ['schema-audit-event', 'schema', 'application/schema+json', 'schema/audit-event.schema.json', 'schema/0.1/audit-event.schema.json'],
  ['schema-readiness-report', 'schema', 'application/schema+json', 'schema/readiness-report.schema.json', 'schema/0.1/readiness-report.schema.json'],
  ['schema-implementation-conformance-report', 'schema', 'application/schema+json', 'schema/implementation-conformance-report.schema.json', 'schema/0.1/implementation-conformance-report.schema.json'],
  ['schema-conformance-report', 'schema', 'application/schema+json', 'schema/conformance-report.schema.json', 'schema/0.1/conformance-report.schema.json'],
  ['schema-conformance-signature-envelope', 'schema', 'application/schema+json', 'schema/conformance-signature-envelope.schema.json', 'schema/0.1/conformance-signature-envelope.schema.json'],
  ['schema-decision-vectors', 'schema', 'application/schema+json', 'schema/conformance-vectors.schema.json', 'schema/0.1/conformance-vectors.schema.json'],
  ['schema-parser-vectors', 'schema', 'application/schema+json', 'schema/parser-vectors.schema.json', 'schema/0.1/parser-vectors.schema.json'],
  ['schema-harness-vectors', 'schema', 'application/schema+json', 'schema/harness-vectors.schema.json', 'schema/0.1/harness-vectors.schema.json'],
  ['schema-conformance-manifest', 'schema', 'application/schema+json', 'schema/conformance-manifest.schema.json', 'schema/0.1/conformance-manifest.schema.json'],
  ['schema-requirements-traceability', 'schema', 'application/schema+json', 'schema/requirements-traceability.schema.json', 'schema/0.1/requirements-traceability.schema.json'],
  ['requirements-traceability', 'requirements', 'application/json', 'conformance/requirements-v0.1.json', 'conformance/0.1/requirements.json'],
  ['decision-core', 'decision-vectors', 'application/json', 'test/conformance/v0.1.json', 'vectors/0.1/decisions.json'],
  ['decision-security', 'decision-vectors', 'application/json', 'test/conformance/security-v0.1.json', 'vectors/0.1/security.json'],
  ['decision-options', 'decision-vectors', 'application/json', 'test/conformance/options-v0.1.json', 'vectors/0.1/options.json'],
  ['decision-limits', 'decision-vectors', 'application/json', 'test/conformance/limits-v0.1.json', 'vectors/0.1/limits.json'],
  ['parser-core', 'parser-vectors', 'application/json', 'test/parser-conformance/v0.1.json', 'vectors/0.1/parser.json'],
  ['harness-codex-sandbox', 'harness-vectors', 'application/json', 'conformance/vectors/codex-sandbox-v0.1.json', 'vectors/0.1/codex-sandbox.json']
];
const origin = 'https://ap-in-indy.github.io/aiignore';
if (manifest.release !== JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')).version) {
  throw new Error('conformance manifest release does not match package version');
}
if (manifest.artifacts.length !== expected.length) {
  throw new Error(`conformance manifest must contain exactly ${expected.length} artifacts`);
}

const ids = new Set();
const paths = new Set();
const uris = new Set();
for (const [index, fields] of expected.entries()) {
  const [id, role, mediaType, relativePath, uriPath] = fields;
  const artifact = manifest.artifacts[index];
  if (
    artifact.id !== id ||
    artifact.role !== role ||
    artifact.mediaType !== mediaType ||
    artifact.path !== relativePath ||
    artifact.uri !== `${origin}/${uriPath}`
  ) {
    throw new Error(`conformance manifest artifact ${index} metadata or ordering drifted`);
  }
  if (ids.has(id) || paths.has(relativePath) || uris.has(artifact.uri)) {
    throw new Error(`duplicate conformance manifest artifact identity: ${id}`);
  }
  ids.add(id);
  paths.add(relativePath);
  uris.add(artifact.uri);
  const absolutePath = path.resolve(root, relativePath);
  if (!absolutePath.startsWith(`${root}${path.sep}`)) throw new Error(`unsafe artifact path: ${relativePath}`);
  const stat = lstatSync(absolutePath);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`artifact is not a regular file: ${relativePath}`);
  const actual = createHash('sha256').update(readFileSync(absolutePath)).digest('hex');
  if (artifact.sha256 !== actual) throw new Error(`artifact digest drifted: ${relativePath}`);
}

process.stdout.write(`ok - conformance manifest binds ${expected.length} canonical artifacts\n`);

function parseRoot(args) {
  if (args.length === 0) return scriptRoot;
  if (args.length === 2 && args[0] === '--root' && args[1]) return path.resolve(args[1]);
  throw new Error('usage: validate-conformance-manifest.mjs [--root directory]');
}

function decodeUtf8(bytes, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }
}
