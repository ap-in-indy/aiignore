import { createHash } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const output = path.join(root, 'site-dist');
const canonicalOrigin = 'https://ap-in-indy.github.io/aiignore';

rmSync(output, { force: true, recursive: true });
mkdirSync(output, { recursive: true });
cpSync(path.join(root, 'site'), output, { recursive: true });

copyDirectory('schema', 'schema/0.1');
copyFile('spec/aiignore.md', 'spec/0.1/aiignore.md');
copyFile('spec/registries.md', 'spec/0.1/registries.md');
copyFile('spec/errata.md', 'spec/0.1/errata.md');
copyFile('test/conformance/v0.1.json', 'vectors/0.1/decisions.json');
copyFile('test/conformance/security-v0.1.json', 'vectors/0.1/security.json');
copyFile('test/conformance/options-v0.1.json', 'vectors/0.1/options.json');
copyFile('test/conformance/limits-v0.1.json', 'vectors/0.1/limits.json');
copyFile('test/parser-conformance/v0.1.json', 'vectors/0.1/parser.json');
copyFile('conformance/vectors/codex-sandbox-v0.1.json', 'vectors/0.1/codex-sandbox.json');
copyFile('conformance/manifest-v0.1.json', 'conformance/0.1/manifest.json');
copyFile('conformance/requirements-v0.1.json', 'conformance/0.1/requirements.json');

const schemaDirectory = path.join(output, 'schema', '0.1');
for (const filename of [
  'aiignore.schema.json',
  'decision.schema.json',
  'audit-event.schema.json',
  'readiness-report.schema.json',
  'implementation-conformance-report.schema.json',
  'conformance-report.schema.json',
  'conformance-signature-envelope.schema.json',
  'conformance-vectors.schema.json',
  'parser-vectors.schema.json',
  'harness-vectors.schema.json',
  'conformance-manifest.schema.json',
  'requirements-traceability.schema.json'
]) {
  const schema = JSON.parse(readFileSync(path.join(schemaDirectory, filename), 'utf8'));
  const expectedId = `${canonicalOrigin}/schema/0.1/${filename}`;
  if (schema.$id !== expectedId) {
    throw new Error(`${filename} has $id ${String(schema.$id)}; expected ${expectedId}`);
  }
}

const manifest = [];
writeFileSync(path.join(output, '.nojekyll'), '');
walk(output, (absolutePath) => {
  const relativePath = path.relative(output, absolutePath).split(path.sep).join('/');
  if (relativePath === 'SHA256SUMS' || relativePath === '.nojekyll') return;
  const bytes = readFileSync(absolutePath);
  manifest.push(`${createHash('sha256').update(bytes).digest('hex')}  ${relativePath}`);
});
writeFileSync(path.join(output, 'SHA256SUMS'), `${manifest.sort().join('\n')}\n`);
validateLocalLinks('index.html');

function copyDirectory(source, destination) {
  const target = path.join(output, destination);
  mkdirSync(path.dirname(target), { recursive: true });
  cpSync(path.join(root, source), target, { recursive: true });
}

function copyFile(source, destination) {
  const target = path.join(output, destination);
  mkdirSync(path.dirname(target), { recursive: true });
  cpSync(path.join(root, source), target);
}

function validateLocalLinks(relativeHtmlPath) {
  const html = readFileSync(path.join(output, relativeHtmlPath), 'utf8');
  for (const match of html.matchAll(/href="([^"]+)"/gu)) {
    const target = match[1];
    if (!target || /^(?:https?:|#)/u.test(target)) continue;
    const absoluteTarget = path.resolve(output, path.dirname(relativeHtmlPath), target);
    if (!absoluteTarget.startsWith(`${output}${path.sep}`) || !existsSync(absoluteTarget)) {
      throw new Error(`${relativeHtmlPath} contains missing or unsafe local link: ${target}`);
    }
  }
}

function walk(directory, visit) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(absolutePath, visit);
    else if (statSync(absolutePath).isFile()) visit(absolutePath);
  }
}
