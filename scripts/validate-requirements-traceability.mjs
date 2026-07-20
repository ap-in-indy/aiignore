import { lstatSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv2020 } from 'ajv/dist/2020.js';

const scriptRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const root = parseRoot(process.argv.slice(2));
const catalogPath = path.join(root, 'conformance/requirements-v0.1.json');
const reviewedCatalogSha256 = 'fd6ada657b2cc10223623827eac2c07ecf3d5c461aad5240f835c7872ffa6182';
const catalog = readJson(catalogPath, 'requirements traceability catalog');
const schema = readJson(
  path.join(root, 'schema/requirements-traceability.schema.json'),
  'requirements traceability schema'
);
const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
if (!validate(catalog)) {
  throw new Error(`invalid requirements traceability catalog: ${JSON.stringify(validate.errors)}`);
}
const catalogSha256 = createHash('sha256').update(readFileSync(catalogPath)).digest('hex');
if (catalogSha256 !== reviewedCatalogSha256) {
  throw new Error('requirements traceability claims differ from the reviewed catalog');
}

const specification = decodeUtf8(
  readFileSync(path.join(root, 'spec/aiignore.md')),
  'specification'
);
const headings = [...specification.matchAll(/^## (\d+)\. ([^\n]+)$/gmu)];
if (headings.length !== 16) throw new Error('specification must contain exactly 16 top-level sections');

const expectedAssurance = [
  'informational',
  'implemented',
  'implemented',
  'implemented',
  'implemented-with-external-limits',
  'implemented-with-external-limits',
  'implemented-with-external-limits',
  'implemented-with-external-limits',
  'implemented-with-external-limits',
  'implemented',
  'implemented-with-external-limits',
  'process',
  'implemented-with-external-limits',
  'implemented-with-external-limits',
  'process',
  'informational'
];
const expectedEvidenceMinimums = [2, 3, 3, 4, 4, 3, 4, 4, 3, 4, 5, 4, 4, 3, 5, 2];
let normativeKeywordTotal = 0;

for (const [index, heading] of headings.entries()) {
  const section = catalog.sections[index];
  const number = Number(heading[1]);
  const title = heading[2];
  const start = (heading.index ?? 0) + heading[0].length;
  const end = headings[index + 1]?.index ?? specification.length;
  const sectionText = specification.slice(start, end).replace(/```[\s\S]*?```/gu, '');
  const normativeKeywordCount = (
    sectionText.match(/\b(?:MUST NOT|SHOULD NOT|MUST|SHOULD|MAY|REQUIRED)\b/gu) ?? []
  ).length;
  normativeKeywordTotal += normativeKeywordCount;

  if (
    section.section !== number ||
    section.title !== title ||
    section.normativeKeywordCount !== normativeKeywordCount
  ) {
    throw new Error(`traceability metadata drifted for specification section ${number}`);
  }
  if (section.assurance !== expectedAssurance[index]) {
    throw new Error(`traceability assurance for section ${number} must remain ${expectedAssurance[index]}`);
  }
  if (section.evidence.length < expectedEvidenceMinimums[index]) {
    throw new Error(`traceability evidence for section ${number} is incomplete`);
  }
  if (
    section.assurance === 'implemented' && section.limitations.length !== 0 ||
    section.assurance !== 'implemented' && section.limitations.length === 0
  ) {
    throw new Error(`traceability limitations do not match assurance for section ${number}`);
  }
  for (const evidence of section.evidence) validateEvidence(root, evidence, number);
}

if (normativeKeywordTotal !== 151) {
  throw new Error(`normative keyword inventory changed from 151 to ${normativeKeywordTotal}`);
}

process.stdout.write(
  `ok - 16 specification sections map an inventory of ${normativeKeywordTotal} normative keywords to explicit evidence or limitations\n`
);

function validateEvidence(repositoryRoot, reference, section) {
  const [relativePath] = reference.split('#', 1);
  const absolutePath = path.resolve(repositoryRoot, relativePath);
  if (!absolutePath.startsWith(`${repositoryRoot}${path.sep}`)) {
    throw new Error(`unsafe traceability evidence path in section ${section}`);
  }
  let stat;
  try {
    stat = lstatSync(absolutePath);
  } catch {
    throw new Error(`missing traceability evidence in section ${section}: ${relativePath}`);
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`traceability evidence is not a regular file in section ${section}: ${relativePath}`);
  }
}

function readJson(filename, label) {
  const bytes = readFileSync(filename);
  if (bytes.byteLength > 256 * 1024) throw new Error(`${label} exceeds 262144 bytes`);
  try {
    return JSON.parse(decodeUtf8(bytes, label));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${label} is not valid JSON`);
    throw error;
  }
}

function decodeUtf8(bytes, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }
}

function parseRoot(args) {
  if (args.length === 0) return scriptRoot;
  if (args.length === 2 && args[0] === '--root' && args[1]) return path.resolve(args[1]);
  throw new Error('usage: validate-requirements-traceability.mjs [--root directory]');
}
