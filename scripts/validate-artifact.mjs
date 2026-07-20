import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const npmEntrypoint = process.env.npm_execpath;
if (!npmEntrypoint) {
  throw new Error('artifact validation must run through npm so its portable entry point is known');
}

const temporaryRoot = mkdtempSync(path.join(tmpdir(), 'aiignore-artifact-'));
try {
  const first = pack(path.join(temporaryRoot, 'pack-one'));
  const second = pack(path.join(temporaryRoot, 'pack-two'));
  const firstBytes = readFileSync(first.path);
  const secondBytes = readFileSync(second.path);
  if (!firstBytes.equals(secondBytes)) {
    throw new Error('two independent npm packs were not byte-for-byte reproducible');
  }

  const consumer = path.join(temporaryRoot, 'consumer');
  mkdirSync(consumer);
  writeFileSync(
    path.join(consumer, 'package.json'),
    `${JSON.stringify({ name: 'aiignore-artifact-consumer', private: true, type: 'module' }, null, 2)}\n`
  );
  runNpm(
    [
      'install',
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
      '--package-lock=false',
      '--prefer-offline',
      first.path
    ],
    consumer
  );

  const version = runNpm(['exec', '--', 'aiignore', '--version'], consumer);
  if (version.stdout !== `${first.version}\n` || version.stderr !== '') {
    throw new Error('installed npm binary did not produce the exact package version');
  }
  const initialized = runNpm(['exec', '--', 'aiignore', 'init', '--json'], consumer);
  const initResult = JSON.parse(initialized.stdout);
  if (
    initResult.profile !== 'recommended' ||
    !/^[a-f0-9]{64}$/u.test(initResult.policyDigest) ||
    !existsSync(path.join(consumer, '.aiignore.yaml'))
  ) {
    throw new Error('installed npm binary did not create the recommended policy safely');
  }
  const validated = runNpm(['exec', '--', 'aiignore', 'validate', '--json'], consumer);
  const validationResult = JSON.parse(validated.stdout);
  if (!validationResult.valid || validationResult.policyDigest !== initResult.policyDigest) {
    throw new Error('installed npm binary did not validate the initialized policy');
  }

  writeConsumerRuntimeCheck(consumer);
  run(process.execPath, ['consumer-check.mjs'], consumer);
  run(
    process.execPath,
    [
      path.join(consumer, 'node_modules', first.name, 'test', 'fuzz', 'fuzz.mjs'),
      '--iterations',
      '100',
      '--seed',
      '0xa17fac7'
    ],
    consumer
  );
  writeConsumerTypeCheck(consumer);
  run(
    process.execPath,
    [path.join(root, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', 'tsconfig.json'],
    consumer
  );

  const sha256 = createHash('sha256').update(firstBytes).digest('hex');
  process.stdout.write(
    `ok - reproducible installed artifact ${first.filename} sha256 ${sha256}\n`
  );
} finally {
  rmSync(temporaryRoot, { recursive: true, force: true });
}

function pack(destination) {
  mkdirSync(destination);
  const result = runNpm(
    ['pack', '--silent', '--json', '--pack-destination', destination],
    root
  );
  const [metadata] = JSON.parse(result.stdout);
  if (!metadata?.filename || !metadata.name || !metadata.version) {
    throw new Error('npm pack returned invalid metadata');
  }
  return {
    filename: metadata.filename,
    name: metadata.name,
    version: metadata.version,
    path: path.resolve(destination, metadata.filename)
  };
}

function runNpm(args, cwd) {
  return run(process.execPath, [npmEntrypoint, ...args], cwd);
}

function run(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024
  });
  if (result.status !== 0) {
    throw new Error(
      `${path.basename(command)} ${args.join(' ')} failed (${String(result.status)}): ${result.stderr || result.error?.message || result.stdout}`
    );
  }
  return result;
}

function writeConsumerRuntimeCheck(consumer) {
  writeFileSync(
    path.join(consumer, 'consumer-check.mjs'),
    `import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  AIIGNORE_SCHEMA,
  AUDIT_EVENT_SCHEMA,
  CONFORMANCE_SIGNATURE_ENVELOPE_SCHEMA,
  DECISION_SCHEMA,
  IMPLEMENTATION_CONFORMANCE_REPORT_SCHEMA,
  READINESS_REPORT_SCHEMA,
  PACKAGE_VERSION,
  PolicyEngine,
  SPEC_VERSION,
  compileCodexPermissionProfile,
  createAuditEvent,
  createReferenceConformanceReport,
  verifyImplementationConformanceBundle,
  assessReadiness,
  parsePolicy,
  runConformanceFile,
  runParserConformanceFile,
  signConformanceReport,
  verifyConformanceReport
} from 'aiignore';

assert.equal(PACKAGE_VERSION, ${JSON.stringify(readPackageVersion())});
assert.equal(SPEC_VERSION, '0.1');
assert.equal(AIIGNORE_SCHEMA.properties.aiignore.const, SPEC_VERSION);
assert.equal(DECISION_SCHEMA.properties.policyDigest.pattern, '^[a-f0-9]{64}$');
assert.equal(AUDIT_EVENT_SCHEMA.properties.formatVersion.const, SPEC_VERSION);
assert.equal(READINESS_REPORT_SCHEMA.properties.deploymentEnforcement.const, 'not-established');
assert.equal(IMPLEMENTATION_CONFORMANCE_REPORT_SCHEMA.properties.reportType.const, 'implementation');
assert.equal(CONFORMANCE_SIGNATURE_ENVELOPE_SCHEMA.properties.signatureAlgorithm.const, 'ed25519');
assert.equal(typeof signConformanceReport, 'function');
assert.equal(typeof verifyConformanceReport, 'function');
const loaded = parsePolicy(new TextEncoder().encode('aiignore: "0.1"\\ndefaults: {files: deny}\\n'));
assert.equal(Object.isFrozen(loaded), true);
assert.equal(Object.isFrozen(loaded.document), true);
const engine = new PolicyEngine(loaded);
assert.equal(engine.decideFile('private.txt', 'read').effect, 'deny');
const audited = new PolicyEngine(parsePolicy('aiignore: "0.1"\\nrules: {files: [{id: observed, effect: audit, paths: ["**"]}]}\\n')).decideFile('file.txt', 'read');
assert.equal(createAuditEvent(audited).formatVersion, SPEC_VERSION);
assert.equal(assessReadiness(loaded).deploymentEnforcement, 'not-established');
assert.equal(compileCodexPermissionProfile(loaded).exact, false);

const jsonAssets = [
  ['aiignore/schema', 'https://ap-in-indy.github.io/aiignore/schema/0.1/aiignore.schema.json'],
  ['aiignore/decision-schema', 'https://ap-in-indy.github.io/aiignore/schema/0.1/decision.schema.json'],
  ['aiignore/audit-event-schema', 'https://ap-in-indy.github.io/aiignore/schema/0.1/audit-event.schema.json'],
  ['aiignore/readiness-report-schema', 'https://ap-in-indy.github.io/aiignore/schema/0.1/readiness-report.schema.json'],
  ['aiignore/implementation-conformance-report-schema', 'https://ap-in-indy.github.io/aiignore/schema/0.1/implementation-conformance-report.schema.json'],
  ['aiignore/conformance-schema', 'https://ap-in-indy.github.io/aiignore/schema/0.1/conformance-report.schema.json'],
  ['aiignore/conformance-signature-envelope-schema', 'https://ap-in-indy.github.io/aiignore/schema/0.1/conformance-signature-envelope.schema.json'],
  ['aiignore/conformance-vectors-schema', 'https://ap-in-indy.github.io/aiignore/schema/0.1/conformance-vectors.schema.json'],
  ['aiignore/parser-vectors-schema', 'https://ap-in-indy.github.io/aiignore/schema/0.1/parser-vectors.schema.json'],
  ['aiignore/harness-vectors-schema', 'https://ap-in-indy.github.io/aiignore/schema/0.1/harness-vectors.schema.json'],
  ['aiignore/conformance-manifest-schema', 'https://ap-in-indy.github.io/aiignore/schema/0.1/conformance-manifest.schema.json'],
  ['aiignore/requirements-traceability-schema', 'https://ap-in-indy.github.io/aiignore/schema/0.1/requirements-traceability.schema.json']
];
for (const [specifier, expectedId] of jsonAssets) {
  const value = JSON.parse(readFileSync(fileURLToPath(import.meta.resolve(specifier)), 'utf8'));
  assert.equal(value.$id, expectedId);
}
const manifestPath = fileURLToPath(import.meta.resolve('aiignore/conformance-manifest'));
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
assert.equal(manifest.uri, 'https://ap-in-indy.github.io/aiignore/conformance/0.1/manifest.json');
assert.equal(manifest.artifacts.length, 22);
const packageRoot = path.resolve(path.dirname(manifestPath), '..');
for (const artifact of manifest.artifacts) {
  const bytes = readFileSync(path.join(packageRoot, artifact.path));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), artifact.sha256);
}
const requirements = JSON.parse(readFileSync(fileURLToPath(import.meta.resolve('aiignore/requirements-traceability')), 'utf8'));
assert.equal(requirements.sections.length, 16);
const decisionVectorSpecifiers = [
  'aiignore/vectors/decisions',
  'aiignore/vectors/security',
  'aiignore/vectors/options',
  'aiignore/vectors/limits'
];
const parserVectors = fileURLToPath(import.meta.resolve('aiignore/vectors/parser'));
for (const specifier of decisionVectorSpecifiers) {
  assert.equal(runConformanceFile(fileURLToPath(import.meta.resolve(specifier))).conformant, true);
}
assert.equal(runParserConformanceFile(parserVectors).conformant, true);
const implementationReport = createReferenceConformanceReport({
  manifestPath,
  date: '2026-07-16',
  sourceUri: 'https://example.invalid/installed-consumer-check.tgz',
  sourceRevision: 'installed-consumer-check',
  sourceSha256: '0'.repeat(64),
  sourceTreeDirty: false,
  runnerVersion: PACKAGE_VERSION,
  runnerSha256: '1'.repeat(64)
});
assert.equal(implementationReport.summary.conformant, true);
assert.equal(implementationReport.summary.total, 163);
const implementationReportBytes = Buffer.from(JSON.stringify(implementationReport));
assert.deepEqual(
  verifyImplementationConformanceBundle(implementationReportBytes, manifestPath),
  {
    valid: true,
    reportSha256: createHash('sha256').update(implementationReportBytes).digest('hex'),
    manifestSha256: createHash('sha256').update(readFileSync(manifestPath)).digest('hex'),
    status: 'provisional',
    conformant: true,
    suites: 5
  }
);
const harnessVectors = JSON.parse(
  readFileSync(fileURLToPath(import.meta.resolve('aiignore/vectors/codex-sandbox')), 'utf8')
);
assert.equal(harnessVectors.specification, SPEC_VERSION);
assert.equal(harnessVectors.cases.length, 11);
const recommended = readFileSync(fileURLToPath(import.meta.resolve('aiignore/profiles/recommended')));
assert.equal(parsePolicy(recommended).document.metadata?.name, 'recommended-secrets-baseline');
`,
    'utf8'
  );
}

function writeConsumerTypeCheck(consumer) {
  writeFileSync(
    path.join(consumer, 'consumer.mts'),
    `import {
  PolicyEngine,
  parsePolicy,
  signConformanceReport,
  verifyConformanceReport,
  type Decision,
  type LoadedPolicy,
  type PolicyDocument,
  type SignConformanceReportOptions,
  type VerifyConformanceReportOptions
} from 'aiignore';

const loaded: LoadedPolicy = parsePolicy(new Uint8Array([0x61]));
const document: PolicyDocument = loaded.document;
const decision: Decision = new PolicyEngine(loaded).decideEnvironment('EXAMPLE');
const environment: Record<string, string | undefined> = { EXAMPLE: 'value', EMPTY: undefined };
new PolicyEngine(loaded).filterEnvironment(environment);
const signOptions: SignConformanceReportOptions = {
  identity: 'https://example.invalid/signer',
  envelopeUri: 'https://example.invalid/report.signature.json'
};
const verifyOptions: VerifyConformanceReportOptions = {
  expectedIdentity: signOptions.identity,
  expectedPublicKeySha256: '0'.repeat(64)
};
void signConformanceReport;
void verifyConformanceReport;
void verifyOptions;
void document;
void decision;
`,
    'utf8'
  );
  writeFileSync(
    path.join(consumer, 'tsconfig.json'),
    `${JSON.stringify(
      {
        compilerOptions: {
          strict: true,
          noEmit: true,
          target: 'ES2022',
          module: 'NodeNext',
          moduleResolution: 'NodeNext',
          skipLibCheck: false,
          types: []
        },
        files: ['consumer.mts']
      },
      null,
      2
    )}\n`
  );
}

function readPackageVersion() {
  return JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')).version;
}
