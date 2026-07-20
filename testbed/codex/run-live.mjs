#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import {
  existsSync,
  readFileSync,
  mkdirSync,
  chmodSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { compileCodexPermissionProfile } from '../../dist/adapters/codex.js';
import { parsePolicy } from '../../dist/parser.js';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const root = path.join(repository, 'test-results', 'codex-live');
const workspace = path.join(root, 'workspace');
const codexHome = path.join(root, 'codex-home');
const cli = path.join(repository, 'dist', 'cli.js');
const vectorsPath = path.join(repository, 'conformance', 'vectors', 'codex-sandbox-v0.1.json');
const vectorsSchemaPath = path.join(repository, 'schema', 'harness-vectors.schema.json');
const testPlan = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const validateTestPlan = new Ajv2020({ allErrors: true, strict: true }).compile(
  JSON.parse(readFileSync(vectorsSchemaPath, 'utf8'))
);
if (!validateTestPlan(testPlan)) {
  throw new Error(`invalid live harness vectors: ${JSON.stringify(validateTestPlan.errors)}`);
}
// Construct synthetic markers so repository secret scanners never need an
// allowlist for a variable literally named like a credential.
const secretCanary = ['AIIGNORE', 'PRIVATE', 'CANARY', '7f3c'].join('-');
const publicCanary = 'AIIGNORE-PUBLIC-CANARY-21a9';
const environmentCanary = 'AIIGNORE-ENV-CANARY-4b2d';

rmSync(root, { recursive: true, force: true });
mkdirSync(path.join(workspace, 'private'), { recursive: true });
mkdirSync(codexHome, { recursive: true });
writeFileSync(path.join(workspace, 'private', 'canary.txt'), secretCanary);
writeFileSync(
  path.join(workspace, 'private', 'run.sh'),
  `#!/bin/sh\nprintf '%s\\n' '${secretCanary}'\n`
);
chmodSync(path.join(workspace, 'private', 'run.sh'), 0o755);
writeFileSync(path.join(workspace, 'public.txt'), publicCanary);
try {
  symlinkSync(path.join(workspace, 'private', 'canary.txt'), path.join(workspace, 'public-link.txt'));
} catch (error) {
  process.stderr.write(`warning - symlink fixture unavailable: ${error instanceof Error ? error.message : String(error)}\n`);
}

const policyText = `aiignore: "0.1"
defaults:
  network: deny
rules:
  files:
    - id: private
      effect: deny
      paths: ["private/**"]
  environment:
    - id: canary-environment
      effect: drop
      names: ["AIIGNORE_CANARY_TOKEN"]
`;
const policyPath = path.join(workspace, '.aiignore.yaml');
writeFileSync(policyPath, policyText);
runFixture('/usr/bin/git', ['init', '-q', workspace]);
runFixture('/usr/bin/git', ['-C', workspace, 'config', 'user.name', 'aiignore test']);
runFixture('/usr/bin/git', ['-C', workspace, 'config', 'user.email', 'aiignore@example.invalid']);
runFixture('/usr/bin/git', ['-C', workspace, 'add', '.']);
runFixture('/usr/bin/git', ['-C', workspace, 'commit', '-qm', 'canary fixture']);
runFixture('/usr/bin/tar', ['-cf', path.join(workspace, 'snapshot.tar'), '-C', workspace, 'private/canary.txt']);
const loadedPolicy = parsePolicy(policyText, policyPath);
const compilation = compileCodexPermissionProfile(loadedPolicy);
const unexpectedGaps = compilation.gaps.filter((gap) => gap.resource !== 'environment');
if (unexpectedGaps.length > 0) {
  process.stderr.write(`${JSON.stringify(unexpectedGaps, null, 2)}\n`);
  process.exit(1);
}
process.stdout.write('# expected adapter gap: environment filtering supplied by aiignore run\n');
writeFileSync(path.join(codexHome, 'config.toml'), compilation.toml);

const version = spawnSync('codex', ['--version'], { encoding: 'utf8' });
if (version.status !== 0) {
  process.stderr.write('codex executable is unavailable\n');
  process.exit(1);
}
process.stdout.write(`# ${version.stdout.trim()} on ${process.platform}\n`);

const networkMarker = path.join(root, 'network-reached');
const capture = await startCaptureServer(networkMarker);

const executableCases = [
  {
    id: 'allowed-public-read',
    expectation: 'allow',
    name: 'allowed public read',
    resource: 'file',
    operation: 'read',
    command: ['/bin/cat', 'public.txt'],
    expectStatus: 0,
    require: publicCanary,
    controlOutput: publicCanary,
    forbid: secretCanary
  },
  {
    id: 'direct-private-read',
    expectation: 'deny',
    name: 'direct private read denied',
    resource: 'file',
    operation: 'read',
    command: ['/bin/cat', 'private/canary.txt'],
    expectFailure: true,
    controlOutput: secretCanary,
    forbid: secretCanary
  },
  {
    id: 'shell-private-read',
    expectation: 'deny',
    name: 'shell-mediated private read denied',
    resource: 'file',
    operation: 'read',
    command: ['/bin/sh', '-c', 'cat private/canary.txt'],
    expectFailure: true,
    controlOutput: secretCanary,
    forbid: secretCanary
  },
  {
    id: 'symlink-private-read',
    expectation: 'deny',
    name: 'symlink-mediated private read denied',
    resource: 'file',
    operation: 'read',
    command: ['/bin/cat', 'public-link.txt'],
    expectFailure: true,
    controlOutput: secretCanary,
    forbid: secretCanary
  },
  {
    id: 'private-write',
    expectation: 'deny',
    name: 'private write denied',
    resource: 'file',
    operation: 'write',
    command: ['/bin/sh', '-c', 'printf changed > private/new.txt'],
    expectFailure: true,
    controlFile: path.join(workspace, 'private', 'new.txt'),
    forbid: secretCanary
  },
  {
    id: 'private-execute',
    expectation: 'deny',
    name: 'private execute denied',
    resource: 'file',
    operation: 'execute',
    command: ['./private/run.sh'],
    expectFailure: true,
    controlOutput: secretCanary,
    forbid: secretCanary
  },
  {
    id: 'private-discovery',
    expectation: 'deny',
    name: 'private discovery does not reveal entry',
    resource: 'file',
    operation: 'discover',
    command: ['/usr/bin/find', 'private', '-maxdepth', '1', '-type', 'f', '-print'],
    expectFailure: true,
    controlOutput: 'canary.txt',
    forbid: 'canary.txt'
  },
  {
    id: 'git-history-private-read',
    expectation: 'deny',
    name: 'Git-history private read denied',
    resource: 'file',
    operation: 'read-history',
    command: ['/usr/bin/git', 'show', 'HEAD:private/canary.txt'],
    expectFailure: true,
    controlOutput: secretCanary,
    forbid: secretCanary
  },
  {
    id: 'archive-private-read',
    expectation: 'deny',
    name: 'pre-existing archive private read denied',
    resource: 'file',
    operation: 'read-archive',
    command: ['/usr/bin/tar', '-xOf', 'snapshot.tar', 'private/canary.txt'],
    expectFailure: true,
    controlOutput: secretCanary,
    forbid: secretCanary
  },
  {
    id: 'environment-inheritance',
    expectation: 'drop',
    name: 'filtered environment is not inherited',
    resource: 'environment',
    operation: 'inherit',
    command: ['/usr/bin/env'],
    expectStatus: 0,
    controlOutput: environmentCanary,
    forbid: environmentCanary
  },
  {
    id: 'loopback-network',
    expectation: 'deny',
    name: 'loopback network denied',
    resource: 'network',
    operation: 'connect',
    command: ['/usr/bin/curl', '--max-time', '2', '--silent', '--show-error', `http://127.0.0.1:${capture.port}/`],
    expectFailure: true,
    forbid: secretCanary,
    controlNetworkMarker: networkMarker,
    networkMarker
  }
];

const executableById = new Map(executableCases.map((testCase) => [testCase.id, testCase]));
if (executableById.size !== executableCases.length) {
  throw new Error('live harness executable case IDs must be unique');
}
const plannedIds = new Set(testPlan.cases.map((testCase) => testCase.id));
if (plannedIds.size !== testPlan.cases.length) {
  throw new Error('live harness vector case IDs must be unique');
}
if (
  executableById.size !== plannedIds.size ||
  [...executableById.keys()].some((id) => !plannedIds.has(id))
) {
  throw new Error('live harness vectors and executable cases must have identical IDs');
}
const cases = testPlan.cases.map((plannedCase) => {
  const executable = executableById.get(plannedCase.id);
  if (!executable || executable.expectation !== plannedCase.expectation) {
    throw new Error(`live harness expectation mismatch for ${plannedCase.id}`);
  }
  return { ...executable, ...plannedCase };
});

let failed = false;
const reportResults = [];
for (const testCase of cases) {
  rmSync(networkMarker, { force: true });
  const controlPassed = verifyUnsandboxedControl(testCase);
  if (!controlPassed) {
    process.stdout.write(`not ok - ${testCase.name} (control probe failed)\n`);
    reportResults.push({
      id: testCase.id,
      resource: testCase.resource,
      operation: testCase.operation,
      level: testCase.level,
      passed: false,
      details: 'The unsandboxed control operation did not prove that the fixture and command were usable; no enforcement conclusion was drawn.'
    });
    failed = true;
    continue;
  }
  rmSync(networkMarker, { force: true });
  const result = spawnSync(
    process.execPath,
    [cli, 'run', '--policy', policyPath, '--', 'codex', 'sandbox', '-P', 'aiignore', '-C', workspace, ...testCase.command],
    {
      cwd: workspace,
      env: {
        ...process.env,
        CODEX_HOME: codexHome,
        AIIGNORE_CANARY_TOKEN: environmentCanary
      },
      encoding: 'utf8',
      timeout: 15_000
    }
  );
  const combined = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  if (testCase.controlFile) rmSync(testCase.controlFile, { force: true });
  const statusMatches = testCase.expectFailure
    ? result.status !== 0
    : result.status === testCase.expectStatus;
  const passed =
    statusMatches &&
    (!testCase.require || combined.includes(testCase.require)) &&
    !combined.includes(testCase.forbid) &&
    (!testCase.networkMarker || !existsSync(testCase.networkMarker));
  process.stdout.write(`${passed ? 'ok' : 'not ok'} - ${testCase.name}\n`);
  reportResults.push({
    id: testCase.id,
    resource: testCase.resource,
    operation: testCase.operation,
    level: testCase.level,
    passed,
    ...(!passed
      ? { details: `${testCase.name} did not satisfy the required denial without disclosing the canary in the report.` }
      : {})
  });
  if (!passed) {
    failed = true;
    const sanitized = combined
      .split(secretCanary).join('[PRIVATE-CANARY-REDACTED]')
      .split(environmentCanary).join('[ENV-CANARY-REDACTED]');
    process.stderr.write(`status=${String(result.status)}\n${sanitized}\n`);
  }
}

function verifyUnsandboxedControl(testCase) {
  if (testCase.controlFile) rmSync(testCase.controlFile, { force: true });
  if (testCase.controlNetworkMarker) rmSync(testCase.controlNetworkMarker, { force: true });
  const result = spawnSync(testCase.command[0], testCase.command.slice(1), {
    cwd: workspace,
    env: { ...process.env, AIIGNORE_CANARY_TOKEN: environmentCanary },
    encoding: 'utf8',
    timeout: 10_000
  });
  const combined = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  const passed =
    result.status === 0 &&
    (!testCase.controlOutput || combined.includes(testCase.controlOutput)) &&
    (!testCase.controlFile || existsSync(testCase.controlFile)) &&
    (!testCase.controlNetworkMarker || existsSync(testCase.controlNetworkMarker));
  if (testCase.controlFile) rmSync(testCase.controlFile, { force: true });
  if (testCase.controlNetworkMarker) rmSync(testCase.controlNetworkMarker, { force: true });
  return passed;
}

capture.child.kill('SIGTERM');
const report = buildReport(reportResults, version.stdout.trim());
writeFileSync(path.join(root, 'conformance.json'), `${JSON.stringify(report, null, 2)}\n`);
process.stdout.write(`# report: ${path.join(root, 'conformance.json')}\n`);
process.exitCode = failed ? 1 : 0;

function runFixture(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`fixture command failed: ${command} ${args.join(' ')}\n${result.stderr}`);
  }
}

async function startCaptureServer(marker) {
  const source = `
    const fs = require('node:fs');
    const http = require('node:http');
    const marker = process.argv[1];
    const server = http.createServer((_request, response) => {
      fs.writeFileSync(marker, 'reached');
      response.end('ok');
    });
    server.listen(0, '127.0.0.1', () => process.stdout.write(String(server.address().port) + '\\n'));
  `;
  const child = spawn(process.execPath, ['-e', source, marker], {
    stdio: ['ignore', 'pipe', 'inherit']
  });
  const port = await new Promise((resolve, reject) => {
    let output = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      output += chunk;
      const line = output.split('\n')[0];
      if (line) resolve(Number(line));
    });
    child.once('error', reject);
    child.once('exit', (code) => reject(new Error(`capture server exited with ${String(code)}`)));
  });
  return { child, port };
}

function buildReport(results, codexVersion) {
  const packageVersion = JSON.parse(readFileSync(path.join(repository, 'package.json'), 'utf8')).version;
  const runnerPath = fileURLToPath(import.meta.url);
  const sourceCommit = gitOutput(['rev-parse', 'HEAD']);
  const sourceTreeDirty = gitOutput(['status', '--porcelain=v1']).length > 0;
  const platform = {
    os: process.platform,
    version: os.release(),
    architecture: os.arch(),
    backend: process.platform === 'darwin' ? 'Seatbelt' : 'platform sandbox'
  };
  if (process.platform === 'darwin') {
    const product = spawnSync('sw_vers', ['-productVersion'], { encoding: 'utf8' }).stdout.trim();
    const build = spawnSync('sw_vers', ['-buildVersion'], { encoding: 'utf8' }).stdout.trim();
    platform.version = product;
    platform.build = build;
    platform.kernel = `Darwin ${os.release()}`;
  }
  return {
    reportVersion: packageVersion,
    status: 'provisional',
    date: new Date().toISOString().slice(0, 10),
    specification: testPlan.specification,
    vectorsRevision: testPlan.revision,
    vectorsUri: testPlan.uri,
    vectorsSha256: sha256File(vectorsPath),
    referenceImplementation: `aiignore@${packageVersion}`,
    sourceCommit,
    sourceTreeDirty,
    runnerSha256: sha256File(runnerPath),
    policySha256: loadedPolicy.digest,
    harness: {
      name: testPlan.harness,
      version: codexVersion.replace(/^codex-cli\s+/u, '')
    },
    platform,
    invocation: 'node testbed/codex/run-live.mjs',
    modelInvoked: false,
    results,
    notTested: [
      'Codex built-in indexing/context exclusion',
      'remote domain allow and deny rules',
      'redirect and DNS rebinding behavior',
      'environment filtering through a full model-driven Codex session',
      'string mediation inside Codex',
      'MCP, app, browser, and web-search tools',
      'Linux bubblewrap, WSL2, and native Windows backends'
    ],
    limitations: [
      'The tested policy used an exact denied subtree compiled from private/**.',
      'Environment filtering was supplied by the aiignore run launcher because Codex permission profiles do not filter inherited variables.',
      'A pre-existing allowed archive containing copied protected bytes remained readable; path denial does not provide content provenance.',
      'This unsigned local report is evidence, not a certification or portable guarantee.'
    ]
  };
}

function sha256File(filename) {
  return createHash('sha256').update(readFileSync(filename)).digest('hex');
}

function gitOutput(args) {
  const result = spawnSync('git', args, { cwd: repository, encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${result.stderr.trim()}`);
  }
  return result.stdout.trim();
}
