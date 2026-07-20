#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { spawn } from 'node:child_process';
import {
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compileCodexPermissionProfile } from './adapters/codex.js';
import { evaluateCodexPreToolUse } from './adapters/codex-hook.js';
import { compileGeminiConfiguration } from './adapters/gemini.js';
import { evaluateGeminiBeforeTool } from './adapters/gemini-hook.js';
import { createAuditEvent } from './audit.js';
import { runConformanceFile } from './conformance.js';
import {
  isLegacyIgnoreFilename,
  PACKAGE_VERSION,
  POLICY_FILENAME,
  SPEC_VERSION
} from './constants.js';
import { PolicyEngine } from './engine.js';
import { PolicyError } from './errors.js';
import {
  createReferenceConformanceReport,
  MAX_IMPLEMENTATION_REPORT_BYTES,
  verifyImplementationConformanceBundle
} from './implementation-conformance.js';
import { loadPinnedPolicy, parsePolicy } from './parser.js';
import { assessReadiness } from './readiness.js';
import { runParserConformanceFile } from './parser-conformance.js';
import { readBoundedRegularFile } from './safe-file.js';
import {
  MAX_CONFORMANCE_ENVELOPE_BYTES,
  MAX_CONFORMANCE_REPORT_BYTES,
  signConformanceReport,
  verifyConformanceReport
} from './report-signature.js';
import {
  FILE_OPERATIONS,
  STRING_SCOPES,
  type Decision
} from './types.js';

const EXIT_INVALID = 2;
const EXIT_DENIED = 3;
const EXIT_PARTIAL = 4;
export const MAX_INPUT_BYTES = 8 * 1024 * 1024;

type ReadInput = () => Promise<string>;

export async function main(
  argv = process.argv.slice(2),
  readInput: ReadInput = readStdin
): Promise<number> {
  const [command, ...rest] = argv;
  try {
    switch (command) {
      case 'validate':
        return validateCommand(rest);
      case 'doctor':
        return doctorCommand(rest);
      case 'init':
        return initCommand(rest);
      case 'check':
        return checkCommand(rest);
      case 'scan':
        return await scanCommand(rest, readInput);
      case 'filter-env':
        return filterEnvironmentCommand(rest);
      case 'run':
        return await runCommand(rest);
      case 'conformance':
        return conformanceCommand(rest);
      case 'parser-conformance':
        return parserConformanceCommand(rest);
      case 'reference-conformance-report':
        return referenceConformanceReportCommand(rest);
      case 'verify-implementation-report':
        return verifyImplementationReportCommand(rest);
      case 'sign-report':
        return signReportCommand(rest);
      case 'verify-report':
        return verifyReportCommand(rest);
      case 'compile':
        return compileCommand(rest);
      case 'hook':
        return await hookCommand(rest, readInput);
      case 'help':
      case '--help':
      case '-h':
      case undefined:
        process.stdout.write(help());
        return 0;
      case '--version':
      case '-V':
        process.stdout.write(`${PACKAGE_VERSION}\n`);
        return 0;
      default:
        throw new PolicyError('usage', `unknown command: ${command}`);
    }
  } catch (error) {
    const parseArgsError = isParseArgsError(error);
    const payload = {
      error: error instanceof PolicyError ? error.code : parseArgsError ? 'usage' : 'unexpected_error',
      message: error instanceof Error ? error.message : String(error)
    };
    process.stderr.write(`${JSON.stringify(payload)}\n`);
    return EXIT_INVALID;
  }
}

function validateCommand(argv: string[]): number {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { json: { type: 'boolean', default: false } }
  });
  const policy = loadPinnedPolicy(positionals[0] ?? POLICY_FILENAME);
  const result = { valid: true, source: policy.source, policyDigest: policy.digest, version: SPEC_VERSION };
  process.stdout.write(values.json ? `${JSON.stringify(result)}\n` : `valid ${policy.digest} ${policy.source}\n`);
  return 0;
}

function doctorCommand(argv: string[]): number {
  const { values } = parseArgs({
    args: argv,
    options: {
      policy: { type: 'string', default: POLICY_FILENAME },
      json: { type: 'boolean', default: false }
    }
  });
  const report = assessReadiness(loadPinnedPolicy(values.policy));
  if (values.json) {
    process.stdout.write(`${JSON.stringify(report)}\n`);
    return 0;
  }
  const adapter = (name: 'codex' | 'gemini'): string => {
    const summary = report.adapters[name];
    return `${name}=${summary.compilationExact ? 'exact' : 'partial'} (${summary.errorGaps} error gaps, ${summary.warningGaps} warning gaps)`;
  };
  process.stdout.write(
    [
      `policy valid: ${report.policyDigest}`,
      'deployment enforcement: NOT ESTABLISHED',
      `defaults: files=${report.defaults.files} environment=${report.defaults.environment} network=${report.defaults.network} strings=${report.defaults.strings}`,
      `rules: files=${report.ruleCounts.files} environment=${report.ruleCounts.environment} network=${report.ruleCounts.network} strings=${report.ruleCounts.strings}`,
      `adapter compilation: ${adapter('codex')}; ${adapter('gemini')}`,
      'findings:',
      ...report.findings.map(
        (finding) => `- ${finding.severity.toUpperCase()} ${finding.id}: ${finding.message}`
      )
    ].join('\n') + '\n'
  );
  return 0;
}

function initCommand(argv: string[]): number {
  const { values } = parseArgs({
    args: argv,
    options: {
      path: { type: 'string', default: POLICY_FILENAME },
      json: { type: 'boolean', default: false }
    }
  });
  const destination = path.resolve(values.path);
  if (isLegacyIgnoreFilename(path.basename(destination))) {
    throw new PolicyError(
      'legacy_ignore_filename',
      `exact .aiignore is reserved for gitignore-style compatibility; use ${POLICY_FILENAME}`
    );
  }
  let bytes: Buffer;
  try {
    bytes = readFileSync(new URL('../profiles/recommended.aiignore.yaml', import.meta.url));
  } catch {
    throw new PolicyError('profile_unavailable', 'the packaged recommended profile is unavailable');
  }
  const policy = parsePolicy(bytes, destination);
  try {
    writeFileSync(destination, bytes, { flag: 'wx', mode: 0o644 });
  } catch (error) {
    if (isErrorCode(error, 'EEXIST')) {
      throw new PolicyError('policy_exists', `refusing to overwrite existing path: ${destination}`);
    }
    throw new PolicyError('policy_unwritable', `cannot create policy file: ${destination}`);
  }
  const result = { created: destination, policyDigest: policy.digest, profile: 'recommended' };
  process.stdout.write(
    values.json
      ? `${JSON.stringify(result)}\n`
      : `created ${destination}\nvalidate and review every rule before enforcement\n`
  );
  return 0;
}

function checkCommand(argv: string[]): number {
  const [resource, candidate, ...rest] = argv;
  if (!resource || !candidate) throw new PolicyError('usage', 'usage: aiignore check <file|env|network> <candidate>');
  const { values } = parseArgs({
    args: rest,
    options: {
      policy: { type: 'string', default: POLICY_FILENAME },
      operation: { type: 'string', default: 'read' },
      root: { type: 'string' },
      json: { type: 'boolean', default: false }
    }
  });
  const policy = loadPinnedPolicy(values.policy);
  const engine = new PolicyEngine(policy);
  let decision: Decision;
  if (resource === 'file') {
    if (!FILE_OPERATIONS.includes(values.operation as (typeof FILE_OPERATIONS)[number])) {
      throw new PolicyError('usage', `invalid file operation: ${values.operation}`);
    }
    decision = engine.decideFile(
      candidate,
      values.operation as (typeof FILE_OPERATIONS)[number],
      values.root ?? policy.root
    );
  } else if (resource === 'env' || resource === 'environment') {
    decision = engine.decideEnvironment(candidate);
  } else if (resource === 'network') decision = engine.decideNetwork(candidate);
  else throw new PolicyError('usage', `unknown resource: ${resource}`);
  writeDecision(decision, values.json);
  return isBlocking(decision) ? EXIT_DENIED : 0;
}

async function scanCommand(argv: string[], readInput: ReadInput): Promise<number> {
  const { values } = parseArgs({
    args: argv,
    options: {
      policy: { type: 'string', default: POLICY_FILENAME },
      scope: { type: 'string' },
      json: { type: 'boolean', default: false }
    }
  });
  if (!values.scope || !STRING_SCOPES.includes(values.scope as (typeof STRING_SCOPES)[number])) {
    throw new PolicyError('usage', `--scope must be one of: ${STRING_SCOPES.join(', ')}`);
  }
  const input = await readInput();
  const decision = new PolicyEngine(loadPinnedPolicy(values.policy)).decideString(
    input,
    values.scope as (typeof STRING_SCOPES)[number]
  );
  writeDecision(decision, values.json);
  if (decision.effect === 'redact' && !values.json) process.stdout.write(`${decision.output ?? ''}\n`);
  return isBlocking(decision) ? EXIT_DENIED : 0;
}

function filterEnvironmentCommand(argv: string[]): number {
  const { values } = parseArgs({
    args: argv,
    options: {
      policy: { type: 'string', default: POLICY_FILENAME },
      json: { type: 'boolean', default: true }
    }
  });
  const result = new PolicyEngine(loadPinnedPolicy(values.policy)).filterEnvironment(process.env);
  const output = {
    retained: Object.keys(result.environment),
    dropped: decisionNames(result.decisions, 'drop'),
    denied: result.denied,
    nameRedacted: decisionNames(result.decisions, 'redact'),
    nameAudited: decisionNames(result.decisions, 'audit'),
    valueRedacted: decisionNames(result.valueDecisions, 'redact'),
    valueAudited: decisionNames(result.valueDecisions, 'audit'),
    policyDigest: Object.values(result.decisions)[0]?.policyDigest ?? null
  };
  process.stdout.write(`${JSON.stringify(output, null, values.json ? 0 : 2)}\n`);
  return result.denied.length > 0 ? EXIT_DENIED : 0;
}

function conformanceCommand(argv: string[]): number {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { json: { type: 'boolean', default: false } }
  });
  const result = runConformanceFile(positionals[0] ?? 'test/conformance/v0.1.json');
  process.stdout.write(
    values.json
      ? `${JSON.stringify(result)}\n`
      : `${result.conformant ? 'conformant' : 'non-conformant'} ${result.passed}/${result.total} revision ${result.revision} vectors ${result.vectorsSha256} policy ${result.policyDigest}\n`
  );
  return result.conformant ? 0 : EXIT_PARTIAL;
}

function parserConformanceCommand(argv: string[]): number {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { json: { type: 'boolean', default: false } }
  });
  const result = runParserConformanceFile(
    positionals[0] ?? 'test/parser-conformance/v0.1.json'
  );
  process.stdout.write(
    values.json
      ? `${JSON.stringify(result)}\n`
      : `${result.conformant ? 'conformant' : 'non-conformant'} ${result.passed}/${result.total} parser revision ${result.revision} vectors ${result.vectorsSha256}\n`
  );
  return result.conformant ? 0 : EXIT_PARTIAL;
}

function referenceConformanceReportCommand(argv: string[]): number {
  const { values } = parseArgs({
    args: argv,
    options: {
      manifest: { type: 'string', default: 'conformance/manifest-v0.1.json' },
      date: { type: 'string' },
      'source-uri': { type: 'string' },
      'source-revision': { type: 'string' },
      'source-sha256': { type: 'string' },
      'runner-sha256': { type: 'string' },
      'source-dirty': { type: 'boolean', default: false }
    }
  });
  if (
    !values.date ||
    !values['source-uri'] ||
    !values['source-revision'] ||
    !values['source-sha256'] ||
    !values['runner-sha256']
  ) {
    throw new PolicyError(
      'usage',
      'usage: aiignore reference-conformance-report --date YYYY-MM-DD --source-uri <https-uri> --source-revision <revision> --source-sha256 <sha256> --runner-sha256 <sha256> [--source-dirty] [--manifest <manifest.json>]'
    );
  }
  const report = createReferenceConformanceReport({
    manifestPath: values.manifest,
    date: values.date,
    sourceUri: values['source-uri'],
    sourceRevision: values['source-revision'],
    sourceSha256: values['source-sha256'],
    sourceTreeDirty: values['source-dirty'],
    runnerVersion: PACKAGE_VERSION,
    runnerSha256: values['runner-sha256']
  });
  process.stdout.write(`${JSON.stringify(report)}\n`);
  return report.summary.conformant ? 0 : EXIT_PARTIAL;
}

function verifyImplementationReportCommand(argv: string[]): number {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      manifest: { type: 'string', default: 'conformance/manifest-v0.1.json' },
      json: { type: 'boolean', default: false }
    }
  });
  const [reportPath, ...extra] = positionals;
  if (!reportPath || extra.length > 0) {
    throw new PolicyError(
      'usage',
      'usage: aiignore verify-implementation-report <report.json> [--manifest <manifest.json>] [--json]'
    );
  }
  const result = verifyImplementationConformanceBundle(
    readCliInputFile(reportPath, MAX_IMPLEMENTATION_REPORT_BYTES, 'implementation report'),
    values.manifest
  );
  process.stdout.write(
    values.json
      ? `${JSON.stringify(result)}\n`
      : `valid implementation report ${result.reportSha256} manifest ${result.manifestSha256} suites ${result.suites} status ${result.status} ${result.conformant ? 'conformant' : 'non-conformant'}\n`
  );
  return result.conformant && result.status !== 'withdrawn' ? 0 : EXIT_PARTIAL;
}

function signReportCommand(argv: string[]): number {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      key: { type: 'string' },
      identity: { type: 'string' },
      issuer: { type: 'string' },
      'envelope-uri': { type: 'string' },
      'report-out': { type: 'string' },
      'envelope-out': { type: 'string' }
    }
  });
  const [inputReport, ...extra] = positionals;
  if (
    !inputReport ||
    extra.length > 0 ||
    !values.key ||
    !values.identity ||
    !values['envelope-uri'] ||
    !values['report-out'] ||
    !values['envelope-out']
  ) {
    throw new PolicyError(
      'usage',
      'usage: aiignore sign-report <provisional-report.json> --key <private.pem> --identity <identity> --envelope-uri <https-uri> --report-out <verified.json> --envelope-out <signature.json> [--issuer <issuer>]'
    );
  }
  const reportOut = path.resolve(values['report-out']);
  const envelopeOut = path.resolve(values['envelope-out']);
  if (reportOut === envelopeOut) {
    throw new PolicyError('usage', 'verified report and signature envelope outputs must differ');
  }
  const signed = signConformanceReport(
    readCliInputFile(inputReport, MAX_CONFORMANCE_REPORT_BYTES, 'conformance report'),
    readCliInputFile(values.key, 64 * 1024, 'private key'),
    {
      identity: values.identity,
      ...(values.issuer === undefined ? {} : { issuer: values.issuer }),
      envelopeUri: values['envelope-uri']
    }
  );
  try {
    writeFileSync(envelopeOut, signed.envelopeBytes, { flag: 'wx', mode: 0o644 });
    try {
      writeFileSync(reportOut, signed.reportBytes, { flag: 'wx', mode: 0o644 });
    } catch (error) {
      rmSync(envelopeOut, { force: true });
      throw error;
    }
  } catch (error) {
    if (isErrorCode(error, 'EEXIST')) {
      throw new PolicyError('output_exists', 'refusing to overwrite a report or envelope output');
    }
    throw new PolicyError('output_unwritable', 'cannot create report signature outputs');
  }
  process.stdout.write(
    `${JSON.stringify({
      signed: true,
      report: reportOut,
      envelope: envelopeOut,
      reportSha256: signed.reportSha256,
      publicKeySha256: signed.publicKeySha256
    })}\n`
  );
  return 0;
}

function verifyReportCommand(argv: string[]): number {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      identity: { type: 'string' },
      issuer: { type: 'string' },
      'key-sha256': { type: 'string' },
      json: { type: 'boolean', default: false }
    }
  });
  const [reportPath, envelopePath, ...extra] = positionals;
  if (!reportPath || !envelopePath || extra.length > 0 || !values.identity || !values['key-sha256']) {
    throw new PolicyError(
      'usage',
      'usage: aiignore verify-report <verified-report.json> <signature.json> --identity <trusted-identity> --key-sha256 <trusted-fingerprint> [--issuer <trusted-issuer>] [--json]'
    );
  }
  const result = verifyConformanceReport(
    readCliInputFile(reportPath, MAX_CONFORMANCE_REPORT_BYTES, 'conformance report'),
    readCliInputFile(envelopePath, MAX_CONFORMANCE_ENVELOPE_BYTES, 'signature envelope'),
    {
      expectedIdentity: values.identity,
      expectedPublicKeySha256: values['key-sha256'],
      ...(values.issuer === undefined ? {} : { expectedIssuer: values.issuer })
    }
  );
  process.stdout.write(
    values.json
      ? `${JSON.stringify(result)}\n`
      : `verified ${result.reportSha256} identity ${result.identity} key ${result.publicKeySha256}\n`
  );
  return 0;
}

async function runCommand(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      policy: { type: 'string', default: POLICY_FILENAME },
      root: { type: 'string' }
    }
  });
  const [command, ...args] = positionals;
  if (!command) {
    throw new PolicyError('usage', `usage: aiignore run [--policy ${POLICY_FILENAME}] -- <command> [args...]`);
  }
  const policy = loadPinnedPolicy(values.policy);
  const policyRoot = path.resolve(values.root ?? policy.root);
  const result = new PolicyEngine(policy).filterEnvironment(process.env);
  if (result.denied.length > 0) {
    throw new PolicyError(
      'environment_denied',
      `refusing to start because environment policy denied: ${result.denied.join(', ')}`
    );
  }
  writeAuditEvents([...Object.values(result.decisions), ...Object.values(result.valueDecisions)]);
  const environment = {
    ...result.environment,
    AIIGNORE_POLICY_SHA256: policy.digest,
    AIIGNORE_POLICY_PATH: policy.source,
    AIIGNORE_POLICY_ROOT: policyRoot
  };
  return await new Promise<number>((resolve, reject) => {
    const child = spawn(command, args, { env: environment, stdio: 'inherit' });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (signal) {
        process.stderr.write(`aiignore: child terminated by ${signal}\n`);
        resolve(128);
      } else resolve(code ?? 1);
    });
  });
}

function compileCommand(argv: string[]): number {
  const [target, ...rest] = argv;
  if (target !== 'codex' && target !== 'gemini') {
    throw new PolicyError('usage', 'compile target must be "codex" or "gemini"');
  }
  const { values } = parseArgs({
    args: rest,
    options: {
      policy: { type: 'string', default: POLICY_FILENAME },
      report: { type: 'boolean', default: false },
      'allow-partial': { type: 'boolean', default: false }
    }
  });
  const policy = loadPinnedPolicy(values.policy);
  if (target === 'codex') {
    const compilation = compileCodexPermissionProfile(policy);
    process.stdout.write(values.report ? `${JSON.stringify(compilation, null, 2)}\n` : compilation.toml);
    return compilation.exact || values['allow-partial'] ? 0 : EXIT_PARTIAL;
  }
  const compilation = compileGeminiConfiguration(policy);
  process.stdout.write(values.report ? `${JSON.stringify(compilation, null, 2)}\n` : compilation.ignoreFile);
  return compilation.exact || values['allow-partial'] ? 0 : EXIT_PARTIAL;
}

async function hookCommand(argv: string[], readInput: ReadInput): Promise<number> {
  const [target, ...rest] = argv;
  if (target !== 'codex' && target !== 'gemini') {
    throw new PolicyError('usage', 'hook target must be "codex" or "gemini"');
  }
  const { values } = parseArgs({
    args: rest,
    options: {
      policy: { type: 'string', default: POLICY_FILENAME },
      root: { type: 'string', default: process.env['AIIGNORE_POLICY_ROOT'] }
    }
  });
  let input: unknown;
  try {
    input = JSON.parse(await readInput()) as unknown;
  } catch {
    throw new PolicyError('invalid_hook_input', 'hook input must be valid JSON');
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new PolicyError('invalid_hook_input', 'hook input must be a JSON object');
  }
  const policy = loadPinnedPolicy(values.policy);
  const hookInput = {
    ...(input as Record<string, unknown>),
    policyRoot: path.resolve(values.root ?? policy.root)
  };
  const result =
    target === 'codex'
      ? evaluateCodexPreToolUse(policy, hookInput)
      : evaluateGeminiBeforeTool(policy, hookInput);
  if (!result.denied) writeAuditEvents(result.decisions);
  if (result.response) process.stdout.write(`${JSON.stringify(result.response)}\n`);
  return result.denied ? EXIT_DENIED : 0;
}

function writeDecision(decision: Decision, json: boolean): void {
  process.stdout.write(
    json
      ? `${JSON.stringify(decision)}\n`
      : `${decision.effect.toUpperCase()} ${decision.resource} ${decision.ruleId ?? '<default>'}: ${decision.reason}\n`
  );
}

function isBlocking(decision: Decision): boolean {
  return ['deny', 'drop'].includes(decision.effect);
}

function decisionNames(
  decisions: Record<string, Decision>,
  effect: Decision['effect']
): string[] {
  return Object.entries(decisions)
    .filter(([, decision]) => decision.effect === effect)
    .map(([name]) => name);
}

function writeAuditEvents(decisions: readonly Decision[]): void {
  for (const decision of decisions) {
    if (decision.effect !== 'audit') continue;
    process.stderr.write(`${JSON.stringify(createAuditEvent(decision))}\n`);
  }
}

function isErrorCode(error: unknown, code: string): boolean {
  return error instanceof Error && 'code' in error && error.code === code;
}

function isParseArgsError(error: unknown): boolean {
  return (
    error instanceof Error &&
    'code' in error &&
    typeof error.code === 'string' &&
    error.code.startsWith('ERR_PARSE_ARGS_')
  );
}

function readCliInputFile(filename: string, maximum: number, label: string): Buffer {
  return readBoundedRegularFile(filename, {
    maximumBytes: maximum,
    label,
    unreadableCode: 'input_unreadable',
    notFileCode: 'input_not_a_file',
    tooLargeCode: 'input_too_large',
    changedCode: 'input_changed'
  });
}

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return '';
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    bytes += buffer.byteLength;
    if (bytes > MAX_INPUT_BYTES) {
      throw new PolicyError('input_too_large', `stdin exceeds ${MAX_INPUT_BYTES} bytes`);
    }
    chunks.push(buffer);
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, bytes));
  } catch {
    throw new PolicyError('invalid_input_encoding', 'stdin is not valid UTF-8');
  }
}

function help(): string {
  return `aiignore ${PACKAGE_VERSION}

Usage:
  aiignore init [--path ${POLICY_FILENAME}] [--json]
  aiignore validate [policy] [--json]
  aiignore doctor [--policy ${POLICY_FILENAME}] [--json]
  aiignore check file <path> [--operation read] [--policy ${POLICY_FILENAME}]
  aiignore check env <name> [--policy ${POLICY_FILENAME}]
  aiignore check network <url> [--policy ${POLICY_FILENAME}]
  aiignore scan --scope <scope> [--policy ${POLICY_FILENAME}] < input
  aiignore filter-env [--policy ${POLICY_FILENAME}]
  aiignore conformance [vectors.json] [--json]
  aiignore parser-conformance [vectors.json] [--json]
  aiignore reference-conformance-report --date YYYY-MM-DD --source-uri <https-uri> --source-revision <revision> --source-sha256 <sha256> --runner-sha256 <sha256> [--source-dirty] [--manifest <manifest.json>]
  aiignore verify-implementation-report <report.json> [--manifest <manifest.json>] [--json]
  aiignore sign-report <provisional-report.json> --key <private.pem> --identity <identity> --envelope-uri <https-uri> --report-out <verified.json> --envelope-out <signature.json>
  aiignore verify-report <verified-report.json> <signature.json> --identity <trusted-identity> --key-sha256 <trusted-fingerprint> [--json]
  aiignore run [--policy ${POLICY_FILENAME}] [--root workspace] -- <command> [args...]
  aiignore compile codex [--policy ${POLICY_FILENAME}] [--report] [--allow-partial]
  aiignore compile gemini [--policy ${POLICY_FILENAME}] [--report] [--allow-partial]
  aiignore hook codex [--policy ${POLICY_FILENAME}] [--root workspace] < hook-event.json
  aiignore hook gemini [--policy ${POLICY_FILENAME}] [--root workspace] < hook-event.json
`;
}

if (isDirectExecution(process.argv[1])) {
  process.exitCode = await main();
}

function isDirectExecution(invokedPath: string | undefined): boolean {
  if (!invokedPath) return false;
  try {
    return realpathSync(invokedPath) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return import.meta.url === pathToFileURL(invokedPath).href;
  }
}
