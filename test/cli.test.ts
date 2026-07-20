import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { main } from '../src/cli.js';
import { loadPinnedPolicy, loadPolicy } from '../src/parser.js';
import { createMinimalConformanceBundle } from './helpers.js';

const CLI_POLICY = `aiignore: "0.1"
rules:
  files:
    - {id: secret-file, effect: deny, paths: ["secret.txt"]}
  environment:
    - {id: forged-attestation, effect: drop, names: ["AIIGNORE_POLICY_*"]}
    - {id: secret-env, effect: drop, names: [AIIGNORE_CLI_SECRET]}
  network:
    - {id: blocked-net, effect: deny, urls: ["https://blocked.test/**"]}
  strings:
    - id: marker
      effect: redact
      scopes: [tool_output]
      patterns: [{type: literal, value: SECRET}]
      replacement: "[MASKED]"
    - id: environment-value-marker
      effect: redact
      scopes: [environment_value]
      patterns: [{type: literal, value: VALUE_SECRET}]
      replacement: "[VALUE-MASKED]"
    - id: environment-value-audit
      effect: audit
      scopes: [environment_value]
      patterns: [{type: literal, value: VALUE_AUDIT}]
`;

let cliDirectory = '';
let cliPolicy = '';

beforeEach(() => {
  cliDirectory = mkdtempSync(path.join(tmpdir(), 'aiignore-cli-main-'));
  cliPolicy = path.join(cliDirectory, '.aiignore.yaml');
  writeFileSync(cliPolicy, CLI_POLICY);
  vi.stubEnv('AIIGNORE_CLI_SECRET', 'not-a-real-secret');
  vi.stubEnv('AIIGNORE_CLI_VALUE_REDACT', 'private-VALUE_SECRET-material');
  vi.stubEnv('AIIGNORE_CLI_VALUE_AUDIT', 'private-VALUE_AUDIT-material');
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

async function invoke(
  argv: string[],
  input = ''
): Promise<{ code: number; stdout: string; stderr: string }> {
  let stdout = '';
  let stderr = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
    stdout += String(chunk);
    return true;
  });
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
    stderr += String(chunk);
    return true;
  });
  const code = await main(argv, () => Promise.resolve(input));
  return { code, stdout, stderr };
}

function parseJson(text: string): unknown {
  return JSON.parse(text) as unknown;
}

describe('CLI session policy integrity', () => {
  it('accepts a pinned digest and fails closed after policy bytes change', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-cli-'));
    const file = path.join(directory, '.aiignore.yaml');
    writeFileSync(file, 'aiignore: "0.1"\n');
    const digest = loadPolicy(file).digest;
    expect(loadPinnedPolicy(file, digest).digest).toBe(digest);
    writeFileSync(file, 'aiignore: "0.1"\nmetadata: {name: changed}\n');
    expect(() => loadPinnedPolicy(file, digest)).toThrow(/policy bytes changed/u);
  });

  it('prints help and version and returns structured usage errors', async () => {
    const help = await invoke([]);
    expect(help.code).toBe(0);
    expect(help.stdout).toContain('Usage:');
    vi.restoreAllMocks();
    expect(await invoke(['--version'])).toMatchObject({ code: 0, stdout: '0.1.0-alpha.1\n' });
    vi.restoreAllMocks();
    const unknown = await invoke(['unknown']);
    expect(unknown.code).toBe(2);
    expect(parseJson(unknown.stderr)).toMatchObject({ error: 'usage' });
  });

  it('validates policies in text and JSON formats', async () => {
    const plain = await invoke(['validate', cliPolicy]);
    expect(plain.code).toBe(0);
    expect(plain.stdout).toMatch(/^valid [a-f0-9]{64}/u);
    vi.restoreAllMocks();
    const json = await invoke(['validate', cliPolicy, '--json']);
    expect(parseJson(json.stdout)).toMatchObject({ valid: true, version: '0.1' });
  });

  it('reports policy readiness without presenting validation as enforcement', async () => {
    const human = await invoke(['doctor', '--policy', cliPolicy]);
    expect(human.code).toBe(0);
    expect(human.stdout).toContain('deployment enforcement: NOT ESTABLISHED');
    expect(human.stdout).toContain('network=allow');
    expect(human.stdout).toContain('codex=partial');
    expect(human.stdout).not.toContain('VALUE_SECRET');
    vi.restoreAllMocks();

    const json = await invoke(['doctor', '--policy', cliPolicy, '--json']);
    expect(json.code).toBe(0);
    expect(parseJson(json.stdout)).toMatchObject({
      formatVersion: '0.1',
      policyValid: true,
      deploymentEnforcement: 'not-established'
    });
    expect(json.stdout).not.toContain('VALUE_SECRET');
    expect(json.stdout).not.toContain(cliDirectory);
  });

  it('emits a content-addressed implementation report for the manifest-selected bundle', async () => {
    const manifest = createMinimalConformanceBundle(path.join(cliDirectory, 'bundle'));
    const result = await invoke([
      'reference-conformance-report',
      '--manifest',
      manifest,
      '--date',
      '2026-07-16',
      '--source-uri',
      'https://example.invalid/source.tgz',
      '--source-revision',
      'test-revision',
      '--source-sha256',
      '1'.repeat(64),
      '--runner-sha256',
      '2'.repeat(64)
    ]);
    expect(result.code).toBe(0);
    expect(parseJson(result.stdout)).toMatchObject({
      reportType: 'implementation',
      status: 'provisional',
      implementation: {
        name: 'aiignore',
        version: '0.1.0-alpha.1',
        language: 'TypeScript',
        classification: 'reference'
      },
      summary: { total: 2, passed: 2, failed: 0, conformant: true }
    });
    expect(result.stdout).not.toContain(path.resolve('.'));
    vi.restoreAllMocks();

    const reportPath = path.join(cliDirectory, 'implementation-report.json');
    writeFileSync(reportPath, result.stdout);
    const verified = await invoke([
      'verify-implementation-report',
      reportPath,
      '--manifest',
      manifest,
      '--json'
    ]);
    expect(verified.code).toBe(0);
    expect(parseJson(verified.stdout)).toMatchObject({
      valid: true,
      status: 'provisional',
      conformant: true,
      suites: 2
    });
    vi.restoreAllMocks();

    const falseAttribution = await invoke([
      'reference-conformance-report',
      '--classification',
      'independent'
    ]);
    expect(falseAttribution.code).toBe(2);
    expect(parseJson(falseAttribution.stderr)).toMatchObject({ error: 'usage' });
    expect(falseAttribution.stderr).toContain('Unknown option');
  });

  it('initializes the recommended profile without overwriting existing or legacy files', async () => {
    const destination = path.join(cliDirectory, 'initialized.aiignore.yaml');
    const created = await invoke(['init', '--path', destination, '--json']);
    expect(created.code).toBe(0);
    expect(parseJson(created.stdout)).toMatchObject({
      created: destination,
      profile: 'recommended'
    });
    expect(loadPolicy(destination).document.metadata?.name).toBe('recommended-secrets-baseline');
    const original = readFileSync(destination);

    vi.restoreAllMocks();
    const overwrite = await invoke(['init', '--path', destination]);
    expect(overwrite.code).toBe(2);
    expect(parseJson(overwrite.stderr)).toMatchObject({ error: 'policy_exists' });
    expect(readFileSync(destination)).toEqual(original);

    vi.restoreAllMocks();
    const legacy = await invoke(['init', '--path', path.join(cliDirectory, '.aiignore')]);
    expect(legacy.code).toBe(2);
    expect(parseJson(legacy.stderr)).toMatchObject({ error: 'legacy_ignore_filename' });

    vi.restoreAllMocks();
    const legacyCaseAlias = await invoke(['init', '--path', path.join(cliDirectory, '.AIIGNORE')]);
    expect(legacyCaseAlias.code).toBe(2);
    expect(parseJson(legacyCaseAlias.stderr)).toMatchObject({ error: 'legacy_ignore_filename' });

    vi.restoreAllMocks();
    const unwritable = await invoke([
      'init',
      '--path',
      path.join(cliDirectory, 'missing-parent', '.aiignore.yaml')
    ]);
    expect(unwritable.code).toBe(2);
    expect(parseJson(unwritable.stderr)).toMatchObject({ error: 'policy_unwritable' });
  });

  it('checks every resource and validates file operations', async () => {
    const file = await invoke(['check', 'file', 'secret.txt', '--policy', cliPolicy, '--json']);
    expect(file.code).toBe(3);
    expect(parseJson(file.stdout)).toMatchObject({ resource: 'file', effect: 'deny' });
    vi.restoreAllMocks();

    const environment = await invoke(['check', 'env', 'AIIGNORE_CLI_SECRET', '--policy', cliPolicy]);
    expect(environment.code).toBe(3);
    expect(environment.stdout).toContain('DROP environment');
    vi.restoreAllMocks();

    const network = await invoke([
      'check',
      'network',
      'https://blocked.test/a',
      '--policy',
      cliPolicy,
      '--json'
    ]);
    expect(network.code).toBe(3);
    vi.restoreAllMocks();

    const invalidOperation = await invoke([
      'check',
      'file',
      'secret.txt',
      '--operation',
      'invalid',
      '--policy',
      cliPolicy
    ]);
    expect(invalidOperation.code).toBe(2);
    expect(invalidOperation.stderr).toContain('invalid file operation');
    vi.restoreAllMocks();
    const invalidResource = await invoke(['check', 'other', 'x', '--policy', cliPolicy]);
    expect(invalidResource.code).toBe(2);
    expect(invalidResource.stderr).toContain('unknown resource');
  });

  it('scans input, validates scope, and filters the process environment', async () => {
    const scan = await invoke(['scan', '--scope', 'tool_output', '--policy', cliPolicy], 'SECRET');
    expect(scan.code).toBe(0);
    expect(scan.stdout).toContain('[MASKED]');
    vi.restoreAllMocks();
    const invalidScope = await invoke(['scan', '--scope', 'invalid', '--policy', cliPolicy]);
    expect(invalidScope.code).toBe(2);
    expect(invalidScope.stderr).toContain('--scope must be one of');
    vi.restoreAllMocks();
    const filtered = await invoke(['filter-env', '--policy', cliPolicy]);
    expect(filtered.code).toBe(0);
    const filteredOutput = parseJson(filtered.stdout);
    expect(filteredOutput).toMatchObject({
      dropped: ['AIIGNORE_CLI_SECRET'],
      valueRedacted: ['AIIGNORE_CLI_VALUE_REDACT'],
      valueAudited: ['AIIGNORE_CLI_VALUE_AUDIT']
    });
    expect(filteredOutput).not.toHaveProperty('environment');
    expect(filtered.stdout).not.toContain('private-VALUE_SECRET-material');
    expect(filtered.stdout).not.toContain('private-VALUE_AUDIT-material');
    vi.restoreAllMocks();
    const unsafeValues = await invoke(['filter-env', '--policy', cliPolicy, '--emit-values']);
    expect(unsafeValues.code).toBe(2);
    expect(unsafeValues.stderr).toContain('Unknown option');
  });

  it('runs both portable conformance suites', async () => {
    const decisions = await invoke([
      'conformance',
      path.resolve('test/conformance/options-v0.1.json'),
      '--json'
    ]);
    expect(parseJson(decisions.stdout)).toMatchObject({ conformant: true, total: 37 });
    vi.restoreAllMocks();
    const parser = await invoke([
      'parser-conformance',
      path.resolve('test/parser-conformance/v0.1.json')
    ]);
    expect(parser.code).toBe(0);
    expect(parser.stdout).toContain('56/56');
  });

  it('compiles both adapters and validates compile targets', async () => {
    const codex = await invoke(['compile', 'codex', '--policy', cliPolicy, '--report', '--allow-partial']);
    expect(codex.code).toBe(0);
    expect(parseJson(codex.stdout)).toMatchObject({ format: 'codex-permission-profile-v1' });
    vi.restoreAllMocks();
    const gemini = await invoke(['compile', 'gemini', '--policy', cliPolicy, '--allow-partial']);
    expect(gemini.code).toBe(0);
    expect(gemini.stdout).toContain('Generated by aiignore');
    vi.restoreAllMocks();
    const invalidTarget = await invoke(['compile', 'other', '--policy', cliPolicy]);
    expect(invalidTarget.code).toBe(2);
    expect(invalidTarget.stderr).toContain('compile target');
  });

  it('evaluates Codex and Gemini hook payloads', async () => {
    const payload = JSON.stringify({
      cwd: cliDirectory,
      tool_name: 'read_file',
      tool_input: { file_path: path.join(cliDirectory, 'secret.txt') }
    });
    const codex = await invoke(['hook', 'codex', '--policy', cliPolicy], payload);
    expect(codex.code).toBe(3);
    expect(parseJson(codex.stdout)).toHaveProperty('hookSpecificOutput.permissionDecision', 'deny');
    vi.restoreAllMocks();
    const gemini = await invoke(['hook', 'gemini', '--policy', cliPolicy], payload);
    expect(gemini.code).toBe(3);
    expect(parseJson(gemini.stdout)).toMatchObject({ decision: 'deny' });
    vi.restoreAllMocks();
    const invalidTarget = await invoke(['hook', 'other', '--policy', cliPolicy], payload);
    expect(invalidTarget.code).toBe(2);
    expect(invalidTarget.stderr).toContain('hook target');
    vi.restoreAllMocks();
    const invalidInput = await invoke(['hook', 'codex', '--policy', cliPolicy], '[]');
    expect(invalidInput.code).toBe(2);
    expect(invalidInput.stderr).toContain('hook input must be a JSON object');
    vi.restoreAllMocks();
    const invalidJson = await invoke(['hook', 'codex', '--policy', cliPolicy], '{');
    expect(invalidJson.code).toBe(2);
    expect(invalidJson.stderr).toContain('invalid_hook_input');
    vi.restoreAllMocks();

    const nestedPolicy = path.join(cliDirectory, 'nested.aiignore.yaml');
    writeFileSync(
      nestedPolicy,
      'aiignore: "0.1"\nrules:\n  files:\n    - {id: nested, effect: deny, paths: ["subdir/private/**"]}\n'
    );
    const nested = await invoke(
      ['hook', 'gemini', '--policy', nestedPolicy],
      JSON.stringify({
        cwd: path.join(cliDirectory, 'subdir'),
        tool_name: 'read_file',
        tool_input: { file_path: 'private/key.txt' }
      })
    );
    expect(nested.code).toBe(3);
    expect(nested.stdout).toContain('nested');
    vi.restoreAllMocks();

    const overriddenRootPayload = JSON.stringify({
      cwd: path.dirname(cliDirectory),
      tool_name: 'read_file',
      tool_input: { file_path: 'secret.txt' }
    });
    const overriddenRoot = await invoke(
      ['hook', 'codex', '--policy', cliPolicy, '--root', cliDirectory],
      overriddenRootPayload
    );
    expect(overriddenRoot.code).toBe(3);
    vi.restoreAllMocks();

    const mixedPolicy = path.join(cliDirectory, 'mixed.aiignore.yaml');
    writeFileSync(
      mixedPolicy,
      'aiignore: "0.1"\nrules:\n  files:\n    - {id: observe-file, effect: audit, paths: ["logs/**"]}\n  network:\n    - {id: block-network, effect: deny, urls: ["https://blocked.test/**"]}\n'
    );
    const mixed = await invoke(
      ['hook', 'codex', '--policy', mixedPolicy],
      JSON.stringify({
        cwd: cliDirectory,
        tool_name: 'fetch_file',
        tool_input: { path: 'logs/event.txt', url: 'https://blocked.test/upload' }
      })
    );
    expect(mixed.code).toBe(3);
    expect(mixed.stderr).not.toContain('aiignore.audit');
  });

  it('runs a child with filtered environment and policy attestation', async () => {
    const digest = loadPolicy(cliPolicy).digest;
    vi.stubEnv('AIIGNORE_POLICY_SHA256', digest);
    vi.stubEnv('AIIGNORE_POLICY_PATH', '/tmp/forged-policy');
    vi.stubEnv('AIIGNORE_POLICY_ROOT', '/tmp/forged-root');
    const result = await invoke([
      'run',
      '--policy',
      cliPolicy,
      '--root',
      cliDirectory,
      '--',
      process.execPath,
      '-e',
      'const [digest, policyPath, policyRoot] = process.argv.slice(1); process.exit(process.env.AIIGNORE_POLICY_SHA256 === digest && process.env.AIIGNORE_POLICY_PATH === policyPath && process.env.AIIGNORE_POLICY_ROOT === policyRoot ? 0 : 9)',
      digest,
      cliPolicy,
      cliDirectory
    ]);
    expect(result.code).toBe(0);
    const auditEvent = parseJson(result.stderr.trim());
    expect(auditEvent).toMatchObject({
      event: 'aiignore.audit',
      formatVersion: '0.1',
      resource: 'string',
      ruleId: 'environment-value-audit'
    });
    expect(result.stderr).not.toContain('VALUE_AUDIT');
    vi.restoreAllMocks();
    const missingCommand = await invoke(['run', '--policy', cliPolicy]);
    expect(missingCommand.code).toBe(2);
    expect(missingCommand.stderr).toContain('usage: aiignore run');

    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    vi.stubEnv('AIIGNORE_DENIED', 'present');
    vi.stubEnv('AIIGNORE_AUDITED', 'present');
    const deniedPolicy = path.join(cliDirectory, 'denied.aiignore.yaml');
    writeFileSync(
      deniedPolicy,
      'aiignore: "0.1"\nrules:\n  environment:\n    - {id: audited, effect: audit, names: [AIIGNORE_AUDITED]}\n    - {id: denied, effect: deny, names: [AIIGNORE_DENIED]}\n'
    );
    const denied = await invoke([
      'run',
      '--policy',
      deniedPolicy,
      '--',
      process.execPath,
      '-e',
      'process.exit(9)'
    ]);
    expect(denied.code).toBe(2);
    expect(denied.stderr).toContain('environment_denied');
    expect(denied.stderr).not.toContain('aiignore.audit');
  });

  it('creates and verifies a detached conformance signature with explicit trust pins', async () => {
    const report = JSON.parse(
      readFileSync(
        new URL('../conformance/results/codex-0.144.5-macos-26.5.2.json', import.meta.url),
        'utf8'
      )
    ) as Record<string, unknown>;
    report['evidence'] = [
      {
        type: 'artifact',
        uri: 'https://example.invalid/evidence.json',
        sha256: '1'.repeat(64)
      }
    ];
    const input = path.join(cliDirectory, 'provisional.json');
    const keyPath = path.join(cliDirectory, 'private.pem');
    const reportOut = path.join(cliDirectory, 'verified.json');
    const envelopeOut = path.join(cliDirectory, 'verified.signature.json');
    writeFileSync(input, `${JSON.stringify(report, null, 2)}\n`);
    const { privateKey } = generateKeyPairSync('ed25519');
    writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    const identity = 'https://example.invalid/signer';
    const signed = await invoke([
      'sign-report',
      input,
      '--key',
      keyPath,
      '--identity',
      identity,
      '--envelope-uri',
      'https://example.invalid/verified.signature.json',
      '--report-out',
      reportOut,
      '--envelope-out',
      envelopeOut
    ]);
    expect(signed.code).toBe(0);
    const signedResult = parseJson(signed.stdout) as { publicKeySha256: string };

    vi.restoreAllMocks();
    const verified = await invoke([
      'verify-report',
      reportOut,
      envelopeOut,
      '--identity',
      identity,
      '--key-sha256',
      signedResult.publicKeySha256,
      '--json'
    ]);
    expect(verified.code).toBe(0);
    expect(parseJson(verified.stdout)).toMatchObject({ verified: true, identity });

    vi.restoreAllMocks();
    const verifiedText = await invoke([
      'verify-report',
      reportOut,
      envelopeOut,
      '--identity',
      identity,
      '--key-sha256',
      signedResult.publicKeySha256
    ]);
    expect(verifiedText.code).toBe(0);
    expect(verifiedText.stdout).toMatch(/^verified [a-f0-9]{64} identity /u);

    vi.restoreAllMocks();
    const overwrite = await invoke([
      'sign-report',
      input,
      '--key',
      keyPath,
      '--identity',
      identity,
      '--envelope-uri',
      'https://example.invalid/verified.signature.json',
      '--report-out',
      reportOut,
      '--envelope-out',
      envelopeOut
    ]);
    expect(overwrite.code).toBe(2);
    expect(overwrite.stderr).toContain('output_exists');

    vi.restoreAllMocks();
    const cleanupEnvelope = path.join(cliDirectory, 'cleanup.signature.json');
    const reportCollision = await invoke([
      'sign-report',
      input,
      '--key',
      keyPath,
      '--identity',
      identity,
      '--envelope-uri',
      'https://example.invalid/cleanup.signature.json',
      '--report-out',
      reportOut,
      '--envelope-out',
      cleanupEnvelope
    ]);
    expect(reportCollision.code).toBe(2);
    expect(reportCollision.stderr).toContain('output_exists');
    expect(existsSync(cleanupEnvelope)).toBe(false);

    vi.restoreAllMocks();
    const sameOutput = await invoke([
      'sign-report',
      input,
      '--key',
      keyPath,
      '--identity',
      identity,
      '--envelope-uri',
      'https://example.invalid/same.json',
      '--report-out',
      path.join(cliDirectory, 'same.json'),
      '--envelope-out',
      path.join(cliDirectory, 'same.json')
    ]);
    expect(sameOutput.code).toBe(2);
    expect(sameOutput.stderr).toContain('outputs must differ');

    vi.restoreAllMocks();
    const missingOutputDirectory = await invoke([
      'sign-report',
      input,
      '--key',
      keyPath,
      '--identity',
      identity,
      '--envelope-uri',
      'https://example.invalid/unwritable.json',
      '--report-out',
      path.join(cliDirectory, 'missing', 'report.json'),
      '--envelope-out',
      path.join(cliDirectory, 'missing', 'signature.json')
    ]);
    expect(missingOutputDirectory.code).toBe(2);
    expect(missingOutputDirectory.stderr).toContain('output_unwritable');

    vi.restoreAllMocks();
    expect(await invoke(['sign-report'])).toMatchObject({ code: 2 });
    vi.restoreAllMocks();
    expect(await invoke(['verify-report'])).toMatchObject({ code: 2 });
    vi.restoreAllMocks();
    const missingInput = await invoke([
      'sign-report',
      path.join(cliDirectory, 'missing-report.json'),
      '--key',
      keyPath,
      '--identity',
      identity,
      '--envelope-uri',
      'https://example.invalid/missing.json',
      '--report-out',
      path.join(cliDirectory, 'missing-report-out.json'),
      '--envelope-out',
      path.join(cliDirectory, 'missing-envelope-out.json')
    ]);
    expect(missingInput.stderr).toContain('input_unreadable');

    vi.restoreAllMocks();
    const directoryInput = await invoke([
      'verify-report',
      cliDirectory,
      envelopeOut,
      '--identity',
      identity,
      '--key-sha256',
      signedResult.publicKeySha256
    ]);
    expect(directoryInput.stderr).toContain('input_not_a_file');

    vi.restoreAllMocks();
    const oversizedKey = path.join(cliDirectory, 'oversized-private.pem');
    writeFileSync(oversizedKey, Buffer.alloc(64 * 1024 + 1));
    const oversizedInput = await invoke([
      'sign-report',
      input,
      '--key',
      oversizedKey,
      '--identity',
      identity,
      '--envelope-uri',
      'https://example.invalid/oversized.json',
      '--report-out',
      path.join(cliDirectory, 'oversized-report.json'),
      '--envelope-out',
      path.join(cliDirectory, 'oversized-envelope.json')
    ]);
    expect(oversizedInput.stderr).toContain('input_too_large');
  });
});
