import { spawnSync } from 'node:child_process';
import { mkdtempSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const npmEntrypoint = process.env.npm_execpath;
const command = npmEntrypoint ? process.execPath : process.platform === 'win32' ? 'npm.cmd' : 'npm';
const args = npmEntrypoint
  ? [npmEntrypoint, 'pack', '--dry-run', '--json']
  : ['pack', '--dry-run', '--json'];
const result = spawnSync(command, args, {
  encoding: 'utf8',
  maxBuffer: 4 * 1024 * 1024
});
if (result.status !== 0) {
  throw new Error(result.stderr || result.error?.message || 'npm pack --dry-run failed');
}

const [pack] = JSON.parse(result.stdout);
if (!pack || pack.name !== '@apinindy/aiignore') throw new Error('unexpected package identity');
if (pack.unpackedSize > 1024 * 1024) throw new Error('package exceeds the 1 MiB unpacked limit');
if (pack.entryCount > 160) throw new Error('package contains unexpectedly many files');

const files = new Map(pack.files.map((file) => [file.path, file]));
for (const required of [
  'dist/index.js',
  'dist/index.d.ts',
  'dist/cli.js',
  'schema/aiignore.schema.json',
  'schema/decision.schema.json',
  'schema/audit-event.schema.json',
  'schema/readiness-report.schema.json',
  'schema/implementation-conformance-report.schema.json',
  'schema/conformance-report.schema.json',
  'schema/conformance-signature-envelope.schema.json',
  'schema/conformance-vectors.schema.json',
  'schema/parser-vectors.schema.json',
  'schema/harness-vectors.schema.json',
  'schema/conformance-manifest.schema.json',
  'schema/requirements-traceability.schema.json',
  'spec/aiignore.md',
  'spec/registries.md',
  'spec/errata.md',
  'test/conformance/v0.1.json',
  'test/conformance/security-v0.1.json',
  'test/conformance/options-v0.1.json',
  'test/conformance/limits-v0.1.json',
  'test/parser-conformance/v0.1.json',
  'test/fuzz/fuzz.mjs',
  'test/fuzz/aiignore.dict',
  'test/fuzz/README.md',
  'docs/fuzzing.md',
  'docs/architecture.md',
  'docs/getting-started.md',
  'docs/conformance-policy.md',
  'docs/credential-management.md',
  'docs/security-baseline.md',
  'docs/versioning.md',
  'docs/requirements-traceability.md',
  'conformance/manifest-v0.1.json',
  'conformance/requirements-v0.1.json',
  'conformance/vectors/codex-sandbox-v0.1.json',
  'profiles/recommended.aiignore.yaml',
  'SECURITY.md',
  'SUPPORT.md',
  'MAINTAINERS.md',
  'DCO',
  'security-insights.yml',
  'LICENSE'
]) {
  if (!files.has(required)) throw new Error(`package is missing required file: ${required}`);
}

for (const filename of files.keys()) {
  if (
    filename.startsWith('.github/') ||
    filename.startsWith('src/') ||
    filename.startsWith('testbed/') ||
    filename.startsWith('site/') ||
    filename.startsWith('coverage/') ||
    /(^|\/)\.env(?:\.|$)/u.test(filename)
  ) {
    throw new Error(`package contains forbidden development file: ${filename}`);
  }
}

const cli = files.get('dist/cli.js');
if (!cli) throw new Error('package is missing dist/cli.js');
// Windows does not expose POSIX executable mode bits through npm pack metadata.
// The Linux package job and release runner enforce the published tarball mode.
if (process.platform !== 'win32' && (cli.mode & 0o111) === 0) {
  throw new Error('dist/cli.js is not executable');
}
const builtCli = path.resolve('dist/cli.js');
const executable = process.platform === 'win32'
  ? { command: process.execPath, args: [builtCli, '--version'] }
  : (() => {
      const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-bin-'));
      const linkedCli = path.join(directory, 'aiignore');
      symlinkSync(builtCli, linkedCli);
      return { command: linkedCli, args: ['--version'] };
    })();
const smoke = spawnSync(executable.command, executable.args, {
  encoding: 'utf8',
  maxBuffer: 1024 * 1024
});
if (smoke.status !== 0 || smoke.stdout !== `${pack.version}\n` || smoke.stderr !== '') {
  throw new Error('packaged CLI entry point did not produce the exact version output');
}
process.stdout.write(`ok - package ${pack.filename} contains ${pack.entryCount} reviewed files\n`);
