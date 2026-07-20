import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

const root = process.cwd();
const validator = path.join(root, 'scripts', 'validate-project-policy.mjs');
const fixtureFiles = [
  '.github/CODEOWNERS',
  '.github/ISSUE_TEMPLATE/config.yml',
  '.github/ISSUE_TEMPLATE/conformance.yml',
  '.github/hosting-policy.json',
  '.github/workflows/dco.yml',
  'CHANGELOG.md',
  'CITATION.cff',
  'CONTRIBUTING.md',
  'DCO',
  'MAINTAINERS.md',
  'README.md',
  'SECURITY.md',
  'SUPPORT.md',
  'docs/architecture.md',
  'docs/conformance-policy.md',
  'docs/credential-management.md',
  'docs/getting-started.md',
  'docs/public-hosting.md',
  'docs/requirements-traceability.md',
  'docs/release-notes/0.1.0-alpha.1.md',
  'docs/security-baseline.md',
  'docs/versioning.md',
  'package.json',
  'schema/aiignore.schema.json',
  'spec/aiignore.md',
  'spec/errata.md',
  'spec/registries.md'
];

describe('project policy validation', () => {
  it('accepts the reviewed policy, ownership, and evidence contracts', () => {
    expect(validate(createFixture()).status).toBe(0);
  });

  it('rejects package/citation version disagreement', () => {
    const fixture = createFixture();
    mutate(fixture, 'CITATION.cff', 'version: 0.1.0-alpha.1', 'version: 0.1.0-alpha.2');
    expect(validate(fixture).status).not.toBe(0);
  });

  it('rejects modification of the verbatim DCO', () => {
    const fixture = createFixture();
    mutate(fixture, 'DCO', 'Developer Certificate of Origin', 'Modified Certificate');
    expect(validate(fixture).status).not.toBe(0);
  });

  it('requires every official OSPS control record exactly once', () => {
    const fixture = createFixture();
    mutate(fixture, 'docs/security-baseline.md', 'OSPS-AC-01.01', 'REMOVED-AC-01.01');
    const result = validate(fixture);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('OSPS-AC-01.01 must have one structured evidence row');
  });

  it('rejects inflation of an OSPS conclusion without reviewed validator policy', () => {
    const fixture = createFixture();
    mutate(
      fixture,
      'docs/security-baseline.md',
      'OSPS-AC-03.01 prevent direct primary-branch commits | Not met',
      'OSPS-AC-03.01 prevent direct primary-branch commits | Implemented'
    );
    const result = validate(fixture);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('OSPS-AC-03.01 status must remain Not met');
  });

  it('rejects unstructured blank issue intake', () => {
    const fixture = createFixture();
    mutate(fixture, '.github/ISSUE_TEMPLATE/config.yml', 'blank_issues_enabled: false', 'blank_issues_enabled: true');
    expect(validate(fixture).status).not.toBe(0);
  });

  it('rejects conditional, untrusted, or mis-scoped DCO validation', () => {
    const conditional = createFixture();
    mutate(
      conditional,
      '.github/workflows/dco.yml',
      'name: Require a matching sign-off on every pull-request commit',
      'name: Require a matching sign-off on every pull-request commit\n        if: ${{ false }}'
    );
    expect(validate(conditional).status).not.toBe(0);

    const wrongRef = createFixture();
    mutate(
      wrongRef,
      '.github/workflows/dco.yml',
      'ref: ${{ github.event.pull_request.base.sha }}',
      'ref: ${{ github.event.pull_request.head.sha }}'
    );
    expect(validate(wrongRef).status).not.toBe(0);

    const untrustedEvent = createFixture();
    mutate(untrustedEvent, '.github/workflows/dco.yml', 'pull_request_target:', 'pull_request:');
    expect(validate(untrustedEvent).status).not.toBe(0);

    const extraStep = createFixture();
    mutate(
      extraStep,
      '.github/workflows/dco.yml',
      'steps:\n      - uses:',
      "steps:\n      - run: node -e 'process.exit(0)'\n      - uses:"
    );
    expect(validate(extraStep).status).not.toBe(0);

    const wrongTokenName = createFixture();
    mutate(
      wrongTokenName,
      '.github/workflows/dco.yml',
      'GITHUB_TOKEN: ${{ github.token }}',
      'GH_TOKEN: ${{ github.token }}'
    );
    expect(validate(wrongTokenName).status).not.toBe(0);
  });

  it('rejects removal of critical code ownership', () => {
    const fixture = createFixture();
    mutate(
      fixture,
      '.github/CODEOWNERS',
      '/scripts/scan-secrets.sh @ap-in-indy',
      '/scripts/scan-secrets.sh'
    );
    expect(validate(fixture).status).not.toBe(0);
  });

  it('locks the explicit zero-review single-maintainer pull-request policy', () => {
    const fixture = createFixture();
    mutate(
      fixture,
      '.github/hosting-policy.json',
      '"required_approving_review_count": 0',
      '"required_approving_review_count": 1'
    );
    expect(validate(fixture).status).not.toBe(0);
  });
});

function createFixture() {
  const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-project-policy-'));
  for (const filename of fixtureFiles) {
    const destination = path.join(directory, filename);
    mkdirSync(path.dirname(destination), { recursive: true });
    cpSync(path.join(root, filename), destination);
  }
  return directory;
}

function mutate(directory: string, filename: string, original: string, replacement: string) {
  const target = path.join(directory, filename);
  const source = readFileSync(target, 'utf8');
  expect(source).toContain(original);
  writeFileSync(target, source.replace(original, replacement));
}

function validate(directory: string) {
  return spawnSync(process.execPath, [validator, '--root', directory], {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024
  });
}
