import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const root = process.cwd();
const validator = path.join(root, 'scripts', 'validate-workflows.mjs');

describe('workflow policy mutation resistance', () => {
  it('accepts the reviewed workflow structure', () => {
    const fixture = createFixture();
    expect(validate(fixture).status).toBe(0);
  });

  it('preserves well-known metadata in the canonical Pages artifact', () => {
    const hiddenFilesExcluded = createFixture();
    mutateFile(
      hiddenFilesExcluded,
      '.github/workflows/pages.yml',
      '--exclude=.github',
      '--exclude=.github \\\n+            --exclude=".[^/]*"'
    );
    expect(validate(hiddenFilesExcluded).status).not.toBe(0);

    const unreviewedUploader = createFixture();
    mutateFile(
      unreviewedUploader,
      '.github/workflows/pages.yml',
      'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',
      'actions/upload-artifact@0000000000000000000000000000000000000000'
    );
    expect(validate(unreviewedUploader).status).not.toBe(0);
  });

  it('rejects commented-out gates and continue-on-error bypasses', () => {
    const commented = createFixture();
    mutateRelease(commented, 'run: npm run security:secrets', "run: '# npm run security:secrets'");
    expect(validate(commented).status).not.toBe(0);

    const continued = createFixture();
    mutateRelease(
      continued,
      'name: Rescan full Git history',
      'name: Rescan full Git history\n        continue-on-error: true'
    );
    expect(validate(continued).status).not.toBe(0);
  });

  it.each([
    'Verify signed tag and version',
    'Verify restricted release environment',
    'Run complete verification gate',
    'Rescan full Git history',
    'Inspect existing release state',
    'Build package and checksums',
    'Create draft or verify the previously inspected prerelease',
    'Attest verified release assets'
  ])('rejects a condition on the critical %s step', (name) => {
    const fixture = createFixture();
    mutateRelease(fixture, `name: ${name}`, `name: ${name}\n        if: \${{ false }}`);
    expect(validate(fixture).status).not.toBe(0);
  });

  it('rejects a job-level continue-on-error bypass', () => {
    const fixture = createFixture();
    mutateRelease(
      fixture,
      'release:\n    needs: build',
      'release:\n    continue-on-error: true\n    needs: build'
    );
    expect(validate(fixture).status).not.toBe(0);
  });

  it('keeps build execution outside publication and repository-write authority', () => {
    const privilegedBuild = createFixture();
    mutateRelease(
      privilegedBuild,
      'build:\n    permissions:\n      actions: read\n      contents: read',
      'build:\n    permissions:\n      contents: write\n      id-token: write'
    );
    expect(validate(privilegedBuild).status).not.toBe(0);

    const rebuiltInRelease = createFixture();
    mutateRelease(
      rebuiltInRelease,
      'EXPECTED_FILES=$(printf',
      'npm ci --ignore-scripts\n          EXPECTED_FILES=$(printf'
    );
    expect(validate(rebuiltInRelease).status).not.toBe(0);

    const detachedAuthority = createFixture();
    mutateRelease(detachedAuthority, 'needs: build', 'needs: []');
    expect(validate(detachedAuthority).status).not.toBe(0);
  });

  it('pins and re-verifies the inert release-input transfer and npm publication tool', () => {
    const downloader = createFixture();
    mutateRelease(
      downloader,
      'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c',
      'actions/download-artifact@0000000000000000000000000000000000000000'
    );
    expect(validate(downloader).status).not.toBe(0);

    const attester = createFixture();
    mutateRelease(
      attester,
      'actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6',
      'actions/attest@0000000000000000000000000000000000000000'
    );
    expect(validate(attester).status).not.toBe(0);

    const integrity = createFixture();
    mutateRelease(
      integrity,
      'sha512-Iy5vXZ55m8tIaSCz6bqQf9+W5XbPfoyURsgWLjOkFglqHTep6RDZqRj2sfYGeRyZvGu2HuJWm0lux0rxPQ29lQ==',
      'sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='
    );
    expect(validate(integrity).status).not.toBe(0);
  });

  it('rejects drift from the reviewed CodeQL action release', () => {
    for (const [filename, action] of [
      ['.github/workflows/codeql.yml', 'init'],
      ['.github/workflows/codeql.yml', 'analyze'],
      ['.github/workflows/scorecard.yml', 'upload-sarif']
    ] as const) {
      const fixture = createFixture();
      mutateFile(
        fixture,
        filename,
        `github/codeql-action/${action}@7188fc363630916deb702c7fdcf4e481b751f97a`,
        `github/codeql-action/${action}@0000000000000000000000000000000000000000`
      );
      expect(validate(fixture).status).not.toBe(0);
    }
  });

  it('rejects a condition on an unnamed release setup step', () => {
    const fixture = createFixture();
    mutateRelease(
      fixture,
      'uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5',
      'if: ${{ false }}\n        uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd # v5'
    );
    expect(validate(fixture).status).not.toBe(0);
  });

  it('rejects removal of serialized release concurrency', () => {
    const fixture = createFixture();
    mutateRelease(fixture, 'group: npm-publication', 'group: publication-${{ github.run_id }}');
    expect(validate(fixture).status).not.toBe(0);
  });

  it('allows the Pages comparison to be skipped only for an immutable rerun', () => {
    const fixture = createFixture();
    mutateRelease(
      fixture,
      "if: ${{ steps.preflight.outputs.published != 'true' }}",
      'if: ${{ inputs.publish_npm }}'
    );
    expect(validate(fixture).status).not.toBe(0);
  });

  it.each([
    'test "$GITHUB_REF" = "refs/tags/$RELEASE_TAG"',
    '[[ "$RELEASE_TAG" =~ $TAG_PATTERN ]]',
    'git merge-base --is-ancestor HEAD origin/main',
    "test \"$(jq -r '.verification.verified' <<<\"$TAG_OBJECT\")\" = \"true\"",
    "test \"$(jq -r '.verification.reason' <<<\"$TAG_OBJECT\")\" = \"valid\"",
    "test \"$(jq -r '.tagger.name' <<<\"$TAG_OBJECT\")\" = \"Alex\"",
    "test \"$(jq -r '.tagger.email' <<<\"$TAG_OBJECT\")\" = \"alex@alexdoes.it\"",
    "test \"$(jq -r '.message | split(\"\\n-----BEGIN SSH SIGNATURE-----\\n\")[0]' <<<\"$TAG_OBJECT\")\" =",
    "test \"$(jq -r '.can_admins_bypass' <<<\"$ENVIRONMENT\")\" = \"false\"",
    `'[.protection_rules[] | select(.type == "required_reviewers")] | length == 0'`,
    'node scripts/normalize-sbom.mjs "$RAW_SBOM" "$INPUT_DIRECTORY/$SBOM"',
    'test "$PUBLISH_NPM" = "false"',
    'node scripts/validate-alpha-advance.mjs "$CURRENT_ALPHA" "$VERSION"',
    'node "$NPM_CLI" publish "$TARBALL" --access public --tag alpha',
    '[[ "$LATEST_VERSION" =~ $STABLE_PATTERN ]]',
    'gh release edit "$RELEASE_TAG" --draft=false --prerelease --latest=false'
  ])('rejects a commented-out release control: %s', (control) => {
    const fixture = createFixture();
    mutateRelease(fixture, control, `# ${control}`);
    expect(validate(fixture).status).not.toBe(0);
  });

  it('rejects an unreviewed live release-environment reviewer gate or broad tag restriction', () => {
    const reviewerGate = createFixture();
    mutateRelease(
      reviewerGate,
      '[.protection_rules[] | select(.type == "required_reviewers")] | length == 0',
      '[.protection_rules[] | select(.type == "required_reviewers")] | length == 1'
    );
    expect(validate(reviewerGate).status).not.toBe(0);

    const broadTags = createFixture();
    mutateRelease(
      broadTags,
      '.total_count == 1 and .branch_policies[0].name == "v*" and .branch_policies[0].type == "tag"',
      '.total_count >= 1'
    );
    expect(validate(broadTags).status).not.toBe(0);
  });

  it.each([
    '--config "$TEMP_DIRECTORY/default-only.toml"',
    '--gitleaks-ignore-path "$TEMP_DIRECTORY/empty.gitleaksignore"',
    '--ignore-gitleaks-allow',
    "--log-opts='--all --text --no-textconv --no-ext-diff'",
    '--redact'
  ])('rejects a commented-out secret-scan control: %s', (control) => {
    const fixture = createFixture();
    mutateFile(fixture, 'scripts/scan-secrets.sh', control, `# ${control}`);
    expect(validate(fixture).status).not.toBe(0);
  });

  it('forces Git patch text even when repository attributes disable diffs', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-git-attributes-'));
    runGit(directory, ['init']);
    writeFileSync(path.join(directory, '.gitattributes'), '* -diff\n');
    const syntheticSecret = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
    writeFileSync(path.join(directory, 'credential.txt'), `${syntheticSecret}\n`);
    runGit(directory, ['add', '.']);
    runGit(directory, [
      '-c',
      'user.name=aiignore test',
      '-c',
      'user.email=aiignore@example.invalid',
      'commit',
      '-m',
      'fixture'
    ]);

    const ordinary = runGit(directory, ['log', '-p', '--all']);
    expect(ordinary.stdout).not.toContain(syntheticSecret);
    const hardened = runGit(directory, [
      'log',
      '-p',
      '--all',
      '--text',
      '--no-textconv',
      '--no-ext-diff'
    ]);
    expect(hardened.stdout).toContain(syntheticSecret);
  }, 15_000);
});

function createFixture() {
  const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-workflow-policy-'));
  mkdirSync(path.join(directory, 'scripts'));
  mkdirSync(path.join(directory, 'docs'));
  cpSync(path.join(root, '.github'), path.join(directory, '.github'), { recursive: true });
  for (const filename of ['scan-secrets.sh', 'normalize-sbom.mjs']) {
    cpSync(path.join(root, 'scripts', filename), path.join(directory, 'scripts', filename));
  }
  cpSync(
    path.join(root, 'docs', 'maintainer-release-runbook.md'),
    path.join(directory, 'docs', 'maintainer-release-runbook.md')
  );
  return directory;
}

function mutateRelease(directory: string, original: string, replacement: string) {
  mutateFile(directory, '.github/workflows/release.yml', original, replacement);
}

function mutateFile(directory: string, relative: string, original: string, replacement: string) {
  const filename = path.join(directory, relative);
  const source = readFileSync(filename, 'utf8');
  expect(source).toContain(original);
  writeFileSync(filename, source.replace(original, replacement));
}

function validate(directory: string) {
  return spawnSync(process.execPath, [validator], {
    cwd: directory,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024
  });
}

function runGit(directory: string, args: string[]) {
  const result = spawnSync('git', args, {
    cwd: directory,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024
  });
  expect(result.status, result.stderr).toBe(0);
  return result;
}
