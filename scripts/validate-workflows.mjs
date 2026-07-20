import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { parse } from 'yaml';

const directory = path.resolve('.github/workflows');
const failures = [];
const reviewedCodeqlSha = '7188fc363630916deb702c7fdcf4e481b751f97a';

for (const filename of readdirSync(directory).filter((name) => /\.ya?ml$/u.test(name))) {
  const source = readFileSync(path.join(directory, filename), 'utf8');
  const workflow = parse(source);
  if (!workflow || typeof workflow !== 'object') {
    failures.push(`${filename}: workflow must be a mapping`);
    continue;
  }
  const workflowEvents = workflow.on;
  const usesPullRequestTarget =
    workflowEvents &&
    typeof workflowEvents === 'object' &&
    Object.hasOwn(workflowEvents, 'pull_request_target');
  const usesPullRequest =
    workflowEvents &&
    typeof workflowEvents === 'object' &&
    Object.hasOwn(workflowEvents, 'pull_request');
  if (usesPullRequestTarget && filename !== 'dco.yml') {
    failures.push(`${filename}: pull_request_target is forbidden`);
  }
  if (filename === 'dco.yml' && (!usesPullRequestTarget || usesPullRequest)) {
    failures.push('dco.yml: trusted-base DCO validation must use only pull_request_target');
  }
  if (!workflow.permissions) failures.push(`${filename}: top-level permissions are required`);
  for (const [jobName, job] of Object.entries(workflow.jobs ?? {})) {
    if (!job || typeof job !== 'object') continue;
    if (!job['timeout-minutes']) failures.push(`${filename}/${jobName}: timeout-minutes is required`);
    if (Object.hasOwn(job, 'continue-on-error')) {
      failures.push(`${filename}/${jobName}: job-level continue-on-error is forbidden`);
    }
    for (const step of job.steps ?? []) {
      if (step && typeof step === 'object' && Object.hasOwn(step, 'continue-on-error')) {
        failures.push(`${filename}/${jobName}: continue-on-error is forbidden`);
      }
      if (!step || typeof step !== 'object' || typeof step.uses !== 'string') continue;
      if (!/^[^/]+\/[^@]+@[a-f0-9]{40}$/u.test(step.uses)) {
        failures.push(`${filename}/${jobName}: action is not pinned to a full commit: ${step.uses}`);
      }
    }
  }
  if (/NPM_TOKEN|NODE_AUTH_TOKEN/u.test(source)) {
    failures.push(`${filename}: long-lived npm publication tokens are forbidden`);
  }
  if (
    filename === 'release.yml' &&
    !/node "\$NPM_CLI" publish "\$TARBALL" --access public --tag alpha/u.test(source)
  ) {
    failures.push('release.yml: prerelease publication must use the explicit alpha dist-tag');
  }
  if (
    filename === 'release.yml' &&
    (workflow.concurrency?.group !== 'npm-publication' ||
      workflow.concurrency?.['cancel-in-progress'] !== false)
  ) {
    failures.push('release.yml: npm publication must be serialized');
  }
  if (filename === 'codeql.yml') {
    for (const action of ['init', 'analyze']) {
      if (!source.includes(`github/codeql-action/${action}@${reviewedCodeqlSha}`)) {
        failures.push(`codeql.yml: ${action} must use the reviewed CodeQL action pin`);
      }
    }
  }
  if (
    filename === 'scorecard.yml' &&
    !source.includes(`github/codeql-action/upload-sarif@${reviewedCodeqlSha}`)
  ) {
    failures.push('scorecard.yml: SARIF upload must use the reviewed CodeQL action pin');
  }
  if (filename === 'release.yml') {
    const build = workflow.jobs?.build;
    const release = workflow.jobs?.release;
    const buildSteps = build?.steps;
    const releaseSteps = release?.steps;
    const steps =
      Array.isArray(buildSteps) && Array.isArray(releaseSteps)
        ? [...buildSteps, ...releaseSteps]
        : undefined;
    if (
      !workflow.permissions ||
      typeof workflow.permissions !== 'object' ||
      Object.keys(workflow.permissions).length !== 0
    ) {
      failures.push('release.yml: top-level permissions must default to none');
    }
    if (!exactPermissions(build?.permissions, { actions: 'read', contents: 'read' })) {
      failures.push('release.yml/build: only read-only Actions and repository contents are permitted');
    }
    if (Object.hasOwn(build ?? {}, 'environment')) {
      failures.push('release.yml/build: unprivileged construction must not use a protected environment');
    }
    if (
      release?.needs !== 'build' ||
      release?.environment !== 'release' ||
      !exactPermissions(release?.permissions, {
        contents: 'write',
        'id-token': 'write',
        attestations: 'write'
      })
    ) {
      failures.push('release.yml/release: protected authority and build dependency are invalid');
    }
    const requiredNames = [
      'Verify signed tag and version',
      'Verify restricted release environment',
      'Run complete verification gate',
      'Rescan full Git history',
      'Inspect existing release state',
      'Verify canonical public artifacts byte for byte',
      'Build package and checksums',
      'Transfer inert release inputs',
      'Download inert release inputs',
      'Verify transferred release inputs',
      'Create draft or verify the previously inspected prerelease',
      'Attest verified release assets',
      'Publish package using npm trusted publishing',
      'Publish the matching GitHub prerelease'
    ];
    if (!Array.isArray(steps)) {
      failures.push('release.yml: separate build and release job steps are required');
    } else {
      const indexes = requiredNames.map((name) => steps.findIndex((step) => step?.name === name));
      if (
        requiredNames.some(
          (name) => steps.filter((step) => step?.name === name).length !== 1
        ) ||
        indexes.some((index) => index < 0) ||
        indexes.some((index, offset) => offset > 0 && index <= indexes[offset - 1])
      ) {
        failures.push('release.yml: named release gates must exist in the required order');
      }
      const named = Object.fromEntries(steps.filter((step) => step?.name).map((step) => [step.name, step]));
      for (const step of steps) {
        if (!step || typeof step !== 'object') continue;
        const allowedCondition =
          step.name === 'Verify canonical public artifacts byte for byte'
            ? "${{ steps.preflight.outputs.published != 'true' }}"
            : [
                  'Publish package using npm trusted publishing',
                  'Publish the matching GitHub prerelease'
                ].includes(step.name)
              ? '${{ inputs.publish_npm }}'
              : undefined;
        if (
          (allowedCondition === undefined && Object.hasOwn(step, 'if')) ||
          (allowedCondition !== undefined && step.if !== allowedCondition)
        ) {
          failures.push(
            `release.yml: ${step.name ?? step.uses ?? 'unnamed step'} has an unreviewed condition`
          );
        }
      }
      for (const name of [
        'Verify signed tag and version',
        'Verify restricted release environment',
        'Run complete verification gate',
        'Rescan full Git history',
        'Inspect existing release state',
        'Build package and checksums',
        'Transfer inert release inputs',
        'Download inert release inputs',
        'Verify transferred release inputs',
        'Create draft or verify the previously inspected prerelease',
        'Attest verified release assets'
      ]) {
        if (named[name] && Object.hasOwn(named[name], 'if')) {
          failures.push(`release.yml: ${name} must be unconditional`);
        }
      }
      if (!executableLines(named['Run complete verification gate']).includes('npm run verify')) {
        failures.push('release.yml: the complete verification gate must execute');
      }
      if (!executableLines(named['Rescan full Git history']).includes('npm run security:secrets')) {
        failures.push('release.yml: the full-history secret rescan must execute');
      }
      if (
        !executableLines(named['Verify canonical public artifacts byte for byte']).includes(
          'npm run publication:verify'
        )
      ) {
        failures.push('release.yml: canonical publication verification must execute');
      }
      if (
        named['Verify canonical public artifacts byte for byte']?.if !==
        "${{ steps.preflight.outputs.published != 'true' }}"
      ) {
        failures.push(
          'release.yml: mutable Pages verification may be skipped only for an already-published release'
        );
      }
      for (const name of [
        'Publish package using npm trusted publishing',
        'Publish the matching GitHub prerelease'
      ]) {
        if (named[name]?.if !== '${{ inputs.publish_npm }}') {
          failures.push(`release.yml: ${name} must use the explicit publication condition`);
        }
      }
      if (
        named['Build package and checksums']?.id !== 'package' ||
        named['Inspect existing release state']?.id !== 'preflight' ||
        named['Create draft or verify the previously inspected prerelease']?.id !== 'release_state'
      ) {
        failures.push('release.yml: package, preflight, and release-state outputs must use their reviewed step IDs');
      }
      if (
        named['Transfer inert release inputs']?.uses !==
          'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' ||
        named['Transfer inert release inputs']?.with?.name !== 'release-input' ||
        named['Transfer inert release inputs']?.with?.['retention-days'] !== 1 ||
        named['Download inert release inputs']?.uses !==
          'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c' ||
        named['Download inert release inputs']?.with?.name !== 'release-input' ||
        named['Attest verified release assets']?.uses !==
          'actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6' ||
        named['Attest verified release assets']?.with?.['subject-path'] !==
          'release-input/${{ needs.build.outputs.tarball }}\nrelease-input/${{ needs.build.outputs.sbom }}\nrelease-input/SHA256SUMS\n'
      ) {
        failures.push('release.yml: inert transfer and verified-asset attestation must use reviewed pinned actions');
      }
      const privilegedCommands = (releaseSteps ?? []).flatMap(executableLines).join('\n');
      for (const forbidden of ['npm ci', 'npm install', 'npm run', 'npm pack', 'npm sbom']) {
        if (privilegedCommands.includes(forbidden)) {
          failures.push(`release.yml/release: privileged job must not execute build command ${forbidden}`);
        }
      }

      const requiredFragments = new Map([
        ['Verify signed tag and version', [
          "TAG_PATTERN='^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)-alpha\\.([1-9][0-9]*)$'",
          '[[ "$RELEASE_TAG" =~ $TAG_PATTERN ]]',
          'test "$GITHUB_REF" = "refs/tags/$RELEASE_TAG"',
          'test "$(gh api "repos/$GITHUB_REPOSITORY" --jq \'.visibility\')" = "public"',
          'test "$(jq -r \'.object.type\' <<<"$TAG_REF")" = "tag"',
          'git merge-base --is-ancestor HEAD origin/main',
          "test \"$(jq -r '.verification.verified' <<<\"$TAG_OBJECT\")\" = \"true\"",
          "test \"$(jq -r '.verification.reason' <<<\"$TAG_OBJECT\")\" = \"valid\"",
          "test \"$(jq -r '.tagger.name' <<<\"$TAG_OBJECT\")\" = \"Alex\"",
          "test \"$(jq -r '.tagger.email' <<<\"$TAG_OBJECT\")\" = \"alex@alexdoes.it\"",
          "test \"$(jq -r '.message | split(\"\\n-----BEGIN SSH SIGNATURE-----\\n\")[0]' <<<\"$TAG_OBJECT\")\" =",
          "test \"$(jq -r '.object.sha' <<<\"$TAG_OBJECT\")\" = \"$(git rev-parse HEAD)\"",
          'test "v$(node -p "require(\'./package.json\').version")" = "$RELEASE_TAG"',
          'test -f "docs/release-notes/${RELEASE_TAG#v}.md"'
        ]],
        ['Verify restricted release environment', [
          'gh api "repos/$GITHUB_REPOSITORY/environments/release"',
          "test \"$(jq -r '.can_admins_bypass' <<<\"$ENVIRONMENT\")\" = \"false\"",
          "'[.protection_rules[] | select(.type == \"required_reviewers\")] | length == 0'",
          "test \"$(jq -r '.deployment_branch_policy.custom_branch_policies' <<<\"$ENVIRONMENT\")\" = \"true\"",
          'environments/release/deployment-branch-policies',
          '.total_count == 1 and .branch_policies[0].name == "v*" and .branch_policies[0].type == "tag"'
        ]],
        ['Inspect existing release state', [
          "test \"$(jq -r '.isPrerelease' <<<\"$RELEASE_STATE\")\" = \"true\"",
          'echo "published=true" >> "$GITHUB_OUTPUT"',
          'echo "published=false" >> "$GITHUB_OUTPUT"'
        ]],
        ['Build package and checksums', [
          'TARBALL=$(npm pack --json --pack-destination "$INPUT_DIRECTORY"',
          'npm sbom --omit=dev --sbom-format=cyclonedx > "$RAW_SBOM"',
          'node scripts/normalize-sbom.mjs "$RAW_SBOM" "$INPUT_DIRECTORY/$SBOM"',
          'NPM_CLI_TARBALL=$(npm pack npm@11.5.1',
          'sha512-Iy5vXZ55m8tIaSCz6bqQf9+W5XbPfoyURsgWLjOkFglqHTep6RDZqRj2sfYGeRyZvGu2HuJWm0lux0rxPQ29lQ==',
          'sha256sum "$TARBALL" "$SBOM" > SHA256SUMS'
        ]],
        ['Verify transferred release inputs', [
          'EXPECTED_FILES=$(printf',
          'ACTUAL_FILES=$(find release-input -mindepth 1 -maxdepth 1 -type f',
          'test "$ACTUAL_FILES" = "$EXPECTED_FILES"',
          'sha256sum --check --strict SHA256SUMS',
          'sha512-Iy5vXZ55m8tIaSCz6bqQf9+W5XbPfoyURsgWLjOkFglqHTep6RDZqRj2sfYGeRyZvGu2HuJWm0lux0rxPQ29lQ==',
          'echo "NPM_CLI=$RUNNER_TEMP/npm-cli/package/bin/npm-cli.js" >> "$GITHUB_ENV"'
        ]],
        ['Create draft or verify the previously inspected prerelease', [
          'if test "$PUBLISH_NPM" = "false"; then',
          'test "$PUBLISH_NPM" = "false"',
          'test "$(jq -r \'.isPrerelease\' <<<"$RELEASE_STATE")" = "true"',
          'gh release upload "$RELEASE_TAG" "$TARBALL" "$SBOM" "$CHECKSUMS" --clobber',
          '--notes-file "docs/release-notes/${RELEASE_TAG#v}.md"',
          'test "$(jq -r \'.name\' <<<"$RELEASE_METADATA")" = "aiignore policy $RELEASE_TAG"',
          'test "$ACTUAL_ASSETS" = "$EXPECTED_ASSETS"',
          'gh release download "$RELEASE_TAG" --dir "$RELEASE_DIRECTORY"',
          'if test "$IS_DRAFT" = "false"; then',
          'test -n "$PUBLISHED_INTEGRITY"',
          'test "$PUBLISHED_INTEGRITY" = "$EXPECTED_INTEGRITY"',
          'cmp --silent "$CHECKSUMS" "$RELEASE_DIRECTORY/SHA256SUMS"',
          'sha256sum --check --strict SHA256SUMS',
          'gh release create "$RELEASE_TAG" "$TARBALL" "$SBOM" "$CHECKSUMS"'
        ]],
        ['Publish package using npm trusted publishing', [
          'CURRENT_ALPHA=$(node "$NPM_CLI" view "$PACKAGE" dist-tags.alpha 2>/dev/null || true)',
          'node scripts/validate-alpha-advance.mjs "$CURRENT_ALPHA" "$VERSION"',
          'node "$NPM_CLI" publish "$TARBALL" --access public --tag alpha',
          'if test "$PUBLISHED_RELEASE" != "true"; then',
          'test -n "$PUBLISHED_INTEGRITY"',
          'test "$PUBLISHED_INTEGRITY" = "$EXPECTED_INTEGRITY"',
          'dist-tags.alpha',
          'LATEST_VERSION=$(node "$NPM_CLI" view "$PACKAGE" dist-tags.latest 2>/dev/null || true)',
          'test "$LATEST_VERSION" != "$VERSION"',
          "STABLE_PATTERN='^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$'",
          '[[ "$LATEST_VERSION" =~ $STABLE_PATTERN ]]'
        ]],
        ['Publish the matching GitHub prerelease', [
          'test "$(jq -r \'.name\' <<<"$RELEASE_METADATA")" = "aiignore policy $RELEASE_TAG"',
          'test "$ACTUAL_ASSETS" = "$EXPECTED_ASSETS"',
          'gh release download "$RELEASE_TAG" --dir "$RELEASE_DIRECTORY"',
          'cmp --silent "$CHECKSUMS" "$RELEASE_DIRECTORY/SHA256SUMS"',
          'sha256sum --check --strict SHA256SUMS',
          'gh release edit "$RELEASE_TAG" --draft=false --prerelease --latest=false',
          'test "$(gh release view "$RELEASE_TAG" --json isDraft --jq \'.isDraft\')" = "false"',
          'test "$(gh release view "$RELEASE_TAG" --json isPrerelease --jq \'.isPrerelease\')" = "true"'
        ]]
      ]);
      for (const [name, fragments] of requiredFragments) {
        const run = executableLines(named[name]).join('\n');
        for (const fragment of fragments) {
          if (!run.includes(fragment)) {
            failures.push(`release.yml: ${name} must execute reviewed control: ${fragment}`);
          }
        }
      }
    }
  }
  if (
    filename === 'pages.yml' &&
    workflow.jobs?.deploy?.if !==
      "${{ !github.event.repository.private && github.ref == 'refs/heads/main' }}"
  ) {
    failures.push('pages.yml: canonical publication must be restricted to main');
  }
  if (
    filename === 'pages.yml' &&
    !(workflow.jobs?.deploy?.steps ?? []).some((step) =>
      executableLines(step).includes('npm run manifest:validate')
    )
  ) {
    failures.push('pages.yml: canonical publication must validate the artifact manifest');
  }
  if (filename === 'pages.yml') {
    const steps = workflow.jobs?.deploy?.steps ?? [];
    const archive = steps.find(
      (step) => step?.name === 'Archive canonical site including well-known metadata'
    );
    const upload = steps.find(
      (step) =>
        step?.uses === 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'
    );
    const archiveRun = executableLines(archive).join('\n');
    if (
      !archiveRun.includes('--directory site-dist') ||
      archiveRun.includes('--exclude=".[^/]*"') ||
      upload?.with?.name !== 'github-pages' ||
      upload?.with?.path !== '${{ runner.temp }}/artifact.tar' ||
      upload?.with?.['if-no-files-found'] !== 'error'
    ) {
      failures.push('pages.yml: canonical archive must preserve well-known metadata');
    }
  }
  if (filename === 'secret-scan.yml') {
    const steps = workflow.jobs?.gitleaks?.steps ?? [];
    const checkout = steps.find((step) => typeof step?.uses === 'string' && step.uses.startsWith('actions/checkout@'));
    if (
      checkout?.with?.['fetch-depth'] !== 0 ||
      !steps.some((step) => executableLines(step).includes('bash scripts/scan-secrets.sh'))
    ) {
      failures.push('secret-scan.yml: full Git history must be scanned by the pinned repository script');
    }
  }
  if (filename === 'fuzz.yml' && workflow.on?.pull_request?.paths) {
    failures.push('fuzz.yml: the required pull-request check must not be path-filtered');
  }
}

if (!readdirSync(directory).includes('secret-scan.yml')) {
  failures.push('secret-scan.yml: repository-owned secret scanning is required');
}
const secretScanner = readFileSync(path.resolve('scripts/scan-secrets.sh'), 'utf8');
const secretScannerExecutable = executableSource(secretScanner);
if (
  !/VERSION=8\.30\.1/u.test(secretScannerExecutable) ||
  !/551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb/u.test(
    secretScannerExecutable
  ) ||
  !/b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5/u.test(
    secretScannerExecutable
  ) ||
  !/e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080/u.test(
    secretScannerExecutable
  ) ||
  !/dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709/u.test(
    secretScannerExecutable
  ) ||
  !/ACTUAL_SHA256=\$\(shasum -a 256/u.test(secretScannerExecutable) ||
  !/test "\$ACTUAL_SHA256" = "\$SHA256"/u.test(secretScannerExecutable) ||
  !/unset GITLEAKS_CONFIG GITLEAKS_CONFIG_TOML/u.test(secretScannerExecutable) ||
  !/--config "\$TEMP_DIRECTORY\/default-only\.toml"/u.test(secretScannerExecutable) ||
  !/--gitleaks-ignore-path "\$TEMP_DIRECTORY\/empty\.gitleaksignore"/u.test(secretScannerExecutable) ||
  !/--ignore-gitleaks-allow/u.test(secretScannerExecutable) ||
  !/--log-opts='--all --text --no-textconv --no-ext-diff'/u.test(secretScannerExecutable) ||
  !/--redact/u.test(secretScannerExecutable)
) {
  failures.push(
    'scan-secrets.sh: scanner version, cross-platform checksums, full history, and redaction must be pinned'
  );
}

const releaseRunbook = readFileSync(path.resolve('docs/maintainer-release-runbook.md'), 'utf8');
if (
  /gh workflow run release\.yml\s+\\\n\s+--ref main/u.test(releaseRunbook) ||
  (releaseRunbook.match(/--ref v0\.1\.0-alpha\.1/gu)?.length ?? 0) !== 2
) {
  failures.push('maintainer release runbook: both protected-environment dispatches must use the signed tag ref');
}

const sbomNormalizer = readFileSync(path.resolve('scripts/normalize-sbom.mjs'), 'utf8');
if (
  !/delete normalized\.serialNumber/u.test(sbomNormalizer) ||
  !/delete normalized\.metadata\.timestamp/u.test(sbomNormalizer) ||
  !/normalized\.metadata\.component\['bom-ref'\] !== expectedReference/u.test(sbomNormalizer) ||
  !/normalized\.metadata\.component\.name = packageIdentity\.name/u.test(sbomNormalizer) ||
  !/Object\.keys\(value\)\s*\.sort\(\)/u.test(sbomNormalizer)
) {
  failures.push(
    'normalize-sbom.mjs: npm run-specific fields must be removed and package identity and object keys canonicalized'
  );
}

if (failures.length > 0) {
  failures.forEach((failure) => process.stderr.write(`not ok - ${failure}\n`));
  process.exit(1);
}
process.stdout.write('ok - workflow permissions, action pins, secret scanning, and release policy\n');

function executableLines(step) {
  if (!step || typeof step.run !== 'string') return [];
  return step.run
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
}

function executableSource(source) {
  return source
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .join('\n');
}

function exactPermissions(actual, expected) {
  if (!actual || typeof actual !== 'object') return false;
  const actualEntries = Object.entries(actual).sort(([left], [right]) => left.localeCompare(right));
  const expectedEntries = Object.entries(expected).sort(([left], [right]) => left.localeCompare(right));
  return JSON.stringify(actualEntries) === JSON.stringify(expectedEntries);
}
