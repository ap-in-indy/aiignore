#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { parse } from 'yaml';

const DCO_SHA256 = 'dac2b0a921aaf4bcaf484dc082fbea072398bedecf5f1d4dcce7e122bbe5d2d5';
const OSPS_CONTROLS = [
  'OSPS-AC-01.01',
  'OSPS-AC-02.01',
  'OSPS-AC-03.01',
  'OSPS-AC-03.02',
  'OSPS-AC-04.01',
  'OSPS-AC-04.02',
  'OSPS-BR-01.01',
  'OSPS-BR-01.03',
  'OSPS-BR-01.04',
  'OSPS-BR-02.01',
  'OSPS-BR-02.02',
  'OSPS-BR-03.01',
  'OSPS-BR-03.02',
  'OSPS-BR-04.01',
  'OSPS-BR-05.01',
  'OSPS-BR-06.01',
  'OSPS-BR-07.01',
  'OSPS-BR-07.02',
  'OSPS-DO-01.01',
  'OSPS-DO-02.01',
  'OSPS-DO-03.01',
  'OSPS-DO-03.02',
  'OSPS-DO-04.01',
  'OSPS-DO-05.01',
  'OSPS-DO-06.01',
  'OSPS-DO-07.01',
  'OSPS-GV-01.01',
  'OSPS-GV-01.02',
  'OSPS-GV-02.01',
  'OSPS-GV-03.01',
  'OSPS-GV-03.02',
  'OSPS-GV-04.01',
  'OSPS-LE-01.01',
  'OSPS-LE-02.01',
  'OSPS-LE-02.02',
  'OSPS-LE-03.01',
  'OSPS-LE-03.02',
  'OSPS-QA-01.01',
  'OSPS-QA-01.02',
  'OSPS-QA-02.01',
  'OSPS-QA-02.02',
  'OSPS-QA-03.01',
  'OSPS-QA-04.01',
  'OSPS-QA-04.02',
  'OSPS-QA-05.01',
  'OSPS-QA-05.02',
  'OSPS-QA-06.01',
  'OSPS-QA-06.02',
  'OSPS-QA-06.03',
  'OSPS-QA-07.01',
  'OSPS-SA-01.01',
  'OSPS-SA-02.01',
  'OSPS-SA-03.01',
  'OSPS-SA-03.02',
  'OSPS-VM-01.01',
  'OSPS-VM-02.01',
  'OSPS-VM-03.01',
  'OSPS-VM-04.01',
  'OSPS-VM-04.02',
  'OSPS-VM-05.01',
  'OSPS-VM-05.02',
  'OSPS-VM-05.03',
  'OSPS-VM-06.01',
  'OSPS-VM-06.02'
];
const OSPS_STATUSES = new Map();
for (const [status, controls] of Object.entries({
  Unverified: ['OSPS-AC-01.01'],
  Prepared: [
    'OSPS-AC-02.01',
    'OSPS-AC-04.01',
    'OSPS-BR-02.01',
    'OSPS-BR-02.02',
    'OSPS-BR-03.01',
    'OSPS-BR-03.02',
    'OSPS-BR-04.01',
    'OSPS-BR-06.01',
    'OSPS-DO-01.01',
    'OSPS-DO-02.01',
    'OSPS-GV-02.01',
    'OSPS-DO-03.01',
    'OSPS-DO-03.02',
    'OSPS-DO-04.01',
    'OSPS-DO-05.01',
    'OSPS-LE-01.01',
    'OSPS-LE-02.02',
    'OSPS-LE-03.02',
    'OSPS-QA-02.02',
    'OSPS-QA-06.01',
    'OSPS-SA-01.01',
    'OSPS-SA-02.01',
    'OSPS-SA-03.01',
    'OSPS-VM-04.01',
    'OSPS-VM-04.02',
    'OSPS-VM-05.03'
  ],
  'Not met': [
    'OSPS-AC-03.01',
    'OSPS-AC-03.02',
    'OSPS-QA-01.01',
    'OSPS-QA-01.02',
    'OSPS-QA-03.01',
    'OSPS-QA-07.01',
    'OSPS-VM-06.02'
  ],
  'Not applicable': ['OSPS-QA-04.01', 'OSPS-QA-04.02'],
  'Implemented policy': ['OSPS-VM-06.01'],
  Implemented: [
    'OSPS-AC-04.02',
    'OSPS-BR-01.01',
    'OSPS-BR-01.03',
    'OSPS-BR-01.04',
    'OSPS-BR-05.01',
    'OSPS-BR-07.01',
    'OSPS-BR-07.02',
    'OSPS-DO-06.01',
    'OSPS-DO-07.01',
    'OSPS-GV-01.01',
    'OSPS-GV-01.02',
    'OSPS-GV-03.01',
    'OSPS-GV-03.02',
    'OSPS-GV-04.01',
    'OSPS-LE-02.01',
    'OSPS-LE-03.01',
    'OSPS-QA-02.01',
    'OSPS-QA-05.01',
    'OSPS-QA-05.02',
    'OSPS-QA-06.02',
    'OSPS-QA-06.03',
    'OSPS-SA-03.02',
    'OSPS-VM-01.01',
    'OSPS-VM-02.01',
    'OSPS-VM-03.01',
    'OSPS-VM-05.01',
    'OSPS-VM-05.02'
  ]
})) {
  for (const control of controls) OSPS_STATUSES.set(control, status);
}

const args = process.argv.slice(2);
let root = process.cwd();
if (args.length > 0) {
  if (args.length !== 2 || args[0] !== '--root') {
    throw new Error('usage: validate-project-policy.mjs [--root DIRECTORY]');
  }
  root = path.resolve(args[1]);
}

const failures = [];
const read = (filename) => readFileSync(path.join(root, filename), 'utf8');
const packageJson = JSON.parse(read('package.json'));
const citation = parse(read('CITATION.cff'));
const schema = JSON.parse(read('schema/aiignore.schema.json'));
const version = packageJson.version;
const policyVersion = schema?.properties?.aiignore?.const;

if (!/^0\.1\.0-alpha\.[1-9][0-9]*$/u.test(version)) {
  failures.push('package.json: release candidate must use the reviewed 0.1.0-alpha.N grammar');
}
if (citation?.version !== version) failures.push('CITATION.cff: version must match package.json');
if (policyVersion !== '0.1') failures.push('schema: policy language must remain draft 0.1');
if (!read('CHANGELOG.md').includes(`## [${version}] - `)) {
  failures.push('CHANGELOG.md: versioned release heading is required');
}
const releaseNotes = read(`docs/release-notes/${version}.md`);
if (
  !releaseNotes.includes('experimental public draft') ||
  !releaseNotes.includes('not as an endorsed\nindustry standard')
) {
  failures.push('release notes: experimental, non-endorsed draft status must remain explicit');
}

const requiredPackageFiles = [
  'DCO',
  'docs/architecture.md',
  'docs/conformance-policy.md',
  'docs/credential-management.md',
  'docs/security-baseline.md',
  'docs/versioning.md'
];
for (const filename of requiredPackageFiles) {
  if (!packageJson.files?.includes(filename) && !filename.startsWith('docs/')) {
    failures.push(`package.json: files must include ${filename}`);
  }
}
if (!packageJson.files?.includes('docs')) failures.push('package.json: files must include docs');
if (!packageJson.files?.includes('spec')) failures.push('package.json: files must include spec');

for (const [filename, required] of new Map([
  ['spec/registries.md', [
    'Status: **Normative companion to draft 0.1**',
    'All draft 0.1 registries are **closed**',
    'Removed values remain reserved',
    'Draft 0.1 defines no private-use token range'
  ]],
  ['spec/errata.md', [
    'Status: **Authoritative errata index**',
    'There are currently **no verified errata**',
    'Published specification, schema, vector, manifest, tag, and release-asset',
    'or security correction requires an RFC'
  ]]
])) {
  const source = read(filename);
  for (const fragment of required) {
    if (!source.includes(fragment)) {
      failures.push(`${filename}: missing standards-maintenance contract ${fragment}`);
    }
  }
}

const dcoBytes = readFileSync(path.join(root, 'DCO'));
if (createHash('sha256').update(dcoBytes).digest('hex') !== DCO_SHA256) {
  failures.push('DCO: verbatim Developer Certificate of Origin 1.1 changed');
}

const issueConfig = parse(read('.github/ISSUE_TEMPLATE/config.yml'));
if (issueConfig?.blank_issues_enabled !== false) {
  failures.push('issue templates: blank issues must remain disabled for structured safe intake');
}
const hostingPolicy = JSON.parse(read('.github/hosting-policy.json'));
if (
  hostingPolicy?.formatVersion !== '0.1' ||
  hostingPolicy?.repository !== 'ap-in-indy/aiignore' ||
  hostingPolicy?.repositorySettings?.visibility !== 'public' ||
  hostingPolicy?.repositorySettings?.defaultWorkflowPermissions !== 'read' ||
  hostingPolicy?.repositorySettings?.workflowsCanApprovePullRequests !== false ||
  hostingPolicy?.repositorySettings?.immutableReleases !== true ||
  hostingPolicy?.repositorySettings?.secretScanningPushProtection !== true ||
  hostingPolicy?.releaseEnvironment?.name !== 'release' ||
  hostingPolicy?.releaseEnvironment?.preventSelfReview !== false ||
  hostingPolicy?.releaseEnvironment?.canAdminsBypass !== false ||
  hostingPolicy?.releaseEnvironment?.requiredReviewerMinimum !== 0 ||
  hostingPolicy?.releaseEnvironment?.requiredReviewers?.length !== 0 ||
  hostingPolicy?.releaseEnvironment?.secrets?.length !== 0 ||
  hostingPolicy?.releaseEnvironment?.variables?.length !== 0
) {
  failures.push('hosting policy: owner-side security and least-privilege settings drifted');
}
const mainRuleset = hostingPolicy?.rulesets?.find(({ name }) => name === 'Protect main');
const tagRuleset = hostingPolicy?.rulesets?.find(({ name }) => name === 'Protect release tags');
const tagCreationRuleset = hostingPolicy?.rulesets?.find(
  ({ name }) => name === 'Restrict release tag creation'
);
const requiredChecks = mainRuleset?.rules?.find(({ type }) => type === 'required_status_checks')
  ?.parameters?.required_status_checks;
const pullRequestRule = mainRuleset?.rules?.find(({ type }) => type === 'pull_request');
for (const required of [
  'Node 20 on ubuntu-latest',
  'Node 24 on ubuntu-latest',
  'Node 24 on macos-latest',
  'Node 24 on windows-latest',
  'package',
  'DCO sign-off',
  'fuzz',
  'Gitleaks full history',
  'dependency-review',
  'Analyze JavaScript and TypeScript'
]) {
  if (!requiredChecks?.some(({ context, integration_id }) =>
    context === required && integration_id === 15368
  )) {
    failures.push(`hosting policy: main ruleset is missing required check ${required}`);
  }
}
if (
  mainRuleset?.enforcement !== 'active' ||
  mainRuleset?.bypass_actors?.length !== 0 ||
  JSON.stringify(pullRequestRule?.parameters) !==
    JSON.stringify({
      allowed_merge_methods: ['squash'],
      dismiss_stale_reviews_on_push: false,
      require_code_owner_review: false,
      require_last_push_approval: false,
      required_approving_review_count: 0,
      required_review_thread_resolution: true
    }) ||
  !mainRuleset?.rules?.some(({ type }) => type === 'required_signatures') ||
  tagRuleset?.enforcement !== 'active' ||
  tagRuleset?.bypass_actors?.length !== 0 ||
  !tagRuleset?.rules?.some(({ type }) => type === 'update') ||
  !tagRuleset?.rules?.some(({ type }) => type === 'deletion') ||
  tagCreationRuleset?.enforcement !== 'active' ||
  JSON.stringify(tagCreationRuleset?.bypass_actors) !==
    JSON.stringify([
      { actor_id: 93954900, actor_type: 'User', bypass_mode: 'always' }
    ]) ||
  tagCreationRuleset?.rules?.length !== 1 ||
  tagCreationRuleset?.rules?.[0]?.type !== 'creation'
) {
  failures.push('hosting policy: branch or immutable release-tag protection drifted');
}
const conformanceIssue = read('.github/ISSUE_TEMPLATE/conformance.yml');
for (const required of [
  'id: target',
  'Implementation',
  'Harness',
  'schema/implementation-conformance-report.schema.json',
  'schema/conformance-report.schema.json',
  'did not use implementation results as harness-enforcement evidence or vice versa'
]) {
  if (!conformanceIssue.includes(required)) {
    failures.push(`conformance issue form: missing claim-separation contract ${required}`);
  }
}

const codeowners = read('.github/CODEOWNERS');
for (const protectedPath of [
  '/.github/ @ap-in-indy',
  '/DCO @ap-in-indy',
  '/MAINTAINERS.md @ap-in-indy',
  '/SECURITY.md @ap-in-indy',
  '/docs/maintainer-release-runbook.md @ap-in-indy',
  '/docs/versioning.md @ap-in-indy',
  '/conformance/requirements-v0.1.json @ap-in-indy',
  '/package-lock.json @ap-in-indy',
  '/scripts/scan-secrets.sh @ap-in-indy',
  '/scripts/validate-alpha-advance.mjs @ap-in-indy',
  '/scripts/validate-dco.mjs @ap-in-indy',
  '/scripts/validate-requirements-traceability.mjs @ap-in-indy',
  '/scripts/validate-workflows.mjs @ap-in-indy',
  '/spec/ @ap-in-indy'
]) {
  if (!codeowners.split('\n').includes(protectedPath)) {
    failures.push(`CODEOWNERS: missing critical ownership rule ${protectedPath}`);
  }
}

const dcoWorkflow = parse(read('.github/workflows/dco.yml'));
const dcoSource = read('.github/workflows/dco.yml');
const dcoJob = dcoWorkflow?.jobs?.signoff;
const dcoSteps = dcoJob?.steps ?? [];
const checkout = dcoSteps.find((step) => step?.uses?.startsWith('actions/checkout@'));
const validation = dcoSteps.find((step) => step?.name?.startsWith('Require a matching sign-off'));
const dcoExpressions = [...dcoSource.matchAll(/\$\{\{\s*([^}]+?)\s*\}\}/gu)].map(
  (match) => match[1].trim()
);
const expectedDcoExpressions = [
  'github.workflow',
  'github.event.pull_request.number',
  'github.event.pull_request.base.sha',
  'github.token',
  'github.event.pull_request.number',
  'github.repository'
].sort();
if (
  !sameKeys(dcoWorkflow, ['concurrency', 'jobs', 'name', 'on', 'permissions']) ||
  dcoWorkflow?.name !== 'DCO' ||
  !Object.hasOwn(dcoWorkflow?.on ?? {}, 'pull_request_target') ||
  Object.hasOwn(dcoWorkflow?.on ?? {}, 'pull_request') ||
  !sameKeys(dcoWorkflow?.on, ['pull_request_target']) ||
  JSON.stringify(dcoWorkflow?.permissions) !==
    JSON.stringify({ contents: 'read', 'pull-requests': 'read' }) ||
  dcoWorkflow?.concurrency?.group !==
    'dco-${{ github.workflow }}-${{ github.event.pull_request.number }}' ||
  dcoWorkflow?.concurrency?.['cancel-in-progress'] !== true ||
  !sameKeys(dcoWorkflow?.jobs, ['signoff']) ||
  !sameKeys(dcoJob, ['name', 'runs-on', 'steps', 'timeout-minutes']) ||
  dcoJob?.name !== 'DCO sign-off' ||
  dcoJob?.['runs-on'] !== 'ubuntu-latest' ||
  dcoJob?.['timeout-minutes'] !== 5 ||
  Object.hasOwn(dcoJob ?? {}, 'if') ||
  Object.hasOwn(dcoJob ?? {}, 'continue-on-error') ||
  dcoSteps.some(
    (step) =>
      Object.hasOwn(step ?? {}, 'if') || Object.hasOwn(step ?? {}, 'continue-on-error')
  ) ||
  dcoSteps.length !== 2 ||
  checkout !== dcoSteps[0] ||
  validation !== dcoSteps[1] ||
  !sameKeys(checkout, ['uses', 'with']) ||
  checkout?.uses !== 'actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd' ||
  !sameKeys(checkout?.with, ['fetch-depth', 'persist-credentials', 'ref']) ||
  checkout?.with?.['fetch-depth'] !== 1 ||
  checkout?.with?.['persist-credentials'] !== false ||
  checkout?.with?.ref !== '${{ github.event.pull_request.base.sha }}' ||
  !sameKeys(validation, ['env', 'name', 'run']) ||
  !sameKeys(validation?.env, ['GITHUB_TOKEN', 'PR_NUMBER', 'REPOSITORY']) ||
  validation?.run !==
    'node scripts/validate-dco.mjs --github-repository "$REPOSITORY" --pull-request "$PR_NUMBER"' ||
  validation?.env?.GITHUB_TOKEN !== '${{ github.token }}' ||
  validation?.env?.PR_NUMBER !== '${{ github.event.pull_request.number }}' ||
  validation?.env?.REPOSITORY !== '${{ github.repository }}' ||
  JSON.stringify(dcoExpressions.sort()) !== JSON.stringify(expectedDcoExpressions)
) {
  failures.push('dco.yml: trusted-base, read-only, API-bound DCO validation is required');
}

const baseline = read('docs/security-baseline.md').replace(/<!--[\s\S]*?-->/gu, '');
if (!baseline.includes('**2026.02.19**')) {
  failures.push('security baseline: reviewed OSPS version must be explicit');
}
const baselineRows = new Map();
for (const match of baseline.matchAll(
  /^\|\s*(OSPS-[A-Z]{2}-[0-9]{2}\.[0-9]{2})\s+([^|\n]{3,})\|\s*(Implemented policy|Implemented|Prepared|Not met|Not applicable|Unverified)\s*\|\s*([^|\n]{20,})\s*\|$/gmu
)) {
  const [, control, description, status, evidence] = match;
  if (baselineRows.has(control)) failures.push(`security baseline: duplicate row ${control}`);
  baselineRows.set(control, {
    description: description.trim(),
    status,
    evidence: evidence.trim()
  });
}
if (OSPS_STATUSES.size !== OSPS_CONTROLS.length) {
  failures.push('security baseline validator: expected-status inventory is incomplete');
}
for (const control of OSPS_CONTROLS) {
  const row = baselineRows.get(control);
  if (!row) failures.push(`security baseline: ${control} must have one structured evidence row`);
  else if (row.status !== OSPS_STATUSES.get(control)) {
    failures.push(
      `security baseline: ${control} status must remain ${OSPS_STATUSES.get(control)}`
    );
  }
}
for (const control of baselineRows.keys()) {
  if (!OSPS_STATUSES.has(control)) failures.push(`security baseline: unknown control ${control}`);
}

const documentContracts = new Map([
  ['spec/aiignore.md', [
    '[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html)',
    '"policyDigest": "0000000000000000000000000000000000000000000000000000000000000000"',
    '### 11.1 Implementation conformance',
    '### 11.2 Harness conformance',
    '## 13. Privacy and data minimization',
    '## 14. Internationalization and text processing',
    '## 16. Normative references'
  ]],
  ['docs/getting-started.md', [
    '# Getting started safely',
    'npx aiignore doctor',
    '`deploymentEnforcement` is fixed to `"not-established"`',
    'does not turn the policy file or reference CLI into\na sandbox'
  ]],
  ['docs/architecture.md', [
    '# Security architecture and external interfaces',
    '## Actors and trust assumptions',
    '## Public TypeScript interface',
    '## CLI interface',
    '## Security boundaries and failure modes'
  ]],
  ['docs/public-hosting.md', [
    '# Public repository hosting controls',
    '.github/hosting-policy.json',
    'npm run hosting:audit',
    'during the preceding seven days',
    'do not put a\npersonal access token in Actions'
  ]],
  ['docs/requirements-traceability.md', [
    '# Normative requirements traceability',
    'all 151\nuses of BCP 14 requirement keywords',
    'implemented-with-external-limits',
    'not a claim that 151 independent test cases'
  ]],
  ['docs/conformance-policy.md', [
    '# Conformance evidence and claim policy',
    '## Claim targets',
    '## Independent implementation requirements',
    '## Status and withdrawal',
    'No conformance mark exists during the alpha.'
  ]],
  ['docs/credential-management.md', [
    '# Project credential and signing-key policy',
    '## Release authority',
    '## Rotation and incident response',
    'two-person key custody'
  ]],
  ['docs/versioning.md', [
    '# Versioning and compatibility policy',
    '## Policy-language evolution',
    '## Support and end of life',
    'Released tags,\npackages, manifests, schemas, vectors, and reports are immutable.'
  ]],
  ['MAINTAINERS.md', [
    '## Sensitive-resource authority',
    '## Adding or escalating maintainers',
    '## Continuity and quorum',
    'no release may claim independent maintainer\nreview'
  ]],
  ['SECURITY.md', [
    'five business days',
    '## Dependency and static-analysis findings',
    'There is no guaranteed remediation SLA.'
  ]],
  ['SUPPORT.md', [
    'Only the latest published prerelease and current `main` are supported',
    'No alpha receives long-term\nsupport.'
  ]]
]);
for (const [filename, fragments] of documentContracts) {
  const source = read(filename);
  for (const fragment of fragments) {
    if (!source.includes(fragment)) failures.push(`${filename}: missing policy contract ${fragment}`);
  }
}

if (failures.length > 0) {
  failures.forEach((failure) => process.stderr.write(`not ok - ${failure}\n`));
  process.exit(1);
}
process.stdout.write(
  `ok - version, DCO, ownership, intake, conformance, and ${OSPS_CONTROLS.length} structured OSPS control records\n`
);

function sameKeys(value, expected) {
  return (
    value &&
    typeof value === 'object' &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort())
  );
}
