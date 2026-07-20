#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const MAX_JSON_BYTES = 4 * 1024 * 1024;
const DEFAULT_POLICY = '.github/hosting-policy.json';

export function auditGithubHosting(options = {}) {
  const policy = readJson(options.policyPath ?? DEFAULT_POLICY, 'hosting policy');
  assertPolicy(policy);
  const repository = options.repository ?? policy.repository;
  if (repository !== policy.repository) {
    throw new Error(`repository must be ${policy.repository}`);
  }
  const snapshot = options.snapshotPath
    ? readJson(options.snapshotPath, 'hosting snapshot')
    : captureHostingSnapshot(repository);
  const findings = [];
  compare(policy.repositorySettings, snapshot.repositorySettings, 'repositorySettings', findings);
  compareRulesets(policy.rulesets, snapshot.rulesets, findings);
  compareReleaseEnvironment(policy.releaseEnvironment, snapshot.releaseEnvironment, findings);
  return { valid: findings.length === 0, repository, findings };
}

function captureHostingSnapshot(repository) {
  const repo = gh(repository, 'repos/{repo}');
  const rulesetSummaries = gh(repository, 'repos/{repo}/rulesets');
  const rulesets = rulesetSummaries.map(({ id }) => gh(repository, `repos/{repo}/rulesets/${id}`));
  const vulnerabilityReporting = ghOptional(
    repository,
    'repos/{repo}/private-vulnerability-reporting',
    { enabled: false }
  );
  const pages = ghOptional(repository, 'repos/{repo}/pages', {
    build_type: null,
    public: false,
    https_enforced: false
  });
  const environment = ghOptional(repository, 'repos/{repo}/environments/release', {
    name: null,
    can_admins_bypass: true,
    protection_rules: [],
    deployment_branch_policy: null
  });
  const deploymentPolicies = ghOptional(
    repository,
    'repos/{repo}/environments/release/deployment-branch-policies',
    { branch_policies: [] }
  );
  const environmentSecrets = ghOptional(
    repository,
    'repos/{repo}/environments/release/secrets',
    { secrets: [] }
  );
  const environmentVariables = ghOptional(
    repository,
    'repos/{repo}/environments/release/variables',
    { variables: [] }
  );
  const actionsPermissions = gh(repository, 'repos/{repo}/actions/permissions/workflow');
  const immutableReleases = ghOptional(repository, 'repos/{repo}/immutable-releases', {
    enabled: false
  });
  const requiredReviewers = (environment.protection_rules ?? []).find(
    ({ type }) => type === 'required_reviewers'
  );
  const security = repo.security_and_analysis ?? {};
  return {
    repositorySettings: {
      visibility: repo.visibility,
      defaultBranch: repo.default_branch,
      issues: repo.has_issues,
      discussions: repo.has_discussions,
      deleteBranchOnMerge: repo.delete_branch_on_merge,
      allowMergeCommit: repo.allow_merge_commit,
      allowRebaseMerge: repo.allow_rebase_merge,
      allowSquashMerge: repo.allow_squash_merge,
      allowAutoMerge: repo.allow_auto_merge,
      webCommitSignoffRequired: repo.web_commit_signoff_required,
      immutableReleases: immutableReleases.enabled === true,
      privateVulnerabilityReporting: vulnerabilityReporting.enabled === true,
      vulnerabilityAlerts: ghEnabled(repository, 'repos/{repo}/vulnerability-alerts'),
      automatedSecurityFixes: ghEnabled(repository, 'repos/{repo}/automated-security-fixes'),
      secretScanning: security.secret_scanning?.status === 'enabled',
      secretScanningPushProtection:
        security.secret_scanning_push_protection?.status === 'enabled',
      codeScanning:
        security.code_security?.status === 'enabled' ||
        security.advanced_security?.status === 'enabled',
      dependabotSecurityUpdates: security.dependabot_security_updates?.status === 'enabled',
      defaultWorkflowPermissions: actionsPermissions.default_workflow_permissions,
      workflowsCanApprovePullRequests:
        actionsPermissions.can_approve_pull_request_reviews === true,
      pages: {
        buildType: pages.build_type,
        public: pages.public,
        httpsEnforced: pages.https_enforced
      }
    },
    rulesets: rulesets.map(normalizeRuleset),
    releaseEnvironment: {
      name: environment.name,
      preventSelfReview: requiredReviewers?.prevent_self_review === true,
      canAdminsBypass: environment.can_admins_bypass !== false,
      requiredReviewers: (requiredReviewers?.reviewers ?? [])
        .map(({ reviewer }) => reviewer?.login ?? reviewer?.slug)
        .filter((value) => typeof value === 'string')
        .sort(),
      protectedBranches: environment.deployment_branch_policy?.protected_branches === true,
      customBranchPolicies:
        environment.deployment_branch_policy?.custom_branch_policies === true,
      deploymentPolicies: (deploymentPolicies.branch_policies ?? [])
        .map(({ name, type }) => ({ name, type }))
        .sort(compareJson),
      secrets: Array.from(
        { length: environmentSecrets.total_count ?? environmentSecrets.secrets?.length ?? 0 },
        () => '<configured>'
      ),
      variables: Array.from(
        { length: environmentVariables.total_count ?? environmentVariables.variables?.length ?? 0 },
        () => '<configured>'
      )
    }
  };
}

function compareReleaseEnvironment(expected, actual, findings) {
  const {
    requiredReviewerMinimum,
    requiredReviewers: expectedReviewers,
    ...expectedSettings
  } = expected;
  const actualSettings = { ...(actual ?? {}) };
  const suppliedReviewers = actualSettings.requiredReviewers;
  const reviewerListValid =
    Array.isArray(suppliedReviewers) &&
    suppliedReviewers.every((reviewer) => typeof reviewer === 'string');
  const actualReviewers = reviewerListValid ? suppliedReviewers : [];
  delete actualSettings.requiredReviewers;
  delete actualSettings.requiredReviewerMinimum;
  compare(expectedSettings, actualSettings, 'releaseEnvironment', findings);
  if (!reviewerListValid) {
    findings.push({
      path: 'releaseEnvironment.requiredReviewers',
      expected: '<string array>',
      actual: '<invalid>'
    });
  }
  for (const reviewer of expectedReviewers) {
    if (!actualReviewers.includes(reviewer)) {
      findings.push({
        path: `releaseEnvironment.requiredReviewers.${reviewer}`,
        expected: '<present>',
        actual: '<missing>'
      });
    }
  }
  if (actualReviewers.length < requiredReviewerMinimum) {
    findings.push({
      path: 'releaseEnvironment.requiredReviewerMinimum',
      expected: requiredReviewerMinimum,
      actual: actualReviewers.length
    });
  }
  if (requiredReviewerMinimum === 0 && actualReviewers.length !== 0) {
    findings.push({
      path: 'releaseEnvironment.requiredReviewerMinimum',
      expected: 0,
      actual: actualReviewers.length
    });
  }
}

function normalizeRuleset(ruleset) {
  return {
    name: ruleset.name,
    target: ruleset.target,
    enforcement: ruleset.enforcement,
    bypass_actors: (ruleset.bypass_actors ?? []).map(normalizeJson).sort(compareJson),
    conditions: normalizeJson(ruleset.conditions),
    rules: (ruleset.rules ?? []).map(normalizeJson).sort(ruleOrder)
  };
}

function compareRulesets(expected, actual, findings) {
  const expectedByName = new Map(expected.map((ruleset) => [ruleset.name, canonicalRuleset(ruleset)]));
  const actualByName = new Map(actual.map((ruleset) => [ruleset.name, canonicalRuleset(ruleset)]));
  for (const [name, expectedRuleset] of expectedByName) {
    compare(expectedRuleset, actualByName.get(name), `rulesets.${name}`, findings);
  }
  for (const name of actualByName.keys()) {
    if (!expectedByName.has(name)) {
      findings.push({ path: `rulesets.${name}`, expected: '<absent>', actual: '<present>' });
    }
  }
}

function canonicalRuleset(ruleset) {
  const normalized = normalizeJson(ruleset);
  normalized.bypass_actors = (normalized.bypass_actors ?? []).sort(compareJson);
  normalized.rules = (normalized.rules ?? []).map((rule) => {
    if (rule.type === 'pull_request' && rule.parameters?.allowed_merge_methods) {
      rule.parameters.allowed_merge_methods.sort();
    }
    if (rule.type === 'required_status_checks' && rule.parameters?.required_status_checks) {
      rule.parameters.required_status_checks.sort(compareJson);
    }
    if (rule.type === 'code_scanning' && rule.parameters?.code_scanning_tools) {
      rule.parameters.code_scanning_tools.sort(compareJson);
    }
    return rule;
  }).sort(ruleOrder);
  return normalized;
}

function compare(expected, actual, location, findings) {
  const normalizedExpected = normalizeJson(expected);
  const normalizedActual = normalizeJson(actual);
  if (JSON.stringify(normalizedExpected) !== JSON.stringify(normalizedActual)) {
    if (isPlainObject(normalizedExpected) && isPlainObject(normalizedActual)) {
      const keys = new Set([...Object.keys(normalizedExpected), ...Object.keys(normalizedActual)]);
      for (const key of [...keys].sort()) {
        compare(normalizedExpected[key], normalizedActual[key], `${location}.${key}`, findings);
      }
      return;
    }
    findings.push({
      path: location,
      expected: safeFindingValue(location, normalizedExpected ?? '<missing>'),
      actual: safeFindingValue(location, normalizedActual ?? '<missing>')
    });
  }
}

function safeFindingValue(location, value) {
  if (
    (location === 'releaseEnvironment.secrets' ||
      location === 'releaseEnvironment.variables') &&
    Array.isArray(value)
  ) {
    return `<configured count ${value.length}>`;
  }
  return value;
}

function normalizeJson(value) {
  if (Array.isArray(value)) return value.map(normalizeJson);
  if (!isPlainObject(value)) return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, child]) => child !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => [key, normalizeJson(child)])
  );
}

function ruleOrder(left, right) {
  return String(left.type).localeCompare(String(right.type));
}

function compareJson(left, right) {
  return JSON.stringify(left).localeCompare(JSON.stringify(right));
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readJson(filename, label) {
  const bytes = readFileSync(path.resolve(filename));
  if (bytes.byteLength > MAX_JSON_BYTES) throw new Error(`${label} exceeds ${MAX_JSON_BYTES} bytes`);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

function assertPolicy(policy) {
  if (
    !isPlainObject(policy) ||
    policy.formatVersion !== '0.1' ||
    !/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/u.test(policy.repository ?? '') ||
    !isPlainObject(policy.repositorySettings) ||
    !Array.isArray(policy.rulesets) ||
    policy.rulesets.length !== 3 ||
    !isPlainObject(policy.releaseEnvironment) ||
    policy.releaseEnvironment.preventSelfReview !== false ||
    policy.releaseEnvironment.canAdminsBypass !== false ||
    !Array.isArray(policy.releaseEnvironment.requiredReviewers) ||
    policy.releaseEnvironment.requiredReviewers.length !== 0 ||
    policy.releaseEnvironment.requiredReviewers.some(
      (reviewer) => typeof reviewer !== 'string' || reviewer.length === 0
    ) ||
    new Set(policy.releaseEnvironment.requiredReviewers).size !==
      policy.releaseEnvironment.requiredReviewers.length ||
    !Number.isSafeInteger(policy.releaseEnvironment.requiredReviewerMinimum) ||
    policy.releaseEnvironment.requiredReviewerMinimum !== 0
  ) {
    throw new Error('hosting policy has an invalid structure');
  }
  const names = policy.rulesets.map(({ name }) => name);
  if (new Set(names).size !== names.length) throw new Error('hosting policy repeats a ruleset name');
}

function gh(repository, endpoint) {
  const result = spawnSync('gh', ['api', endpoint.replace('{repo}', repository)], {
    encoding: 'utf8',
    maxBuffer: MAX_JSON_BYTES
  });
  if (result.status !== 0) {
    throw new Error(`cannot read required GitHub hosting evidence: ${endpoint}`);
  }
  if (!result.stdout.trim()) return {};
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error(`GitHub returned invalid JSON for ${endpoint}`);
  }
}

function ghEnabled(repository, endpoint) {
  const result = spawnSync('gh', ['api', endpoint.replace('{repo}', repository)], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024
  });
  if (result.status === 0) return true;
  if (/HTTP 404|Not Found/u.test(result.stderr)) return false;
  throw new Error(`cannot read required GitHub hosting evidence: ${endpoint}`);
}

function ghOptional(repository, endpoint, fallback) {
  const result = spawnSync('gh', ['api', endpoint.replace('{repo}', repository)], {
    encoding: 'utf8',
    maxBuffer: MAX_JSON_BYTES
  });
  if (result.status !== 0) {
    if (/HTTP 404|Not Found/u.test(result.stderr)) return fallback;
    throw new Error(`cannot read required GitHub hosting evidence: ${endpoint}`);
  }
  if (!result.stdout.trim()) return {};
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error(`GitHub returned invalid JSON for ${endpoint}`);
  }
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--json') options.json = true;
    else if (argument === '--validate-policy') options.validatePolicy = true;
    else if (['--policy', '--snapshot', '--repository'].includes(argument)) {
      const value = argv[index + 1];
      if (!value) throw new Error(`missing value for ${argument}`);
      index += 1;
      if (argument === '--policy') options.policyPath = value;
      else if (argument === '--snapshot') options.snapshotPath = value;
      else options.repository = value;
    } else {
      throw new Error(
        'usage: audit-github-hosting.mjs [--policy FILE] [--snapshot FILE] [--repository OWNER/REPO] [--validate-policy] [--json]'
      );
    }
  }
  return options;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const options = parseArgs(process.argv.slice(2));
    if (options.validatePolicy) {
      if (options.snapshotPath || options.repository) {
        throw new Error('--validate-policy cannot be combined with --snapshot or --repository');
      }
      const policy = readJson(options.policyPath ?? DEFAULT_POLICY, 'hosting policy');
      assertPolicy(policy);
      process.stdout.write(`ok - GitHub hosting policy is structurally valid for ${policy.repository}\n`);
      process.exit(0);
    }
    const result = auditGithubHosting(options);
    if (options.json) process.stdout.write(`${JSON.stringify(result)}\n`);
    else if (result.valid) process.stdout.write(`ok - GitHub hosting matches policy for ${result.repository}\n`);
    else {
      for (const finding of result.findings) {
        process.stderr.write(
          `not ok - ${finding.path}: expected ${displayValue(finding.expected)}, got ${displayValue(finding.actual)}\n`
        );
      }
    }
    process.exitCode = result.valid ? 0 : 1;
  } catch (error) {
    process.stderr.write(`not ok - ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 2;
  }
}

function displayValue(value) {
  if (Array.isArray(value)) return `<array length ${value.length}>`;
  if (isPlainObject(value)) return '<configured object>';
  return JSON.stringify(value);
}
