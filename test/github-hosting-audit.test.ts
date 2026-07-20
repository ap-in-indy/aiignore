import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { auditGithubHosting } from '../scripts/audit-github-hosting.mjs';

const policyPath = path.resolve('.github/hosting-policy.json');
const policy = JSON.parse(readFileSync(policyPath, 'utf8')) as HostingPolicy;

describe('public GitHub hosting policy audit', () => {
  it('accepts the complete reviewed desired state independent of semantic array order', () => {
    const snapshot = completeSnapshot();
    snapshot.rulesets.reverse();
    snapshot.rulesets[0]!.rules.reverse();
    const statusChecks = snapshot.rulesets
      .find(({ name }) => name === 'Protect main')!
      .rules.find(({ type }) => type === 'required_status_checks')!;
    statusChecks.parameters!.required_status_checks!.reverse();
    expect(auditGithubHosting({ policyPath, snapshotPath: writeSnapshot(snapshot) })).toEqual({
      valid: true,
      repository: 'ap-in-indy/aiignore',
      findings: []
    });
  });

  it.each([
    ['repository visibility', (value: HostingPolicy) => { value.repositorySettings.visibility = 'private'; }, 'repositorySettings.visibility'],
    ['push protection', (value: HostingPolicy) => { value.repositorySettings.secretScanningPushProtection = false; }, 'repositorySettings.secretScanningPushProtection'],
    ['workflow write authority', (value: HostingPolicy) => { value.repositorySettings.defaultWorkflowPermissions = 'write'; }, 'repositorySettings.defaultWorkflowPermissions'],
    ['unexpected release reviewer rule', (value: HostingPolicy) => {
      value.releaseEnvironment.preventSelfReview = true;
      value.releaseEnvironment.requiredReviewers = ['ap-in-indy'];
    }, 'releaseEnvironment.preventSelfReview'],
    ['release administrator bypass', (value: HostingPolicy) => { value.releaseEnvironment.canAdminsBypass = true; }, 'releaseEnvironment.canAdminsBypass'],
    ['release secret', (value: HostingPolicy) => { value.releaseEnvironment.secrets = ['NPM_TOKEN']; }, 'releaseEnvironment.secrets'],
    ['release branch policy', (value: HostingPolicy) => { value.releaseEnvironment.deploymentPolicies = []; }, 'releaseEnvironment.deploymentPolicies']
  ])('reports exact drift for %s without exposing values beyond setting metadata', (_name, mutate, expectedPath) => {
    const snapshot = completeSnapshot();
    mutate(snapshot);
    const result = auditGithubHosting({ policyPath, snapshotPath: writeSnapshot(snapshot) });
    expect(result.valid).toBe(false);
    expect(result.findings.map(({ path: findingPath }) => findingPath)).toContain(expectedPath);
  });

  it('rejects weakened main protection, tag mutation, bypass actors, and unexpected rulesets', () => {
    const snapshot = completeSnapshot();
    const main = snapshot.rulesets.find(({ name }) => name === 'Protect main')!;
    main.rules = main.rules.filter(({ type }) => type !== 'pull_request');
    const tags = snapshot.rulesets.find(({ name }) => name === 'Protect release tags')!;
    tags.rules = tags.rules.filter(({ type }) => type !== 'update');
    main.bypass_actors = [{ actor_type: 'RepositoryRole', actor_id: 5, bypass_mode: 'always' }];
    snapshot.rulesets.push({
      name: 'Unreviewed bypass',
      target: 'branch',
      enforcement: 'active',
      bypass_actors: [],
      conditions: { ref_name: { include: ['~ALL'], exclude: [] } },
      rules: []
    });
    const paths = auditGithubHosting({ policyPath, snapshotPath: writeSnapshot(snapshot) })
      .findings.map(({ path: findingPath }) => findingPath);
    expect(paths).toContain('rulesets.Protect main.bypass_actors');
    expect(paths).toContain(
      'rulesets.Protect main.rules'
    );
    expect(paths).toContain('rulesets.Protect release tags.rules');
    expect(paths).toContain('rulesets.Unreviewed bypass');
  });

  it('rejects a required check that is not pinned to the GitHub Actions app', () => {
    const snapshot = completeSnapshot();
    const statusChecks = snapshot.rulesets
      .find(({ name }) => name === 'Protect main')!
      .rules.find(({ type }) => type === 'required_status_checks')!;
    statusChecks.parameters!.required_status_checks![0]!.integration_id = 999;
    const result = auditGithubHosting({ policyPath, snapshotPath: writeSnapshot(snapshot) });
    expect(result.valid).toBe(false);
    expect(result.findings.map(({ path: findingPath }) => findingPath)).toContain(
      'rulesets.Protect main.rules'
    );
  });

  it('requires the reviewed solo environment to have no human reviewer rule', () => {
    const unexpectedReviewer = completeSnapshot();
    unexpectedReviewer.releaseEnvironment.requiredReviewers = ['ap-in-indy'];
    unexpectedReviewer.releaseEnvironment.preventSelfReview = true;
    expect(
      auditGithubHosting({ policyPath, snapshotPath: writeSnapshot(unexpectedReviewer) }).findings
        .map(({ path: findingPath }) => findingPath)
    ).toContain('releaseEnvironment.requiredReviewerMinimum');
  });

  it('rejects malformed reviewer evidence without treating text as a reviewer array', () => {
    const snapshot = completeSnapshot();
    snapshot.releaseEnvironment.requiredReviewers = 'ap-in-indy-and-someone' as unknown as string[];
    const result = auditGithubHosting({ policyPath, snapshotPath: writeSnapshot(snapshot) });
    expect(result.valid).toBe(false);
    expect(result.findings.map(({ path: findingPath }) => findingPath)).toContain(
      'releaseEnvironment.requiredReviewers'
    );
  });

  it('rejects a desired state that misrepresents the solo release model', () => {
    const inconsistentPolicy = structuredClone(policy);
    inconsistentPolicy.releaseEnvironment.preventSelfReview = true;
    inconsistentPolicy.releaseEnvironment.requiredReviewers = ['ap-in-indy'];
    inconsistentPolicy.releaseEnvironment.requiredReviewerMinimum = 1;
    const inconsistentPolicyPath = writeSnapshot(inconsistentPolicy);
    expect(() =>
      auditGithubHosting({ policyPath: inconsistentPolicyPath, snapshotPath: writeSnapshot(completeSnapshot()) })
    ).toThrow(/invalid structure/u);
  });

  it('never returns environment secret or variable names in audit findings', () => {
    const snapshot = completeSnapshot();
    snapshot.releaseEnvironment.secrets = ['DO_NOT_DISCLOSE_SECRET_NAME'];
    snapshot.releaseEnvironment.variables = ['DO_NOT_DISCLOSE_VARIABLE_NAME'];
    const serialized = JSON.stringify(
      auditGithubHosting({ policyPath, snapshotPath: writeSnapshot(snapshot) })
    );
    expect(serialized).not.toContain('DO_NOT_DISCLOSE');
    expect(serialized).toContain('<configured count 1>');
  });

  it('rejects the wrong repository and malformed or oversized evidence', () => {
    expect(() =>
      auditGithubHosting({
        policyPath,
        snapshotPath: writeSnapshot(policy),
        repository: 'attacker/example'
      })
    ).toThrow(/repository must be/u);
    const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-hosting-invalid-'));
    const malformed = path.join(directory, 'snapshot.json');
    writeFileSync(malformed, '{');
    expect(() => auditGithubHosting({ policyPath, snapshotPath: malformed })).toThrow(
      /not valid JSON/u
    );
    writeFileSync(malformed, Buffer.alloc(4 * 1024 * 1024 + 1));
    expect(() => auditGithubHosting({ policyPath, snapshotPath: malformed })).toThrow(/exceeds/u);
  });

  it('locks all high-value owner-side controls in the desired state', () => {
    expect(policy.repositorySettings).toMatchObject({
      visibility: 'public',
      defaultBranch: 'main',
      immutableReleases: true,
      privateVulnerabilityReporting: true,
      vulnerabilityAlerts: true,
      automatedSecurityFixes: true,
      secretScanning: true,
      secretScanningPushProtection: true,
      codeScanning: true,
      dependabotSecurityUpdates: true,
      defaultWorkflowPermissions: 'read',
      workflowsCanApprovePullRequests: false,
      webCommitSignoffRequired: true
    });
    expect(policy.releaseEnvironment).toMatchObject({
      name: 'release',
      preventSelfReview: false,
      canAdminsBypass: false,
      requiredReviewers: [],
      requiredReviewerMinimum: 0,
      secrets: [],
      variables: [],
      deploymentPolicies: [{ name: 'v*', type: 'tag' }]
    });
    expect(policy.rulesets.find(({ name }) => name === 'Protect release tags')).toMatchObject({
      enforcement: 'active',
      bypass_actors: [],
      rules: [{ type: 'update' }, { type: 'deletion' }]
    });
    expect(
      policy.rulesets.find(({ name }) => name === 'Restrict release tag creation')
    ).toMatchObject({
      enforcement: 'active',
      bypass_actors: [
        { actor_id: 93954900, actor_type: 'User', bypass_mode: 'always' }
      ],
      rules: [{ type: 'creation' }]
    });
    expect(
      policy.rulesets
        .find(({ name }) => name === 'Protect main')!
        .rules.find(({ type }) => type === 'required_status_checks')!
      .parameters!.required_status_checks!.map(({ context, integration_id }) => ({
        context,
        integration_id
      }))
    ).toEqual([
      { context: 'Node 20 on ubuntu-latest', integration_id: 15368 },
      { context: 'Node 24 on ubuntu-latest', integration_id: 15368 },
      { context: 'Node 24 on macos-latest', integration_id: 15368 },
      { context: 'Node 24 on windows-latest', integration_id: 15368 },
      { context: 'package', integration_id: 15368 },
      { context: 'DCO sign-off', integration_id: 15368 },
      { context: 'fuzz', integration_id: 15368 },
      { context: 'Gitleaks full history', integration_id: 15368 },
      { context: 'dependency-review', integration_id: 15368 },
      { context: 'Analyze JavaScript and TypeScript', integration_id: 15368 }
    ]);
  });
});

function writeSnapshot(snapshot: HostingPolicy): string {
  const directory = mkdtempSync(path.join(tmpdir(), 'aiignore-hosting-snapshot-'));
  const filename = path.join(directory, 'snapshot.json');
  writeFileSync(filename, `${JSON.stringify(snapshot)}\n`);
  return filename;
}

function completeSnapshot(): HostingPolicy {
  return structuredClone(policy);
}

interface Rule {
  type: string;
  parameters?: {
    required_approving_review_count?: number;
    required_status_checks?: Array<{ context: string; integration_id?: number }>;
  };
}

interface HostingPolicy {
  repository: string;
  repositorySettings: Record<string, unknown> & {
    visibility: string;
    secretScanningPushProtection: boolean;
    defaultWorkflowPermissions: string;
  };
  rulesets: Array<{
    name: string;
    target: string;
    enforcement: string;
    bypass_actors: unknown[];
    conditions: { ref_name: { include: string[]; exclude: string[] } };
    rules: Rule[];
  }>;
  releaseEnvironment: Record<string, unknown> & {
    preventSelfReview: boolean;
    canAdminsBypass: boolean;
    requiredReviewers: string[];
    requiredReviewerMinimum: number;
    secrets: string[];
    variables: string[];
    deploymentPolicies: Array<{ name: string; type: string }>;
  };
}
