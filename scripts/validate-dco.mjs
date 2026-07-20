#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const MAX_COMMITS = 250;
const MAX_PAGE_BYTES = 8 * 1024 * 1024;
const SHA256_PATTERN = /^[a-f0-9]{40}$/u;
const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u;
const PULL_REQUEST_PATTERN = /^[1-9][0-9]*$/u;
const SIGNOFF_PATTERN = /^Signed-off-by:\s*([^<>\r\n]+?)\s*<([^<>\s\r\n]+)>\s*$/gmu;

export function validateDcoRange(base, head, options = {}) {
  if (!SHA256_PATTERN.test(base) || !SHA256_PATTERN.test(head)) {
    throw new Error('DCO range endpoints must be full lowercase Git commit SHAs');
  }
  const runGit = options.runGit ?? defaultRunGit;
  runGit(['cat-file', '-e', `${base}^{commit}`]);
  runGit(['cat-file', '-e', `${head}^{commit}`]);
  runGit(['merge-base', '--is-ancestor', base, head]);
  const commitIds = runGit(['rev-list', '--reverse', `${base}..${head}`])
    .trim()
    .split('\n')
    .filter(Boolean);
  const commits = commitIds.map((commit) => {
    if (!SHA256_PATTERN.test(commit)) throw new Error('git returned a malformed commit identity');
    const fields = runGit([
      'show',
      '--no-patch',
      '--format=%an%x00%ae%x00%B',
      commit
    ]).split('\0');
    if (fields.length < 3) throw new Error(`cannot inspect DCO metadata for ${commit}`);
    const [authorName, authorEmail, ...messageParts] = fields;
    return { sha: commit, authorName, authorEmail, message: messageParts.join('\0') };
  });
  return validateDcoCommits(commits);
}

export function validateDcoCommits(commits) {
  if (!Array.isArray(commits) || commits.length === 0 || commits.length > MAX_COMMITS) {
    throw new Error(`DCO range must contain between 1 and ${MAX_COMMITS} commits`);
  }
  const failures = [];
  const identities = new Set();
  for (const commit of commits) {
    if (!SHA256_PATTERN.test(commit.sha)) throw new Error('commit has a malformed identity');
    if (identities.has(commit.sha)) throw new Error('commit metadata contains a duplicate identity');
    identities.add(commit.sha);
    if (
      typeof commit.authorName !== 'string' ||
      !commit.authorName.trim() ||
      typeof commit.authorEmail !== 'string' ||
      !commit.authorEmail.trim() ||
      typeof commit.message !== 'string'
    ) {
      throw new Error(`commit ${commit.sha.slice(0, 12)} has malformed DCO metadata`);
    }
    const expectedName = commit.authorName.trim();
    const expectedEmail = commit.authorEmail.trim().toLowerCase();
    const signoffs = [...commit.message.matchAll(SIGNOFF_PATTERN)];
    const valid = signoffs.some((match) => {
      const name = match[1]?.trim();
      const email = match[2]?.trim().toLowerCase();
      return name === expectedName && email === expectedEmail;
    });
    if (!valid) {
      failures.push(
        `${commit.sha.slice(0, 12)} ${expectedName} <${commit.authorEmail.trim()}>`
      );
    }
  }
  if (failures.length > 0) {
    throw new Error(
      `commits missing an author-matching DCO sign-off:\n${failures.join('\n')}`
    );
  }
  return { commits: commits.length };
}

export async function validateGithubPullRequest(repository, pullRequest, options = {}) {
  if (!REPOSITORY_PATTERN.test(repository)) {
    throw new Error('GitHub repository must use the OWNER/NAME form');
  }
  if (repository.split('/').some((segment) => segment === '.' || segment === '..')) {
    throw new Error('GitHub repository contains an unsafe path segment');
  }
  if (!PULL_REQUEST_PATTERN.test(pullRequest)) {
    throw new Error('pull request number must be a positive decimal integer');
  }
  const token = options.token ?? process.env.GITHUB_TOKEN;
  if (!token || /[\r\n]/u.test(token)) throw new Error('a GitHub API token is required');
  const fetchImpl = options.fetchImpl ?? fetch;
  const pullUrl = new URL(`https://api.github.com/repos/${repository}/pulls/${pullRequest}`);
  const pull = await fetchGithubJson(pullUrl, fetchImpl, token);
  if (!Number.isSafeInteger(pull?.commits) || pull.commits < 1 || pull.commits > MAX_COMMITS) {
    throw new Error(
      `pull request must contain between 1 and ${MAX_COMMITS} commits for complete DCO review`
    );
  }
  const expectedCommits = pull.commits;
  const commits = [];
  for (let page = 1; commits.length < expectedCommits; page += 1) {
    const url = new URL(
      `https://api.github.com/repos/${repository}/pulls/${pullRequest}/commits`
    );
    url.searchParams.set('per_page', '100');
    url.searchParams.set('page', String(page));
    const pageCommits = await fetchGithubJson(url, fetchImpl, token);
    if (!Array.isArray(pageCommits)) throw new Error('GitHub returned malformed commit metadata');
    for (const entry of pageCommits) {
      commits.push({
        sha: entry?.sha,
        authorName: entry?.commit?.author?.name,
        authorEmail: entry?.commit?.author?.email,
        message: entry?.commit?.message
      });
      if (commits.length > MAX_COMMITS) {
        throw new Error(`DCO range must contain between 1 and ${MAX_COMMITS} commits`);
      }
    }
    if (pageCommits.length === 0) break;
  }
  if (commits.length !== expectedCommits) {
    throw new Error(
      `GitHub returned ${commits.length} of ${expectedCommits} pull-request commits`
    );
  }
  return validateDcoCommits(commits);
}

async function fetchGithubJson(url, fetchImpl, token) {
  const response = await fetchImpl(url, {
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${token}`,
      'user-agent': 'aiignore-dco-validator',
      'x-github-api-version': '2022-11-28'
    },
    redirect: 'error',
    signal: AbortSignal.timeout(15_000)
  });
  if (!response.ok || response.redirected) {
    throw new Error(`GitHub pull-request query failed with status ${response.status}`);
  }
  const bytes = await readBoundedResponse(response, MAX_PAGE_BYTES);
  return JSON.parse(bytes.toString('utf8'));
}

async function readBoundedResponse(response, maximumBytes) {
  const contentLength = response.headers.get('content-length');
  if (contentLength && Number(contentLength) > maximumBytes) {
    throw new Error('GitHub commit metadata exceeds the response limit');
  }
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximumBytes) {
      await reader.cancel();
      throw new Error('GitHub commit metadata exceeds the response limit');
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, total);
}

function defaultRunGit(args) {
  const result = spawnSync('git', args, {
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || result.error?.message || `git ${args[0]} failed`);
  }
  return result.stdout;
}

async function main() {
  const args = process.argv.slice(2);
  let result;
  if (args.length === 2 && !args[0].startsWith('--')) {
    result = validateDcoRange(args[0], args[1]);
  } else if (
    args.length === 4 &&
    args[0] === '--github-repository' &&
    args[2] === '--pull-request'
  ) {
    result = await validateGithubPullRequest(args[1], args[3]);
  } else {
    throw new Error(
      'usage: validate-dco.mjs BASE_SHA HEAD_SHA | --github-repository OWNER/NAME --pull-request NUMBER'
    );
  }
  process.stdout.write(`ok - ${result.commits} commits contain matching DCO sign-offs\n`);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
