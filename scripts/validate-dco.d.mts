export interface DcoValidationOptions {
  runGit?: (args: string[]) => string;
}

export interface DcoValidationResult {
  commits: number;
}

export interface DcoCommit {
  sha: string;
  authorName: string;
  authorEmail: string;
  message: string;
}

export function validateDcoRange(
  base: string,
  head: string,
  options?: DcoValidationOptions
): DcoValidationResult;

export function validateDcoCommits(commits: DcoCommit[]): DcoValidationResult;

export function validateGithubPullRequest(
  repository: string,
  pullRequest: string,
  options?: { fetchImpl?: typeof fetch; token?: string }
): Promise<DcoValidationResult>;
